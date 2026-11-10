"""Execution and workspace provenance helpers for cargotrail.

This module observes the local runtime and workspace. It does not provide a
sandbox, lock the workspace, or attest external build inputs.
"""

# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import date
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple

from artifact_inventory import (
    FileVerificationError,
    _is_link_entry as _shared_is_link_entry,
    _same_file_state as _shared_same_file_state,
    hash_regular_file as _shared_hash_regular_file,
    read_regular_file as _shared_read_regular_file,
    read_link as _shared_read_link,
    secure_directory as _shared_secure_directory,
    stat_child as _shared_stat_child,
)
from process_supervision import run_supervised_process


PROVENANCE_SCHEMA_VERSION = 1
INVENTORY_SCHEMA_VERSION = 1
PROBE_TIMEOUT_SECONDS = 30
PROBE_OUTPUT_LIMIT = 8192
# Cargo metadata is transiently retained only up to this limit for JSON parsing.
# The 64 MiB cap supports large workspaces while bounding both disk and parse input.
CARGO_METADATA_PARSE_LIMIT = 64 * 1024 * 1024
HASH_BLOCK_SIZE = 1024 * 1024
RUNTIME_SOURCE_FILES = (
    "cargotrail.py",
    "process_supervision.py",
    "provenance.py",
    "artifact_inventory.py",
)
ENVIRONMENT_NAMES = (
    "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "CARGO_BUILD_TARGET_DIR",
    "CARGO_BUILD_RUSTC", "CARGO_BUILD_RUSTC_WRAPPER", "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTDOC", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTDOC",
    "RUSTUP_HOME", "RUSTUP_TOOLCHAIN", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS", "RUSTDOCFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS",
    "CARGO_BUILD_RUSTDOCFLAGS", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "CC", "CXX", "AR",
    "CFLAGS", "CXXFLAGS", "LDFLAGS", "PKG_CONFIG_PATH",
)
SECRET_NAME_RE = re.compile(r"token|password|secret|key|credential|auth", re.IGNORECASE)
SENSITIVE_FLAGS = frozenset({
    "--token", "--password", "--secret", "--api-key", "--apikey",
    "--access-token", "--refresh-token", "--client-secret", "--registry-token",
    "--credential", "--auth-token", "--auth",
})
REDACTED = "<REDACTED>"
URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s\"'<>]+")
BUILD_SETTING_RE = re.compile(r"^\s*([A-Za-z0-9_-]+)\s*=\s*(.*?)\s*(?:#.*)?$")


class DuplicateJSONKeyError(ValueError):
    """Raised when any JSON object contains an ambiguous repeated key."""

    def __init__(self) -> None:
        # Deliberately omit both the key and its values: callers may be parsing
        # credentials, configuration, or untrusted tool output.
        super().__init__("duplicate JSON object key detected")


def strict_json_loads(text: str) -> Any:
    """Decode JSON while rejecting duplicate keys recursively in every object."""
    duplicate_found = [False]

    def strict_object(pairs: List[Tuple[str, Any]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                duplicate_found[0] = True
            result[key] = value
        return result

    # Finish parsing the complete document before raising for duplicates. This
    # keeps JSONDecodeError authoritative if the document is also malformed.
    value = json.loads(text, object_pairs_hook=strict_object)
    if duplicate_found[0]:
        raise DuplicateJSONKeyError()
    return value


def _redact_url(url: str, unparseable_value: str = "<REDACTED_URL>") -> str:
    """Redact credentials, secret query values, and fragments in one URL."""
    try:
        parts = urlsplit(url)
        if not parts.scheme or not parts.netloc:
            return url
        netloc = parts.netloc
        if parts.username is not None or parts.password is not None:
            hostname = parts.hostname or ""
            if ":" in hostname and not hostname.startswith("["):
                hostname = "[{}]".format(hostname)
            port = ":{}".format(parts.port) if parts.port is not None else ""
            netloc = "<REDACTED>@{}{}".format(hostname, port)
        query_items = parse_qsl(parts.query, keep_blank_values=True)
        redacted_query = [
            (key, REDACTED if SECRET_NAME_RE.search(key) else value)
            for key, value in query_items
        ]
        changed_query = redacted_query != query_items
        if netloc == parts.netloc and not changed_query and not parts.fragment:
            return url
        return urlunsplit((
            parts.scheme,
            netloc,
            parts.path,
            urlencode(redacted_query) if changed_query else parts.query,
            REDACTED if parts.fragment else "",
        ))
    except (ValueError, UnicodeError):
        return unparseable_value


def redact_url_text(value: str, unparseable_value: str = "<REDACTED_URL>") -> str:
    """Redact URL components in a string while preserving surrounding text."""
    return URL_RE.sub(lambda match: _redact_url(match.group(0), unparseable_value), value)


class _TomlValueRedactionError(ValueError):
    """Raised when a Cargo config value cannot be scanned without ambiguity."""


def _toml_key_is_sensitive(key: str) -> bool:
    # Escaped keys are conservatively treated as sensitive because their
    # decoded spelling cannot be classified safely by the shared name policy.
    return bool(SECRET_NAME_RE.search(key) or "\\" in key)


_TOML_DECIMAL_DIGITS = r"[0-9](?:_?[0-9])*"
_TOML_UNSIGNED_DECIMAL_INTEGER = r"(?:0|[1-9](?:_?[0-9])*)"
_TOML_DECIMAL_INTEGER = r"[+-]?" + _TOML_UNSIGNED_DECIMAL_INTEGER
_TOML_SCALAR_PATTERNS = tuple(re.compile(pattern) for pattern in (
    r"(?:true|false)",
    _TOML_DECIMAL_INTEGER,
    r"0x[0-9A-Fa-f](?:_?[0-9A-Fa-f])*",
    r"0o[0-7](?:_?[0-7])*",
    r"0b[01](?:_?[01])*",
    r"[+-]?(?:inf|nan)",
    r"[+-]?" + _TOML_UNSIGNED_DECIMAL_INTEGER + r"\." + _TOML_DECIMAL_DIGITS + r"(?:[eE][+-]?" + _TOML_DECIMAL_DIGITS + r")?",
    r"[+-]?" + _TOML_UNSIGNED_DECIMAL_INTEGER + r"[eE][+-]?" + _TOML_DECIMAL_DIGITS,
))
_TOML_DATE_PATTERN = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")
_TOML_LOCAL_TIME_PATTERN = re.compile(
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]+))?"
)


def _toml_scalar_is_valid(atom: str) -> bool:
    """Validate the scalar spellings supported by the TOML value scanner."""
    if any(pattern.fullmatch(atom) for pattern in _TOML_SCALAR_PATTERNS):
        return True

    date_match = _TOML_DATE_PATTERN.fullmatch(atom)
    if date_match:
        try:
            date(*(int(part) for part in date_match.groups()))
        except ValueError:
            return False
        return True

    def valid_time(spelling: str) -> bool:
        match = _TOML_LOCAL_TIME_PATTERN.fullmatch(spelling)
        if not match:
            return False
        hour, minute, second = (int(part) for part in match.groups()[:3])
        return hour <= 23 and minute <= 59 and second <= 60

    time_match = _TOML_LOCAL_TIME_PATTERN.fullmatch(atom)
    if time_match:
        return valid_time(atom)

    if len(atom) >= 11 and _TOML_DATE_PATTERN.fullmatch(atom[:10]) and atom[10] in "Tt ":
        if not date_match:
            try:
                year, month, day_value = (int(part) for part in atom[:10].split("-"))
                date(year, month, day_value)
            except ValueError:
                return False
        time_and_offset = atom[11:]
        if time_and_offset.endswith(("Z", "z")):
            return valid_time(time_and_offset[:-1])
        if len(time_and_offset) >= 6 and time_and_offset[-6] in "+-" and time_and_offset[-3] == ":":
            offset_hour = time_and_offset[-5:-3]
            offset_minute = time_and_offset[-2:]
            if not (re.fullmatch(r"[0-9]{2}", offset_hour) and re.fullmatch(r"[0-9]{2}", offset_minute)):
                return False
            if int(offset_hour) > 23 or int(offset_minute) > 59:
                return False
            return valid_time(time_and_offset[:-6])
        return valid_time(time_and_offset)

    return False


class _TomlValueRedactor:
    """Small fail-closed scanner for Cargo --config TOML values.

    It preserves source formatting while walking strings, arrays, and inline
    tables. Comments are replaced and scalar atoms are validated before being
    retained. Malformed or unsupported structure raises so the caller can
    redact the complete Cargo config value.
    """

    MAX_DEPTH = 128

    def __init__(self, value: str):
        self.value = value

    def redact(self) -> str:
        prefix, position = self._trivia(0)
        if position >= len(self.value):
            raise _TomlValueRedactionError("missing TOML value")
        result, position = self._value(position, 0, True)
        suffix, position = self._trivia(position)
        if position != len(self.value):
            raise _TomlValueRedactionError("unconsumed TOML value text")
        return prefix + result + suffix

    def _trivia(self, position: int) -> Tuple[str, int]:
        result = []
        while position < len(self.value):
            char = self.value[position]
            if char in " \t":
                result.append(char)
                position += 1
                continue
            if char == "\n":
                result.append(char)
                position += 1
                continue
            if char == "\r":
                if position + 1 >= len(self.value) or self.value[position + 1] != "\n":
                    raise _TomlValueRedactionError("unsupported TOML line ending")
                result.append("\r\n")
                position += 2
                continue
            if char == "#":
                previous = self.value[position - 1] if position else ""
                if previous and previous not in " \t\r\n[{,=":
                    raise _TomlValueRedactionError("ambiguous TOML comment position")
                result.append("#<REDACTED_COMMENT>")
                position += 1
                while position < len(self.value) and self.value[position] not in "\r\n":
                    comment_char = self.value[position]
                    if (ord(comment_char) < 0x20 and comment_char != "\t") or ord(comment_char) == 0x7F:
                        raise _TomlValueRedactionError("control character in TOML comment")
                    position += 1
                if position < len(self.value) and self.value[position] == "\r":
                    if position + 1 >= len(self.value) or self.value[position + 1] != "\n":
                        raise _TomlValueRedactionError("unsupported TOML line ending")
                    result.append("\r\n")
                    position += 2
                elif position < len(self.value):
                    result.append("\n")
                    position += 1
                continue
            break
        return "".join(result), position

    def _value(self, position: int, depth: int, redact: bool) -> Tuple[str, int]:
        if depth > self.MAX_DEPTH:
            raise _TomlValueRedactionError("TOML value nesting limit exceeded")
        if position >= len(self.value):
            raise _TomlValueRedactionError("missing TOML value")
        char = self.value[position]
        if char in "\"'":
            return self._string(position, redact)
        if char == "{":
            return self._inline_table(position, depth, redact)
        if char == "[":
            return self._array(position, depth, redact)
        return self._atom(position, redact)

    def _atom(self, position: int, redact: bool) -> Tuple[str, int]:
        start = position
        while position < len(self.value):
            char = self.value[position]
            if char in ",]}":
                break
            if char in " \t\r\n":
                break
            position += 1
        if position == start:
            raise _TomlValueRedactionError("empty TOML atom")
        atom = self.value[start:position]
        if not _toml_scalar_is_valid(atom):
            raise _TomlValueRedactionError("invalid or unsupported TOML scalar")
        return (redact_url_text(atom) if redact else atom), position

    def _array(self, position: int, depth: int, redact: bool) -> Tuple[str, int]:
        result = ["["]
        position += 1
        trivia, position = self._trivia(position)
        result.append(trivia)
        if position < len(self.value) and self.value[position] == "]":
            result.append("]")
            return "".join(result), position + 1
        while True:
            item, position = self._value(position, depth + 1, redact)
            result.append(item)
            trivia, position = self._trivia(position)
            result.append(trivia)
            if position >= len(self.value):
                raise _TomlValueRedactionError("unterminated TOML array")
            char = self.value[position]
            if char == "]":
                result.append("]")
                return "".join(result), position + 1
            if char != ",":
                raise _TomlValueRedactionError("expected comma or array close")
            result.append(",")
            position += 1
            trivia, position = self._trivia(position)
            result.append(trivia)
            if position < len(self.value) and self.value[position] == "]":
                result.append("]")
                return "".join(result), position + 1

    def _inline_table(self, position: int, depth: int, redact: bool) -> Tuple[str, int]:
        result = ["{"]
        seen_keys = []
        position += 1
        trivia, position = self._trivia(position)
        result.append(trivia)
        if position < len(self.value) and self.value[position] == "}":
            result.append("}")
            return "".join(result), position + 1
        while True:
            equals, key_parts = self._key_equals(position)
            key = self.value[position:equals]
            if not key.strip():
                raise _TomlValueRedactionError("missing inline-table key")
            for prior_key in seen_keys:
                if (key_parts == prior_key or key_parts[:len(prior_key)] == prior_key
                        or prior_key[:len(key_parts)] == key_parts):
                    raise _TomlValueRedactionError("duplicate or conflicting inline-table key")
            seen_keys.append(key_parts)
            result.extend((key, "="))
            position = equals + 1
            trivia, position = self._trivia(position)
            result.append(trivia)
            sensitive = redact and _toml_key_is_sensitive(key)
            parsed_value, position = self._value(position, depth + 1, redact and not sensitive)
            result.append(REDACTED if sensitive else parsed_value)
            trivia, position = self._trivia(position)
            result.append(trivia)
            if position >= len(self.value):
                raise _TomlValueRedactionError("unterminated TOML inline table")
            char = self.value[position]
            if char == "}":
                result.append("}")
                return "".join(result), position + 1
            if char != ",":
                raise _TomlValueRedactionError("expected comma or inline-table close")
            result.append(",")
            position += 1
            trivia, position = self._trivia(position)
            result.append(trivia)
            if position < len(self.value) and self.value[position] == "}":
                raise _TomlValueRedactionError("trailing inline-table comma is unsupported")

    def _key_equals(self, position: int) -> Tuple[int, Tuple[str, ...]]:
        components = []
        while True:
            if position >= len(self.value):
                raise _TomlValueRedactionError("inline-table key has no assignment")
            char = self.value[position]
            if char in "\"'":
                if self.value.startswith(char * 3, position):
                    raise _TomlValueRedactionError("multiline inline-table key is unsupported")
                string_start = position
                _raw, position = self._string(position, False)
                if char == "\"":
                    component = self._decode_basic_string(self.value[string_start + 1:position - 1], False)
                else:
                    component = self.value[string_start + 1:position - 1]
            else:
                start = position
                while position < len(self.value) and (
                    self.value[position].isascii()
                    and (self.value[position].isalnum() or self.value[position] in "_-")
                ):
                    position += 1
                if position == start:
                    raise _TomlValueRedactionError("invalid inline-table key")
                component = self.value[start:position]
            components.append(component)

            while position < len(self.value) and self.value[position] in " \t":
                position += 1
            if position >= len(self.value):
                raise _TomlValueRedactionError("inline-table key has no assignment")
            char = self.value[position]
            if char == ".":
                position += 1
                while position < len(self.value) and self.value[position] in " \t":
                    position += 1
                continue
            if char == "=":
                return position, tuple(components)
            raise _TomlValueRedactionError("invalid inline-table key syntax")

    def _string(self, position: int, redact: bool) -> Tuple[str, int]:
        quote = self.value[position]
        basic = quote == '"'
        delimiter = quote * 3 if self.value.startswith(quote * 3, position) else quote
        content_start = position + len(delimiter)
        cursor = content_start
        while cursor < len(self.value):
            char = self.value[cursor]
            if basic and char == "\\":
                if cursor + 1 >= len(self.value):
                    raise _TomlValueRedactionError("unterminated TOML escape")
                if self.value[cursor + 1] in "\r\n":
                    raise _TomlValueRedactionError("TOML multiline continuation is unsupported")
                cursor += 2
                continue
            if char == "\r" and (cursor + 1 >= len(self.value) or self.value[cursor + 1] != "\n"):
                raise _TomlValueRedactionError("unsupported TOML line ending")
            if self.value.startswith(delimiter, cursor):
                end = cursor + len(delimiter)
                raw = self.value[position:end]
                content = self.value[content_start:cursor]
                if not basic:
                    if not redact:
                        return raw, end
                    return delimiter + redact_url_text(content) + delimiter, end
                decoded = self._decode_basic_string(content, multiline=len(delimiter) == 3)
                if not redact:
                    return raw, end
                redacted = redact_url_text(decoded)
                if redacted == decoded:
                    return raw, end
                if "\\" in content:
                    return json.dumps(redacted, ensure_ascii=False), end
                return delimiter + redacted + delimiter, end
            if len(delimiter) == 1 and char in "\r\n":
                raise _TomlValueRedactionError("newline in single-line TOML string")
            if (ord(char) < 0x20 and char not in "\t\r\n") or ord(char) == 0x7F:
                raise _TomlValueRedactionError("control character in TOML string")
            cursor += 1
        raise _TomlValueRedactionError("unterminated TOML string")

    @staticmethod
    def _decode_basic_string(content: str, multiline: bool) -> str:
        decoded = []
        escapes = {
            "b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r",
            '"': '"', "\\": "\\",
        }
        position = 0
        while position < len(content):
            char = content[position]
            if char != "\\":
                decoded.append(char)
                position += 1
                continue
            if position + 1 >= len(content):
                raise _TomlValueRedactionError("unterminated TOML escape")
            escape = content[position + 1]
            if escape in escapes:
                decoded.append(escapes[escape])
                position += 2
                continue
            if escape in ("u", "U"):
                width = 4 if escape == "u" else 8
                digits = content[position + 2:position + 2 + width]
                if len(digits) != width or not re.fullmatch(r"[0-9A-Fa-f]{" + str(width) + r"}", digits):
                    raise _TomlValueRedactionError("invalid TOML Unicode escape")
                codepoint = int(digits, 16)
                if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
                    raise _TomlValueRedactionError("invalid TOML Unicode code point")
                decoded.append(chr(codepoint))
                position += width + 2
                continue
            if multiline and escape in "\r\n":
                raise _TomlValueRedactionError("TOML multiline continuation is unsupported")
            raise _TomlValueRedactionError("unsupported TOML string escape")
        return "".join(decoded)


def _redact_config_value(argument: str) -> str:
    """Redact a Cargo KEY=VALUE argument using the shared key-name policy."""
    if "=" not in argument:
        return redact_url_text(argument)
    key, value = argument.split("=", 1)
    normalized_key = key.strip().strip('"').strip("'")
    # Alias values are command argv, not ordinary Cargo setting values. Their
    # contents may carry credentials in any position, so presentation copies
    # redact the whole value while leaving the actual argv untouched.
    if normalized_key == "alias" or normalized_key.startswith("alias."):
        return key + "=" + REDACTED
    if _toml_key_is_sensitive(key):
        return key + "=" + REDACTED
    try:
        redacted_value = _TomlValueRedactor(value).redact()
    except (RecursionError, UnicodeError, _TomlValueRedactionError):
        # A partial parse is unsafe: never persist the original complex value.
        redacted_value = REDACTED
    return key + "=" + redacted_value


def redact_args(args: List[str], indexes: Optional[List[int]] = None) -> List[str]:
    """Return a safe presentation copy of argv without changing invocation args.

    Automatic sensitivity is derived from the original argument sequence before
    explicit indexes are applied, so masking a flag cannot hide its value.
    """
    original = list(args)
    result = [redact_url_text(argument) for argument in original]
    explicit_indexes = {index for index in (indexes or []) if 0 <= index < len(original)}
    redact_indexes = set(explicit_indexes)

    for index, argument in enumerate(original):
        lower = argument.lower()
        if lower in SENSITIVE_FLAGS and index + 1 < len(original):
            redact_indexes.add(index + 1)
        elif any(lower.startswith(flag + "=") for flag in SENSITIVE_FLAGS):
            flag, _value = argument.split("=", 1)
            result[index] = flag + "=" + REDACTED
        if lower == "--config" and index + 1 < len(original):
            result[index + 1] = _redact_config_value(original[index + 1])
        elif lower.startswith("--config="):
            prefix, config_value = argument.split("=", 1)
            result[index] = prefix + "=" + _redact_config_value(config_value)

    for index in redact_indexes:
        result[index] = REDACTED
    return result


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _resolved_executable(value: str, env: dict, cwd: Optional[Path] = None) -> Optional[str]:
    candidate = Path(value).expanduser()
    if candidate.is_absolute():
        found = str(candidate) if candidate.is_file() else None
    elif cwd is not None and (candidate.parent != Path(".") or "/" in value or "\\" in value):
        relative = cwd / candidate
        found = str(relative) if relative.is_file() else None
    else:
        found = shutil.which(value, path=env.get("PATH"))
    if not found:
        return None
    try:
        return str(Path(found).resolve())
    except OSError:
        return str(Path(found).absolute())


def _strip_toml_comment(value: str) -> str:
    quote = None
    escaped = False
    for index, char in enumerate(value):
        if quote == '"' and escaped:
            escaped = False
            continue
        if quote == '"' and char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "#":
            return value[:index]
    return value


def _toml_value_is_complete(value: str) -> bool:
    quote = None
    escaped = False
    square = 0
    curly = 0
    for char in value:
        if quote == '"' and escaped:
            escaped = False
            continue
        if quote == '"' and char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "[":
            square += 1
        elif char == "]":
            square -= 1
        elif char == "{":
            curly += 1
        elif char == "}":
            curly -= 1
    return quote is None and square <= 0 and curly <= 0


def _split_toml_items(value: str) -> List[str]:
    result = []
    start = 0
    quote = None
    escaped = False
    square = 0
    curly = 0
    for index, char in enumerate(value):
        if quote == '"' and escaped:
            escaped = False
            continue
        if quote == '"' and char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "[":
            square += 1
        elif char == "]":
            square -= 1
        elif char == "{":
            curly += 1
        elif char == "}":
            curly -= 1
        elif char == "," and square == 0 and curly == 0:
            result.append(value[start:index].strip())
            start = index + 1
    tail = value[start:].strip()
    if tail:
        result.append(tail)
    return result


def _parse_toml_string(value: str) -> Optional[str]:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, str) else None
        except json.JSONDecodeError:
            return None
    if len(value) >= 2 and value[0] == "'" and value[-1] == "'":
        return value[1:-1]
    return None


def _parse_include_entry(value: str) -> Tuple[Optional[dict], Optional[str]]:
    value = _strip_toml_comment(value).strip()
    if value.startswith("{") and value.endswith("}"):
        fields = {}
        for field in _split_toml_items(value[1:-1]):
            if "=" not in field:
                return None, "malformed_inline_table"
            key, raw = field.split("=", 1)
            key = key.strip().strip('"').strip("'")
            fields[key] = _strip_toml_comment(raw).strip()
        path = _parse_toml_string(fields.get("path", ""))
        optional_raw = fields.get("optional", "false")
        if optional_raw not in {"true", "false"} or path is None:
            return None, "unsupported_inline_table"
        if set(fields) - {"path", "optional"}:
            return None, "unsupported_inline_table_fields"
        return {"path": path, "optional": optional_raw == "true"}, None
    path = _parse_toml_string(value)
    if path is not None:
        return {"path": path, "optional": False}, None
    return None, "unsupported_include_value"


def _top_level_include_specs(content: str) -> Tuple[List[dict], List[dict]]:
    specs = []
    issues = []
    section_seen = False
    lines = content.splitlines()
    index = 0

    def finish_array_table(fields: Optional[dict], line_number: int) -> None:
        if fields is None:
            return
        spec, error = _parse_include_fields(fields)
        if error:
            issues.append({
                "code": "cargo_config_include_unresolved",
                "reason": error,
                "line": line_number,
            })
        elif not spec["path"]:
            issues.append({
                "code": "cargo_config_include_unresolved",
                "reason": "empty_path",
                "line": line_number,
            })
        else:
            specs.append(spec)

    array_fields = None
    array_line = None
    while index < len(lines):
        line = _strip_toml_comment(lines[index]).strip()
        if not line:
            index += 1
            continue
        array_header = re.match(r"^\[\[\s*(?:include|\"include\"|'include')\s*\]\]$", line)
        if array_header:
            finish_array_table(array_fields, array_line or index + 1)
            array_fields = {}
            array_line = index + 1
            section_seen = True
            index += 1
            continue
        if line.startswith("["):
            finish_array_table(array_fields, array_line or index + 1)
            array_fields = None
            array_line = None
            if re.match(r"^\[\[.*include.*\]\]$", line, re.IGNORECASE):
                issues.append({
                    "code": "cargo_config_include_unresolved",
                    "reason": "unsupported_include_table_header",
                    "line": index + 1,
                })
            section_seen = True
            index += 1
            continue
        if array_fields is not None:
            if "=" not in line:
                issues.append({
                    "code": "cargo_config_include_unresolved",
                    "reason": "malformed_array_table_field",
                    "line": index + 1,
                })
                index += 1
                continue
            key, raw = line.split("=", 1)
            key = key.strip().strip('"').strip("'")
            array_fields[key] = _strip_toml_comment(raw).strip()
            index += 1
            continue
        match = re.match(r"^(?:include|\"include\"|'include')\s*=\s*(.*)$", line)
        if not section_seen and match:
            raw = match.group(1)
            while not _toml_value_is_complete(raw) and index + 1 < len(lines):
                index += 1
                raw += "\n" + _strip_toml_comment(lines[index])
            raw = _strip_toml_comment(raw).strip()
            if raw.startswith("[") and raw.endswith("]"):
                values = _split_toml_items(raw[1:-1])
            else:
                values = [raw]
            for value in values:
                if not value:
                    continue
                spec, error = _parse_include_entry(value)
                if error:
                    issues.append({"code": "cargo_config_include_unresolved", "reason": error, "line": index + 1})
                elif not spec["path"]:
                    issues.append({"code": "cargo_config_include_unresolved", "reason": "empty_path", "line": index + 1})
                else:
                    specs.append(spec)
        elif not section_seen:
            unknown_include = re.match(r"^(?:include(?:\.|\s)|\"include\"\.|'include'\.)", line)
            if unknown_include:
                issues.append({
                    "code": "cargo_config_include_unresolved",
                    "reason": "unsupported_include_assignment",
                    "line": index + 1,
                })
        index += 1
    finish_array_table(array_fields, array_line or len(lines))
    return specs, issues


def _parse_include_fields(fields: dict) -> Tuple[Optional[dict], Optional[str]]:
    if set(fields) - {"path", "optional"}:
        return None, "unsupported_inline_table_fields"
    path = _parse_toml_string(fields.get("path", ""))
    optional_raw = fields.get("optional", "false")
    if path is None or optional_raw not in {"true", "false"}:
        return None, "unsupported_inline_table"
    return {"path": path, "optional": optional_raw == "true"}, None


def _bounded_text(value: Optional[bytes]) -> Tuple[str, int, bool, str]:
    value = value or b""
    prefix = value[:PROBE_OUTPUT_LIMIT]
    return (
        prefix.decode("utf-8", errors="replace"),
        len(value),
        len(value) > PROBE_OUTPUT_LIMIT,
        sha256_bytes(value),
    )


def _run_probe_capture(
    name: str,
    command: List[str],
    cwd: Path,
    env: dict,
    keep_stdout: bool = True,
    include_raw_stdout: bool = False,
    redact_arg_indexes: Optional[List[int]] = None,
    termination_grace_seconds: float = 5.0,
    cancellation: Any = None,
) -> dict:
    """Run a bounded, shell-free metadata probe without affecting the pipeline."""
    started = time.monotonic()
    probe_env = dict(env)
    # A missing +toolchain selector must not make rustup auto-install a toolchain.
    probe_env["RUSTUP_AUTO_INSTALL"] = "0"
    safe_command = redact_args(command, redact_arg_indexes)
    if cancellation is not None and bool(getattr(cancellation, "cancelled", False)):
        signal_number = getattr(cancellation, "signal_number", None) or getattr(signal, "SIGINT", 2)
        signal_name = getattr(cancellation, "signal_name", None)
        try:
            signal_name = signal_name or signal.Signals(signal_number).name
        except (ValueError, TypeError):
            signal_name = signal_name or "SIGNAL_{}".format(signal_number)
        empty_hash = sha256_bytes(b"")
        cancelled_result = {
            "name": name, "argv": safe_command,
            "environment_overrides": {"RUSTUP_AUTO_INSTALL": "0"},
            "status": "interrupted", "exit_code": 128 + signal_number,
            "signal_number": signal_number, "signal_name": signal_name,
            "timeout_seconds": PROBE_TIMEOUT_SECONDS, "duration_ms": 0,
            "stdout_bytes": 0, "stdout_sha256": empty_hash, "stdout_truncated": False,
            "stdout_capture_truncated": False,
            "stderr_bytes": 0, "stderr_sha256": empty_hash, "stderr_truncated": False,
            "stderr_capture_truncated": False,
            "stdout_capture_limit_bytes": CARGO_METADATA_PARSE_LIMIT if include_raw_stdout else PROBE_OUTPUT_LIMIT,
            "stderr_capture_limit_bytes": PROBE_OUTPUT_LIMIT,
            "capture_status": "not_started",
            "process_tree": {
                "supervision": "not_started", "trigger": "cancelled-before-launch",
                "cleanup_complete": True, "active_members_after_cleanup": 0, "errors": [],
            },
        }
        if keep_stdout:
            cancelled_result["stdout_excerpt"] = ""
        if include_raw_stdout:
            cancelled_result["_raw_stdout"] = b""
        return cancelled_result
    capture_stdout_limit = CARGO_METADATA_PARSE_LIMIT if include_raw_stdout else PROBE_OUTPUT_LIMIT
    with tempfile.TemporaryDirectory(prefix="cargo-evidence-probe-") as temporary:
        temporary_path = Path(temporary)
        stdout_path = temporary_path / "stdout.capture"
        stderr_path = temporary_path / "stderr.capture"
        completed = run_supervised_process(
            command, cwd, probe_env, stdout_path, stderr_path,
            PROBE_TIMEOUT_SECONDS, termination_grace_seconds,
            cancellation=cancellation,
            capture_limits={"stdout": capture_stdout_limit, "stderr": PROBE_OUTPUT_LIMIT},
        )
        captured_stdout = stdout_path.read_bytes() if stdout_path.is_file() else b""
        captured_stderr = stderr_path.read_bytes() if stderr_path.is_file() else b""
        capture = completed.get("capture") or {}
        out_info = capture.get("stdout") or {}
        err_info = capture.get("stderr") or {}
        stdout = captured_stdout[:PROBE_OUTPUT_LIMIT].decode("utf-8", errors="replace")
        stderr = captured_stderr[:PROBE_OUTPUT_LIMIT].decode("utf-8", errors="replace")
        out_size = int(out_info.get("bytes", len(captured_stdout)))
        err_size = int(err_info.get("bytes", len(captured_stderr)))
        out_digest = out_info.get("sha256") or sha256_bytes(captured_stdout)
        err_digest = err_info.get("sha256") or sha256_bytes(captured_stderr)
        out_capture_truncated = bool(out_info.get("truncated", out_size > capture_stdout_limit))
        err_capture_truncated = bool(err_info.get("truncated", err_size > PROBE_OUTPUT_LIMIT))
        out_truncated = out_size > PROBE_OUTPUT_LIMIT
        err_truncated = err_size > PROBE_OUTPUT_LIMIT
        if completed.get("interrupted"):
            status = "interrupted"
        elif completed.get("timed_out"):
            status = "timed_out"
        elif completed.get("spawn_error"):
            status = "unavailable"
        elif completed.get("supervision_error") or (completed.get("process_tree") or {}).get("cleanup_complete") is False:
            status = "failed"
        else:
            status = "succeeded" if completed.get("exit_code") == 0 else "failed"
        result = {
            "name": name,
            "argv": safe_command,
            "environment_overrides": {"RUSTUP_AUTO_INSTALL": "0"},
            "status": status,
            "exit_code": completed.get("exit_code"),
            "timeout_seconds": PROBE_TIMEOUT_SECONDS,
            "duration_ms": completed.get("duration_ms") or round((time.monotonic() - started) * 1000),
            "stdout_bytes": out_size,
            "stdout_sha256": out_digest,
            "stdout_truncated": out_truncated,
            "stdout_capture_truncated": out_capture_truncated,
            "stderr_bytes": err_size,
            "stderr_sha256": err_digest,
            "stderr_truncated": err_truncated,
            "stderr_capture_truncated": err_capture_truncated,
            "stdout_capture_limit_bytes": capture_stdout_limit,
            "stderr_capture_limit_bytes": PROBE_OUTPUT_LIMIT,
            "process_tree": completed.get("process_tree"),
        }
        for key in ("signal_number", "signal_name", "supervision_error", "spawn_error"):
            if completed.get(key) is not None:
                result[key] = completed[key]
        capture_errors = [
            error for info in (out_info, err_info) for error in info.get("errors", [])
        ]
        if capture_errors:
            result["capture_status"] = "failed"
            result["capture_error"] = "; ".join(capture_errors)
            result["status"] = "failed"
        else:
            result["capture_status"] = "complete"
        if keep_stdout:
            result["stdout_excerpt"] = stdout
        if include_raw_stdout and not out_capture_truncated and status == "succeeded" and not capture_errors:
            # This bounded transient value is consumed by _cargo_metadata and
            # removed before provenance serialization.
            result["_raw_stdout"] = captured_stdout
        if stderr:
            result["stderr_excerpt"] = stderr
        return result


def run_probe(
    name: str,
    command: List[str],
    cwd: Path,
    env: dict,
    keep_stdout: bool = True,
    include_raw_stdout: bool = False,
    redact_arg_indexes: Optional[List[int]] = None,
    termination_grace_seconds: float = 5.0,
    cancellation: Any = None,
) -> dict:
    """Run one supervised probe and always return a structured outcome."""
    started = time.monotonic()
    safe_command = redact_args(command, redact_arg_indexes)
    try:
        return _run_probe_capture(
            name, command, cwd, env, keep_stdout, include_raw_stdout,
            redact_arg_indexes, termination_grace_seconds, cancellation,
        )
    except KeyboardInterrupt:
        if cancellation is not None:
            try:
                cancellation.request(getattr(signal, "SIGINT", 2))
            except Exception:
                pass
        signal_number = getattr(cancellation, "signal_number", None) if cancellation is not None else None
        signal_name = getattr(cancellation, "signal_name", None) if cancellation is not None else "SIGINT"
        return {
            "name": name, "argv": safe_command,
            "environment_overrides": {"RUSTUP_AUTO_INSTALL": "0"},
            "status": "interrupted", "exit_code": 128 + (signal_number or getattr(signal, "SIGINT", 2)),
            "signal_number": signal_number or getattr(signal, "SIGINT", 2),
            "signal_name": signal_name or "SIGINT", "timeout_seconds": PROBE_TIMEOUT_SECONDS,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "capture_status": "failed", "supervision_error": "probe interrupted outside process wait",
        }
    except Exception as exc:
        cancelled = cancellation is not None and bool(getattr(cancellation, "cancelled", False))
        signal_number = getattr(cancellation, "signal_number", None) if cancelled else None
        signal_name = getattr(cancellation, "signal_name", None) if cancelled else None
        result = {
            "name": name, "argv": safe_command,
            "environment_overrides": {"RUSTUP_AUTO_INSTALL": "0"},
            "status": "interrupted" if cancelled else "unavailable",
            "exit_code": (128 + signal_number) if signal_number is not None else None,
            "timeout_seconds": PROBE_TIMEOUT_SECONDS,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "error_type": type(exc).__name__,
            "capture_status": "failed",
            "supervision_error": "probe capture failed: {}".format(type(exc).__name__),
        }
        if signal_number is not None:
            result["signal_number"] = signal_number
            result["signal_name"] = signal_name
        return result


def runtime_provenance(agent_version: str, source_directory: Path) -> dict:
    source_records = []
    source_errors = []
    for name in RUNTIME_SOURCE_FILES:
        path = source_directory / name
        digest, size, status, issue = _shared_hash_regular_file(path)
        if status == "complete" and digest is not None and size is not None:
            source_records.append({
                "path": name,
                "size_bytes": size,
                "sha256": digest,
                "status": "hashed",
            })
        else:
            source_records.append({
                "path": name, "status": "unavailable",
                "error_type": (issue or {}).get("error_type", "FileVerificationError"),
            })
            source_errors.append(name)
    composite = [
        {"path": item["path"], "sha256": item.get("sha256"), "status": item["status"]}
        for item in source_records
    ]
    return {
        "agent": {
            "version": agent_version,
            "runtime_source_files": source_records,
            "runtime_source_digest": "sha256:" + sha256_bytes(canonical_json_bytes(composite)),
        },
        "python": {
            "implementation": platform.python_implementation(),
            "version": sys.version,
            "executable": str(Path(sys.executable).resolve()),
            "process_bits": platform.architecture()[0],
            "pointer_bits": 8 * __import__("struct").calcsize("P"),
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "source_errors": source_errors,
    }


CARGO_BUILTIN_ALIASES = {
    "b": "build", "c": "check", "d": "doc", "r": "run", "t": "test", "rm": "remove",
}
# Cargo's command inventory was checked against installed Cargo 1.91.1 and
# Cargo's stable release records through 1.94. Stable 1.92–1.94 add no new
# top-level commands; 1.94 adds config-include/TOML support instead. An unknown
# name on a later Cargo version is unresolved until that release is reviewed.
CARGO_BUILTIN_COMMANDS = frozenset({
    "add", "bench", "build", "check", "clean", "config", "doc", "fetch", "fix",
    "generate-lockfile", "git-checkout", "help", "info", "init", "install", "locate-project", "login",
    "logout", "metadata", "new", "owner", "package", "pkgid", "publish", "read-manifest",
    "remove", "report", "run", "rustc", "rustdoc", "search", "test", "tree", "uninstall",
    "explain", "list", "update", "vendor", "verify-project", "version", "yank",
})
# The complete inventory is anchored to the installed Cargo 1.91.1 baseline.
# Known names remain recognizable on later releases, while unknown names on
# versions outside this reviewed band are unresolved instead of assumed custom.
CARGO_BUILTIN_INVENTORY_MIN_VERSION = (1, 91)
CARGO_BUILTIN_INVENTORY_MAX_VERSION = (1, 94)
# rustup-distributed proxies (cargo-fmt, cargo-clippy). They are external
# subcommands that the evidence policy already names explicitly, so their
# identity does not depend on the reviewed built-in inventory window.
CARGO_KNOWN_EXTERNAL_SUBCOMMANDS = frozenset({"clippy", "fmt"})
CARGO_VERSION_SENSITIVE_BUILTINS = frozenset({"add", "config", "info", "owner", "remove", "report", "tree"})
CARGO_ALIAS_MAX_DEPTH = 32
CARGO_GLOBAL_VALUE_OPTIONS = ("--config", "--color", "--explain", "-C")
CARGO_GLOBAL_FLAG_OPTIONS = (
    "--locked", "--offline", "--frozen", "--quiet", "-q", "--verbose", "-v",
    "-vv", "-vvv",
    "--help", "-h", "--version", "-V", "--list",
)
CARGO_LOCAL_VALUE_OPTIONS = ("--message-format", "--manifest-path", "--target", "--target-dir")


def _invocation_issue(code: str) -> dict:
    """Create a stable invocation issue without retaining argument values."""
    return {"code": code}


def _parse_cargo_argument_tokens(tokens: List[dict]) -> dict:
    """Parse Cargo's global options and the command options consumed here.

    ``tokens`` carry original argv indexes where available. Unknown command-local
    options are left opaque; unknown pre-command options make command identity
    unresolved because their arity cannot safely be guessed.
    """
    global_options = {"flags": [], "values": [], "config_occurrences": [], "z_flags": [], "change_directory": None}
    command_options = {"message_format": [], "manifest_path": [], "target": [], "target_dir": []}
    issues = []
    selector = None
    selector_index = None
    subcommand = None
    subcommand_index = None
    subcommand_position = None
    top_level_command = None
    command_tail = []
    payload_after_separator = []
    end_of_options = False
    index = 0

    if tokens and tokens[0]["value"].startswith("+"):
        selector_token = tokens[0]["value"]
        if len(selector_token) <= 1:
            issues.append(_invocation_issue("cargo_toolchain_selector_empty"))
        else:
            selector = selector_token[1:]
            selector_index = tokens[0].get("source_index")
        index = 1

    def consume_value(option: str, attached: Optional[str], allow_equal: bool, source: str) -> Tuple[Optional[str], int]:
        nonlocal index
        token = tokens[index]
        if attached is not None:
            if not attached:
                issues.append(_invocation_issue("cargo_option_value_missing"))
                return None, 1
            return attached, 1
        if index + 1 >= len(tokens) or tokens[index + 1]["value"] == "--" or tokens[index + 1]["value"].startswith("-"):
            issues.append(_invocation_issue("cargo_option_value_missing"))
            return None, 1
        value_token = tokens[index + 1]
        if value_token["value"] == "":
            issues.append(_invocation_issue("cargo_option_value_missing"))
            return None, 1
        return value_token["value"], 2

    while index < len(tokens):
        token_record = tokens[index]
        token = token_record["value"]
        source_index = token_record.get("source_index")
        if token == "" and subcommand is None:
            issues.append(_invocation_issue("cargo_subcommand_empty"))
            break
        if token == "--":
            if subcommand is None:
                issues.append(_invocation_issue("cargo_subcommand_missing_before_separator"))
            else:
                payload_after_separator = tokens[index + 1:]
                command_tail.extend(tokens[index:])
            end_of_options = True
            break

        if subcommand is None and not token.startswith("-"):
            subcommand = token
            subcommand_index = source_index
            subcommand_position = index
            index += 1
            continue

        if not token.startswith("-"):
            command_tail.append(token_record)
            index += 1
            continue

        # Cargo global options can appear before the subcommand and are also
        # recognized after it. Consume their values before considering a token
        # as a possible subcommand or command-local option.
        matched_global = False
        for option in CARGO_GLOBAL_VALUE_OPTIONS:
            attached = None
            if token == option:
                matched_global = True
            elif option.startswith("--") and token.startswith(option + "="):
                attached = token.split("=", 1)[1]
                matched_global = True
            elif option == "-C" and token.startswith("-C") and token != "-C":
                attached = token[2:].lstrip("=")
                matched_global = True
            if not matched_global:
                continue
            if option == "-C" and subcommand is not None:
                # Cargo documents -C as a pre-command option. Do not apply a
                # form that Cargo itself will reject after the subcommand.
                issues.append(_invocation_issue("cargo_change_directory_after_subcommand"))
                index += 1
                break
            value, consumed = consume_value(option, attached, option.startswith("--"), "global")
            if value is not None:
                if option == "--config":
                    form = "equals" if token.startswith("--config=") else "separate"
                    global_options["config_occurrences"].append({
                        "value": value,
                        "option_argument": token,
                        "form": form,
                        "argument_index": source_index,
                        "value_argument_index": (
                            tokens[index + 1].get("source_index") if consumed == 2 else source_index
                        ),
                        "source": token_record.get("source", "configured"),
                    })
                elif option == "-C":
                    global_options["change_directory"] = {
                        "value": value, "argument_index": source_index,
                    }
                else:
                    global_options["values"].append({
                        "option": option, "value": value, "argument_index": source_index,
                    })
            index += consumed
            break
        if matched_global:
            continue

        if token.startswith("-Z"):
            if token == "-Z":
                value, consumed = consume_value("-Z", None, False, "global")
            else:
                value, consumed = token[2:].lstrip("="), 1
                if not value:
                    issues.append(_invocation_issue("cargo_option_value_missing"))
            if value is not None:
                global_options["z_flags"].append({"value": value, "argument_index": source_index})
            index += consumed
            continue

        if token in CARGO_GLOBAL_FLAG_OPTIONS:
            global_options["flags"].append({"option": token, "argument_index": source_index})
            index += 1
            continue

        local_match = None
        local_value = None
        for option in CARGO_LOCAL_VALUE_OPTIONS:
            if token == option:
                local_match = option
                break
            if token.startswith(option + "="):
                local_match = option
                local_value = token.split("=", 1)[1]
                break
        if local_match is not None and subcommand is not None:
            value, consumed = consume_value(local_match, local_value, True, "command")
            if value is not None:
                key = {
                    "--message-format": "message_format", "--manifest-path": "manifest_path",
                    "--target": "target", "--target-dir": "target_dir",
                }[local_match]
                command_options[key].append({"value": value, "argument_index": source_index})
            index += consumed
            continue

        if subcommand is None:
            issues.append(_invocation_issue("cargo_global_option_unsupported_or_ambiguous"))
            # Without knowing this option's arity, later tokens cannot safely
            # establish the requested command.
            break
        command_tail.append(token_record)
        index += 1

    if subcommand is None and not any(
        issue["code"] in {"cargo_global_option_unsupported_or_ambiguous", "cargo_subcommand_missing_before_separator"}
        for issue in issues
    ):
        top_level_candidates = []
        for item in global_options["flags"]:
            if item["option"] in {"--version", "-V"}:
                top_level_candidates.append("version")
            elif item["option"] in {"--help", "-h"}:
                top_level_candidates.append("help")
            elif item["option"] == "--list":
                top_level_candidates.append("list")
        if any(item["option"] == "--explain" for item in global_options["values"]):
            top_level_candidates.append("explain")
        distinct_top_level = sorted(set(top_level_candidates))
        if len(distinct_top_level) == 1:
            top_level_command = distinct_top_level[0]
        elif len(distinct_top_level) > 1:
            issues.append(_invocation_issue("cargo_top_level_command_ambiguous"))
        else:
            issues.append(_invocation_issue("cargo_subcommand_missing"))
    if subcommand_position is not None:
        # Alias expansion receives every original post-subcommand token, even
        # options that were parsed for analysis above.
        command_tail = tokens[subcommand_position + 1:]
    return {
        "toolchain_selector": selector,
        "toolchain_selector_index": selector_index,
        "requested_subcommand": subcommand,
        "requested_subcommand_index": subcommand_index,
        "top_level_command": top_level_command,
        "global_options": global_options,
        "command_options": command_options,
        "command_tail": command_tail,
        "payload_after_separator": payload_after_separator,
        "issues": issues,
        "end_of_options": end_of_options,
    }


def _cargo_selector(args: List[str]) -> Tuple[Optional[str], int]:
    """Compatibility wrapper delegated to the shared invocation parser."""
    analysis = analyze_cargo_invocation(args, Path.cwd(), os.environ)
    return analysis["toolchain_selector"], analysis["toolchain_selector_index"] or 0


def _cargo_version_tuple(cargo_version: Optional[dict]) -> Optional[Tuple[int, int, int]]:
    parsed = (cargo_version or {}).get("parsed") or {}
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", parsed.get("release") or "")
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())


def _cargo_builtin_state(
    name: str,
    version: Optional[Tuple[int, int, int]],
    inventory_complete: bool = False,
) -> Optional[bool]:
    if name not in CARGO_BUILTIN_COMMANDS:
        if name in CARGO_KNOWN_EXTERNAL_SUBCOMMANDS:
            return False
        # Outside the reviewed stable inventory, an apparently custom name
        # could be a new Cargo built-in that shadows a user alias.
        return False if inventory_complete else None
    if name in CARGO_VERSION_SENSITIVE_BUILTINS:
        if version is None or version[:2] < CARGO_BUILTIN_INVENTORY_MIN_VERSION:
            # The name is in the reviewed inventory, but this release may
            # allow a user alias or external command to use the same name.
            return None
    return True


def parse_cargo_version_probe(cargo_version: dict) -> dict:
    """Parse the existing bounded ``cargo -Vv`` probe for capability checks."""
    result = dict(cargo_version or {})
    text = result.get("stdout_excerpt", "")
    result["parsed"] = {
        key: match.group(1).strip()
        for key, pattern in (
            ("release", r"^release:\s*(.+)$"),
            ("host", r"^host:\s*(.+)$"),
            ("commit_hash", r"^commit-hash:\s*(.+)$"),
            ("commit_date", r"^commit-date:\s*(.+)$"),
            ("channel", r"^channel:\s*(.+)$"),
        )
        for match in [re.search(pattern, text, re.MULTILINE)] if match
    }
    release = result["parsed"].get("release") or ""
    if "channel" not in result["parsed"]:
        result["parsed"]["channel"] = (
            "nightly" if "nightly" in release else "beta" if "beta" in release else "stable"
        ) if release else None
    return result


def _alias_value_words(value: Any) -> Tuple[Optional[List[str]], Optional[str]]:
    if isinstance(value, str):
        words = value.split()
    elif isinstance(value, list):
        if any(not isinstance(item, str) for item in value):
            return None, "cargo_alias_array_element_invalid"
        words = list(value)
    else:
        return None, "cargo_alias_type_invalid"
    if not words or not words[0]:
        return None, "cargo_alias_empty"
    return words, None


def analyze_cargo_invocation(
    args: List[str],
    cwd: Path,
    effective_environment: dict,
    cargo_version_or_capability_context: Optional[dict] = None,
    build_producing_subcommands: Optional[Iterable[str]] = None,
    analysis_context: Optional[dict] = None,
) -> dict:
    """Parse and resolve one Cargo invocation without executing any command.

    Alias strings use Cargo's whitespace split; array aliases preserve argv
    elements. The returned private configuration context is in-memory only and
    must never be serialized.
    """
    source_tokens = [
        {"value": value, "source_index": index, "source": "configured"}
        for index, value in enumerate(args)
    ]
    parsed = (
        analysis_context.get("_base_parse")
        if analysis_context is not None
        else _parse_cargo_argument_tokens(source_tokens)
    )
    analysis = {
        "toolchain_selector": parsed["toolchain_selector"],
        "toolchain_selector_index": parsed["toolchain_selector_index"],
        "requested_subcommand": parsed["requested_subcommand"],
        "requested_subcommand_index": parsed["requested_subcommand_index"],
        "top_level_command": parsed.get("top_level_command"),
        "global_options": parsed["global_options"],
        "command_options": parsed["command_options"],
        "message_format": (
            parsed["command_options"]["message_format"][-1]["value"]
            if parsed["command_options"]["message_format"] else None
        ),
        "manifest_path": (
            parsed["command_options"]["manifest_path"][-1]["value"]
            if parsed["command_options"]["manifest_path"] else None
        ),
        "explicit_target": (
            parsed["command_options"]["target"][-1]["value"]
            if parsed["command_options"]["target"] else None
        ),
        "explicit_target_dir": (
            parsed["command_options"]["target_dir"][-1]["value"]
            if parsed["command_options"]["target_dir"] else None
        ),
        "config_occurrences": list(parsed["global_options"]["config_occurrences"]),
        "alias_resolution_status": "not_attempted",
        "alias_chain": [],
        "resolved_subcommand": None,
        "classification": "unresolved",
        "resolution_issues": list(parsed["issues"]),
        "parse_issues": list(parsed["issues"]),
        "source_index_map": [item["source_index"] for item in source_tokens],
        "_cargo_configuration": None,
        "_base_parse": parsed,
        "_original_args": list(args),
        "_effective_environment": dict(effective_environment),
        "_cwd": cwd,
    }
    if parsed["issues"] or (not parsed["requested_subcommand"] and not parsed.get("top_level_command")):
        analysis["alias_resolution_status"] = "unresolved"
        analysis["resolution_issues"].append(_invocation_issue("cargo_invocation_parse_unresolved"))
        return analysis

    cargo_cwd = cwd
    change_directory = parsed["global_options"].get("change_directory")
    if change_directory and change_directory.get("value"):
        directory = Path(change_directory["value"])
        if not directory.is_absolute():
            directory = cwd / directory
        try:
            cargo_cwd = directory.resolve()
        except (OSError, RuntimeError):
            cargo_cwd = directory.absolute()
            analysis["resolution_issues"].append(_invocation_issue("cargo_change_directory_unresolved"))
    analysis["_cargo_cwd"] = cargo_cwd

    cargo_version = cargo_version_or_capability_context or {}
    if cargo_version_or_capability_context is None:
        # Preflight can use this parsed header to select the toolchain for its
        # bounded cargo -Vv capability probe, then complete this same parse.
        return analysis
    initial_rows, initial_file_layers, initial_inline_layers, initial_discoveries = _collect_cargo_configuration(
        cargo_cwd, effective_environment, args, include_supported=False, include_active=False,
        parsed_invocation=parsed,
    )
    initial_settings, _initial_issues = _resolve_cargo_config_settings(
        initial_file_layers, initial_inline_layers, effective_environment, cargo_cwd,
    )
    include_support = _cargo_config_include_capability(cargo_version, parsed, initial_settings)
    records, file_layers, inline_layers, include_discoveries = _collect_cargo_configuration(
        cargo_cwd, effective_environment, args,
        include_supported=bool(include_support.get("supported")),
        include_active=bool(include_support.get("active")),
        parsed_invocation=parsed,
    )

    # File layers are already ordered from lower to higher Cargo precedence.
    aliases = {}
    alias_parse_uncertain = bool(
        include_support.get("support_status") == "unknown"
        and any(item.get("discovered") and item.get("argument_index") is None for item in initial_discoveries)
    )
    for row in records:
        if row.get("argument_index") is not None:
            # Cargo applies CLI --config values after alias expansion.
            continue
        if row.get("effective") and row.get("status") in {
            "unreadable", "not_regular_file", "not_present_required",
        }:
            alias_parse_uncertain = True
        if row.get("effective") and row.get("content_parse_status") == "skipped_sensitive_file":
            alias_parse_uncertain = True
        if row.get("effective") and include_support.get("active"):
            if any(issue.get("code", "").startswith("cargo_config_include_") for issue in row.get("_include_issues", [])):
                alias_parse_uncertain = True
    for layer in file_layers:
        if layer.get("precedence_group") == "cli":
            continue
        if layer.get("alias_issues"):
            alias_parse_uncertain = True
        for name, value in layer.get("aliases", {}).items():
            previous = aliases.get(name)
            if previous is not None and previous.get("status") == "resolved":
                previous_value = previous.get("value")
                # Cargo's configuration merge concatenates array-valued
                # aliases from lower to higher precedence. Scalar strings
                # replace the lower-precedence value.
                if isinstance(previous_value, list) and isinstance(value, list):
                    value = list(previous_value) + list(value)
            aliases[name] = {"value": value, "status": "resolved", "source": layer.get("source", "config_file")}
        for name in layer.get("invalid_aliases", []):
            aliases[name] = {"value": None, "status": "unresolved", "source": layer.get("source", "config_file")}
    # Cargo's alias environment variables override file values.
    environment_aliases = {}
    for key, value in effective_environment.items():
        if not key.startswith("CARGO_ALIAS_") or key != key.upper():
            continue
        normalized_name = key[len("CARGO_ALIAS_"):].lower().replace("_", "-")
        if not normalized_name:
            continue
        existing = environment_aliases.get(normalized_name)
        if existing is not None and existing.get("value") != value:
            environment_aliases[normalized_name] = {
                "value": None, "status": "unresolved", "source": "environment",
            }
        elif existing is None:
            environment_aliases[normalized_name] = {
                "value": value, "status": "resolved", "source": "environment",
            }
    for env_name, env_value in environment_aliases.items():
        aliases[env_name] = env_value
    # Cargo expands aliases before it applies command-line --config values or
    # files. Those values remain part of the invocation/config provenance, but
    # they cannot change this command's alias resolution.

    command_name = parsed["requested_subcommand"] or parsed.get("top_level_command")
    alias_chain = []
    resolution_issues = list(parsed["issues"])
    effective_options = parsed["command_options"]
    effective_global = parsed["global_options"]
    current_tail = parsed["command_tail"]
    requested_name = command_name
    seen = set()
    alias_resolution_status = "not_alias"
    cargo_version_pair = _cargo_version_tuple(cargo_version)
    cargo_channel = ((cargo_version or {}).get("parsed") or {}).get("channel")
    builtin_inventory_complete = bool(
        cargo_version_pair
        and CARGO_BUILTIN_INVENTORY_MIN_VERSION <= cargo_version_pair[:2] <= CARGO_BUILTIN_INVENTORY_MAX_VERSION
        and cargo_channel == "stable"
    )

    while True:
        builtin_state = _cargo_builtin_state(command_name, cargo_version_pair, builtin_inventory_complete)
        if builtin_state is True:
            alias_resolution_status = "resolved" if alias_chain else "not_alias"
            break
        if builtin_state is None:
            alias_resolution_status = "unresolved"
            resolution_issues.append(_invocation_issue("cargo_builtin_identity_version_unresolved"))
            command_name = None
            break
        alias_entry = aliases.get(command_name)
        if alias_entry is None and command_name in CARGO_BUILTIN_ALIASES:
            alias_entry = {"value": CARGO_BUILTIN_ALIASES[command_name], "source": "cargo_builtin_alias", "status": "resolved"}
        if alias_entry is None:
            if alias_parse_uncertain:
                alias_resolution_status = "unresolved"
                resolution_issues.append(_invocation_issue("cargo_alias_configuration_unresolved"))
                command_name = None
            else:
                alias_resolution_status = "resolved" if alias_chain else "not_alias"
            break
        alias_resolution_status = "resolved"
        if alias_entry.get("status") != "resolved":
            alias_resolution_status = "unresolved"
            resolution_issues.append(_invocation_issue("cargo_alias_definition_unresolved"))
            command_name = None
            break
        if command_name in seen:
            alias_resolution_status = "unresolved"
            resolution_issues.append(_invocation_issue("cargo_alias_cycle"))
            command_name = None
            break
        if len(alias_chain) >= CARGO_ALIAS_MAX_DEPTH:
            alias_resolution_status = "unresolved"
            resolution_issues.append(_invocation_issue("cargo_alias_recursion_limit"))
            command_name = None
            break
        seen.add(command_name)
        alias_chain.append(command_name)
        alias_words, alias_error = _alias_value_words(alias_entry.get("value"))
        if alias_error:
            alias_resolution_status = "unresolved"
            resolution_issues.append(_invocation_issue(alias_error))
            command_name = None
            break
        alias_tokens = [{"value": word, "source_index": None, "source": "alias"} for word in alias_words]
        if any(token["value"] == "--config" or token["value"].startswith("--config=") for token in alias_tokens):
            alias_resolution_status = "unresolved"
            resolution_issues.append(_invocation_issue("cargo_alias_cli_config_unresolved"))
            command_name = None
            break
        alias_tokens.extend(current_tail)
        expanded = _parse_cargo_argument_tokens(alias_tokens)
        if expanded["issues"] or not expanded["requested_subcommand"]:
            alias_resolution_status = "unresolved"
            resolution_issues.extend(expanded["issues"] or [_invocation_issue("cargo_alias_target_missing_subcommand")])
            command_name = None
            break
        command_name = expanded["requested_subcommand"]
        current_tail = expanded["command_tail"]
        effective_options = expanded["command_options"]
        effective_global["flags"].extend(expanded["global_options"]["flags"])
        effective_global["values"].extend(expanded["global_options"]["values"])
        effective_global["z_flags"].extend(expanded["global_options"]["z_flags"])

    if command_name is not None and not alias_parse_uncertain:
        final_command = command_name
    else:
        final_command = None

    if final_command is not None:
        analysis["resolved_subcommand"] = final_command
        if final_command == "fmt":
            classification = "known_special_external"
        elif final_command in set(build_producing_subcommands or ()):
            classification = "build_producing_command"
        elif _cargo_builtin_state(final_command, cargo_version_pair, builtin_inventory_complete) is True:
            classification = "known_non_build_builtin"
        elif builtin_inventory_complete:
            classification = "custom_or_external"
        else:
            classification = "unresolved"
            analysis["resolved_subcommand"] = None
            alias_resolution_status = "unresolved"
            resolution_issues.append(_invocation_issue("cargo_builtin_inventory_version_unverified"))
    else:
        classification = "unresolved"

    analysis.update({
        "alias_resolution_status": alias_resolution_status,
        "alias_chain": alias_chain,
        "resolved_subcommand": analysis.get("resolved_subcommand"),
        "classification": classification,
        "command_options": effective_options,
        "message_format": effective_options["message_format"][-1]["value"] if effective_options["message_format"] else None,
        "manifest_path": effective_options["manifest_path"][-1]["value"] if effective_options["manifest_path"] else None,
        "explicit_target": effective_options["target"][-1]["value"] if effective_options["target"] else None,
        "explicit_target_dir": effective_options["target_dir"][-1]["value"] if effective_options["target_dir"] else None,
        "global_options": effective_global,
        "resolution_issues": resolution_issues,
        "include_support": include_support,
    })
    analysis["_cargo_configuration"] = {
        "records": records, "file_layers": file_layers, "inline_layers": inline_layers,
        "include_discoveries": include_discoveries, "initial_rows": initial_rows,
        "settings": _resolve_cargo_config_settings(file_layers, inline_layers, effective_environment, cargo_cwd)[0],
    }
    analysis["_cargo_cwd"] = cargo_cwd
    return analysis


def _cargo_metadata(
    command: List[str],
    cwd: Path,
    env: dict,
    redact_arg_indexes: Optional[List[int]] = None,
    termination_grace_seconds: float = 5.0,
    cancellation: Any = None,
) -> Tuple[dict, Optional[dict]]:
    probe_options = {}
    if redact_arg_indexes:
        probe_options["redact_arg_indexes"] = redact_arg_indexes
    probe = run_probe(
        "cargo_metadata", command, cwd, env,
        keep_stdout=False, include_raw_stdout=True,
        termination_grace_seconds=termination_grace_seconds,
        cancellation=cancellation,
        **probe_options
    )
    raw = probe.pop("_raw_stdout", b"")
    result = {key: value for key, value in probe.items() if key != "stderr_excerpt"}
    metadata = None
    if probe.get("stdout_capture_truncated"):
        result["extraction_status"] = "capture_limit_exceeded"
    elif probe["status"] == "succeeded":
        try:
            data = strict_json_loads(raw.decode("utf-8"))
            metadata = {
                "workspace_root": data.get("workspace_root"),
                "target_directory": data.get("target_directory"),
                "build_directory": data.get("build_directory"),
                "package_manifest_paths": [
                    {"name": package.get("name"), "manifest_path": package.get("manifest_path")}
                    for package in data.get("packages", [])
                    if isinstance(package, dict) and package.get("manifest_path")
                ],
            }
            result["extraction_status"] = "succeeded"
        except DuplicateJSONKeyError:
            # Do not retain partially extracted fields or any raw source values.
            metadata = None
            result["extraction_status"] = "duplicate_json_key"
        except (UnicodeDecodeError, json.JSONDecodeError):
            result["extraction_status"] = "failed"
    else:
        result["extraction_status"] = "not_attempted"
    return result, metadata


def _selected_config_paths(directory: Path) -> Tuple[Optional[Path], Optional[Path]]:
    extensionless = directory / "config"
    toml_path = directory / "config.toml"
    has_extensionless = os.path.lexists(str(extensionless))
    has_toml = os.path.lexists(str(toml_path))
    if has_extensionless:
        return extensionless, toml_path if has_toml else None
    if has_toml:
        return toml_path, None
    return None, None


def _canonical_cargo_config_path(path: Path) -> Path:
    absolute = Path(os.path.abspath(str(path)))
    if os.name != "nt":
        # macOS commonly exposes temporary directories through aliases such
        # as /var -> /private/var. Resolve the parent, but deliberately retain
        # the final path component: a symlinked config file must still be
        # detected as a symlink by the no-follow file checks below.
        try:
            return absolute.parent.resolve(strict=False) / absolute.name
        except (OSError, RuntimeError):
            return absolute

    import ctypes
    from ctypes import wintypes

    get_long_path_name = ctypes.WinDLL("kernel32", use_last_error=True).GetLongPathNameW
    get_long_path_name.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
    get_long_path_name.restype = wintypes.DWORD
    for candidate, append_name in ((absolute, False), (absolute.parent, True)):
        buffer = ctypes.create_unicode_buffer(32768)
        length = get_long_path_name(str(candidate), buffer, len(buffer))
        if length:
            parent = Path(buffer.value)
            return parent / absolute.name if append_name else parent
    return absolute


def _collect_cargo_configuration(
    cwd: Path,
    env: dict,
    args: List[str],
    include_supported: bool = True,
    include_active: bool = True,
    parsed_invocation: Optional[dict] = None,
) -> Tuple[List[dict], List[dict], List[dict], List[dict]]:
    records: List[dict] = []
    file_layers: List[dict] = []
    inline_layers: List[dict] = []
    include_discoveries: List[dict] = []
    include_active = bool(include_supported and include_active)
    if parsed_invocation is None:
        parsed_invocation = analyze_cargo_invocation(args, cwd, env)

    def read_config(
        path: Path,
        source: str,
        effective: bool = True,
        included_by: Optional[str] = None,
        optional: bool = False,
        active_chain: Tuple[str, ...] = (),
        argument_index: Optional[int] = None,
        precedence_group: str = "files",
    ) -> List[dict]:
        canonical = _canonical_cargo_config_path(path)
        key = os.path.normcase(str(canonical))
        if key in active_chain:
            issue = {"code": "cargo_config_include_cycle", "path": str(canonical), "included_by": included_by}
            if records:
                records[-1].setdefault("_include_issues", []).append(issue)
            return []
        existing_row = next((item for item in records if os.path.normcase(item.get("path", "")) == key), None)
        try:
            path_stat = os.stat(str(path), follow_symlinks=False)
        except FileNotFoundError:
            if source in {"explicit_--config_file", "cargo_config_include"}:
                status = "not_present_optional" if optional else "not_present_required"
                row = {
                    "path": str(canonical), "source": source, "status": status,
                    "effective": effective, "included_by": included_by,
                    "optional": optional if included_by else None,
                    "argument_index": argument_index,
                }
                if status == "not_present_required":
                    row["_include_issues"] = [{
                        "code": "cargo_config_include_required_file_missing" if included_by else "cargo_config_file_missing",
                        "path": str(canonical), "included_by": included_by,
                    }]
                records.append(row)
            return []
        except OSError as exc:
            row = {
                "path": str(canonical), "source": source, "status": "unreadable",
                "effective": effective, "error_type": type(exc).__name__,
                "included_by": included_by, "optional": optional if included_by else None,
                "argument_index": argument_index,
                "_include_issues": [{
                    "code": "cargo_config_include_file_unreadable" if included_by else "cargo_config_file_unreadable",
                    "path": str(canonical),
                }],
            }
            records.append(row)
            return []
        if not stat.S_ISREG(path_stat.st_mode) or _shared_is_link_entry(path, path_stat):
            records.append({
                "path": str(canonical), "source": source, "status": "not_regular_file",
                "effective": effective, "included_by": included_by,
                "optional": optional if included_by else None, "argument_index": argument_index,
                "_include_issues": [{"code": "cargo_config_include_not_regular_file", "path": str(canonical)}],
            })
            return []
        try:
            data, digest, size = _shared_read_regular_file(path,)
        except OSError as exc:
            records.append({
                "path": str(canonical), "source": source, "status": "unreadable",
                "effective": effective, "error_type": type(exc).__name__,
                "included_by": included_by, "optional": optional if included_by else None,
                "argument_index": argument_index,
                "_include_issues": [{
                    "code": "cargo_config_include_file_unreadable" if included_by else "cargo_config_file_unreadable",
                    "path": str(canonical),
                }],
            })
            return []
        sensitive_path = bool(SECRET_NAME_RE.search(canonical.name))
        if existing_row is None:
            row = {
                "path": str(canonical), "size_bytes": size, "sha256": digest,
                "source": source, "status": "fingerprinted", "effective": effective,
                "included_by": included_by, "optional": optional if included_by else None,
                "argument_index": argument_index, "_content": None if sensitive_path else data.decode("utf-8-sig", errors="replace"),
                "_settings": {}, "_setting_issues": [], "_include_issues": [], "_include_discoveries": [],
            }
            records.append(row)
        else:
            row = existing_row
            if effective:
                row["effective"] = True
                row.pop("configuration_role", None)
        if not effective:
            row["configuration_role"] = "inactive_legacy_extension"
            return []
        if sensitive_path:
            row["content_parse_status"] = "skipped_sensitive_file"
            row["_include_issues"].append({
                "code": "cargo_config_sensitive_include_not_parsed", "path": str(canonical),
            })
            return [{
                "source": source, "path": str(canonical), "settings": {},
                "issues": row["_include_issues"], "precedence_group": precedence_group,
                "argument_index": argument_index,
            }]

        settings, setting_issues = _read_cargo_config_settings(row["_content"])
        row["_settings"] = settings
        row["_setting_issues"] = setting_issues
        row["_include_issues"].extend(setting_issues)
        specs, parse_issues = _top_level_include_specs(row["_content"])
        for issue in parse_issues:
            structured_issue = dict(issue, path=str(canonical))
            row["_include_issues"].append(structured_issue)
            discovery = dict(
                structured_issue, discovered=True, supported=include_supported,
                active=include_active, fingerprinted=False, argument_index=argument_index,
                precedence_group=precedence_group,
            )
            include_discoveries.append(discovery)
            row["_include_discoveries"].append(discovery)
        next_chain = active_chain + (key,)
        child_layers = []
        for spec_index, spec in enumerate(specs):
            include_value = spec["path"]
            include_path = Path(include_value)
            if not include_path.is_absolute():
                include_path = canonical.parent / include_path
            try:
                resolved_include_path = include_path.resolve()
            except (OSError, RuntimeError) as exc:
                issue = {
                    "code": "cargo_config_include_path_unresolved", "path": str(include_path),
                    "included_by": str(canonical), "error_type": type(exc).__name__,
                }
                row["_include_issues"].append(issue)
                include_discoveries.append(dict(
                    issue, discovered=True, supported=include_supported, active=include_active,
                    optional=spec["optional"], fingerprinted=False, argument_index=argument_index,
                    precedence_group=precedence_group,
                ))
                row["_include_discoveries"].append(include_discoveries[-1])
                continue
            edge = {
                "path": str(resolved_include_path), "included_by": str(canonical),
                "declared_order": spec_index, "optional": spec["optional"],
                "discovered": True, "supported": include_supported, "active": include_active,
                "fingerprinted": False, "argument_index": argument_index,
                "precedence_group": precedence_group,
            }
            include_discoveries.append(edge)
            row["_include_discoveries"].append(edge)
            if not include_active:
                continue
            if resolved_include_path.suffix.lower() != ".toml":
                issue = dict(edge, code="cargo_config_include_path_extension_unsupported")
                row["_include_issues"].append(issue)
                continue
            if os.path.normcase(str(resolved_include_path)) in next_chain:
                issue = dict(edge, code="cargo_config_include_cycle")
                row["_include_issues"].append(issue)
                continue
            child_layers.extend(read_config(
                resolved_include_path, "cargo_config_include", True, str(canonical),
                spec["optional"], next_chain, argument_index, precedence_group,
            ))
            edge["fingerprinted"] = any(
                os.path.normcase(item.get("path", "")) == os.path.normcase(str(resolved_include_path))
                and item.get("status") == "fingerprinted"
                for item in records
            )
        current_layer = {
            "source": source, "path": str(canonical), "settings": settings,
            "issues": setting_issues, "precedence_group": precedence_group,
            "argument_index": argument_index,
            "aliases": {
                key[len("alias."):]: value for key, value in settings.items()
                if key.startswith("alias.")
            },
            "alias_issues": [issue for issue in setting_issues if issue.get("code", "").startswith("cargo_alias_")],
        }
        return child_layers + [current_layer]

    cargo_home = Path(env.get("CARGO_HOME", str(Path.home() / ".cargo"))).expanduser()
    home_source = "CARGO_HOME" if env.get("CARGO_HOME") else "default_CARGO_HOME"
    selected, inactive = _selected_config_paths(cargo_home)
    if selected is not None:
        file_layers.extend(read_config(selected, home_source, True, precedence_group="files"))
    if inactive is not None:
        read_config(inactive, home_source, False, precedence_group="files")

    directories = []
    current = cwd
    while True:
        directories.append(current)
        if current.parent == current:
            break
        current = current.parent
    for directory in reversed(directories):
        cargo_dir = directory / ".cargo"
        selected, inactive = _selected_config_paths(cargo_dir)
        if selected is not None:
            file_layers.extend(read_config(selected, "cwd_or_parent", True, precedence_group="files"))
        if inactive is not None:
            read_config(inactive, "cwd_or_parent", False, precedence_group="files")

    for occurrence in parsed_invocation.get("global_options", {}).get("config_occurrences", []):
        config_value = occurrence.get("value")
        argument_index = occurrence.get("argument_index")
        if config_value is None:
            continue
        if "=" not in config_value:
            explicit_path = Path(config_value).expanduser()
            if not explicit_path.is_absolute():
                explicit_path = cwd / explicit_path
            file_layers.extend(read_config(
                explicit_path, "explicit_--config_file", True,
                argument_index=argument_index, precedence_group="cli",
            ))
            continue
        key, raw = config_value.split("=", 1)
        key = key.strip().strip('"').strip("'")
        if key not in BUILD_CONFIG_KEYS and key != "alias" and not key.startswith("alias."):
            continue
        parsed, valid = _parse_toml_value(raw)
        layer = {
            "key": key, "value": parsed,
            "status": "resolved" if valid else "unresolved",
            "source": "cargo_--config", "argument_index": argument_index,
        }
        inline_layers.append(layer)

    for edge in include_discoveries:
        if not edge.get("active"):
            continue
        target_key = os.path.normcase(edge.get("path", ""))
        edge["fingerprinted"] = any(
            os.path.normcase(item.get("path", "")) == target_key
            and item.get("status") == "fingerprinted"
            for item in records
        )
    return records, file_layers, inline_layers, include_discoveries


def _cargo_config_files(
    cwd: Path,
    env: dict,
    args: List[str],
    include_supported: bool = True,
    include_active: bool = True,
    parsed_invocation: Optional[dict] = None,
) -> List[dict]:
    records, _file_layers, _inline_layers, _discoveries = _collect_cargo_configuration(
        cwd, env, args, include_supported, include_active, parsed_invocation,
    )
    return records


def refresh_step_cargo_configuration(
    step_record: dict,
    original_args: Optional[List[str]] = None,
    invocation_analysis: Optional[dict] = None,
) -> List[dict]:
    """Fingerprint the Cargo config/include graph again after all steps ran."""
    configuration = step_record.get("cargo_configuration") or {}
    before_rows = configuration.get("files") or []
    # The public probe argv is redacted presentation data. Refresh the config
    # graph from the original in-memory step arguments when the runner supplies
    # them; callers without invocation context can still refresh discovered
    # files without inheriting redacted probe arguments.
    args = list(original_args or [])
    home_path = configuration.get("cargo_home_search_path")
    env = {"CARGO_HOME": home_path} if configuration.get("cargo_home_source") == "CARGO_HOME" and home_path else {}
    include_support = configuration.get("include_support") or {}
    refresh_includes_supported = include_support.get("supported", True) if include_support else True
    refresh_includes_active = include_support.get("active", True) if include_support else True
    try:
        analysis = invocation_analysis
        if analysis is None:
            cargo_context = parse_cargo_version_probe(
                (step_record.get("cargo") or {}).get("version_probe") or {}
            )
            analysis = analyze_cargo_invocation(
                args, Path(step_record["cwd"]), env, cargo_context,
            )
        after_rows = _cargo_config_files(
            Path(step_record["cwd"]), env, args,
            include_supported=bool(refresh_includes_supported),
            include_active=bool(refresh_includes_active),
            parsed_invocation=analysis,
        )
    except (KeyError, OSError, ValueError) as exc:
        configuration["refresh_status"] = "unavailable"
        configuration.setdefault("include_issues", []).append({
            "code": "cargo_configuration_after_unavailable", "error_type": type(exc).__name__,
        })
        return [{"code": "cargo_configuration_after_unavailable", "error_type": type(exc).__name__}]

    def public(item: dict) -> dict:
        return {key: value for key, value in item.items() if not key.startswith("_")}

    def state(item: Optional[dict]) -> dict:
        if item is None:
            return {"status": "not_present", "size_bytes": None, "sha256": None}
        return {
            "status": item.get("status", "unavailable"),
            "size_bytes": item.get("size_bytes"),
            "sha256": item.get("sha256"),
        }

    def path_key(item: dict) -> str:
        return os.path.normcase(os.path.abspath(item.get("path", "")))

    before_by_path = {path_key(item): item for item in before_rows}
    after_by_path = {path_key(item): item for item in after_rows}
    merged = []
    changed_paths = []
    for key in sorted(set(before_by_path) | set(after_by_path)):
        before_item = before_by_path.get(key)
        after_item = after_by_path.get(key)
        row = public(before_item or after_item)
        before_state = state(before_item)
        after_state = state(after_item)
        changed = before_state != after_state
        row["before"] = before_state
        row["after"] = after_state
        row["change_status"] = "changed" if changed else "unchanged"
        if changed:
            changed_paths.append(row.get("path"))
        merged.append(row)
    before_issues = configuration.get("include_issues") or []
    after_issues = [issue for item in after_rows for issue in item.get("_include_issues", [])]
    after_discoveries = [edge for item in after_rows for edge in item.get("_include_discoveries", [])]

    def deduplicate(items: List[dict]) -> List[dict]:
        seen = set()
        result = []
        for item in items:
            key = canonical_json_bytes(item)
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result

    combined_issues = deduplicate(list(before_issues) + after_issues)
    configuration["files"] = merged
    configuration["include_issues_before"] = before_issues
    configuration["include_issues_after"] = after_issues
    configuration["include_issues"] = combined_issues
    configuration["include_discoveries_after"] = after_discoveries
    configuration["refresh_status"] = "succeeded"
    issues = []
    if changed_paths:
        issues.append({
            "code": "cargo_configuration_changed_during_agent_run",
            "paths": changed_paths,
        })
    if before_issues != after_issues:
        issues.append({"code": "cargo_configuration_include_graph_changed"})
    return issues


BUILD_CONFIG_KEYS = {
    "build.target", "build.rustc", "build.rustc-wrapper", "build.rustc-workspace-wrapper",
    "build.target-dir", "build.build-dir", "unstable.config-include",
}


def _parse_toml_value(raw: str) -> Tuple[Any, bool]:
    raw = _strip_toml_comment(raw).strip()
    parsed_string = _parse_toml_string(raw)
    if parsed_string is not None:
        return parsed_string, True
    if raw.startswith("[") and raw.endswith("]"):
        values = []
        for item in _split_toml_items(raw[1:-1]):
            if not item:
                continue
            parsed, valid = _parse_toml_value(item)
            if not valid:
                return None, False
            values.append(parsed)
        return values, True
    try:
        return json.loads(raw), True
    except (json.JSONDecodeError, TypeError):
        return None, False


def _read_cargo_config_settings(content: str) -> Tuple[dict, List[dict]]:
    """Read provenance-relevant Cargo settings without adding a TOML dependency."""
    result = {}
    issues = []
    alias_keys_seen = set()
    section = ""
    lines = content.splitlines()
    index = 0
    while index < len(lines):
        stripped = _strip_toml_comment(lines[index]).strip()
        if not stripped:
            index += 1
            continue
        table = re.match(r"^\[([^]]+)\]$", stripped)
        array_table = re.match(r"^\[\[(.+)\]\]$", stripped)
        if table:
            section = table.group(1).strip().strip('"').strip("'")
            index += 1
            continue
        if array_table:
            section = array_table.group(1).strip().strip('"').strip("'")
            if section == "alias":
                issues.append({"code": "cargo_alias_config_unresolved", "line": index + 1})
            index += 1
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*=\s*(.*)$", stripped)
        if not match:
            if section == "alias" or stripped.startswith("alias"):
                issues.append({"code": "cargo_alias_config_unresolved", "line": index + 1})
            index += 1
            continue
        raw_key, raw = match.group(1), match.group(2)
        key = raw_key if "." in raw_key else (section + "." + raw_key if section else raw_key)
        while not _toml_value_is_complete(raw) and index + 1 < len(lines):
            index += 1
            raw += "\n" + _strip_toml_comment(lines[index])
        if key in BUILD_CONFIG_KEYS or key == "alias" or key.startswith("alias."):
            value, valid = _parse_toml_value(raw)
            if valid:
                result[key] = value
            else:
                if key == "alias" or key.startswith("alias."):
                    issues.append({"code": "cargo_alias_config_unresolved", "line": index + 1})
                else:
                    issues.append({
                        "code": "cargo_config_setting_unresolved",
                        "key": key,
                        "line": index + 1,
                    })
            if key.startswith("alias."):
                if key in alias_keys_seen:
                    issues.append({"code": "cargo_alias_config_duplicate", "line": index + 1})
                alias_keys_seen.add(key)
        index += 1
    return result, issues


def _read_build_setting(content: str, setting: str) -> Tuple[bool, Any, bool]:
    key = "build." + setting
    settings, issues = _read_cargo_config_settings(content)
    issue = next((item for item in issues if item.get("key") == key), None)
    return key in settings or issue is not None, settings.get(key), issue is None


def _inline_build_settings(args: List[str]) -> List[dict]:
    analysis = analyze_cargo_invocation(args, Path.cwd(), os.environ)
    context = analysis.get("_cargo_configuration") or {}
    return [
        layer for layer in context.get("inline_layers", [])
        if layer.get("key") in BUILD_CONFIG_KEYS
    ]


def _explicit_target(args: List[str]) -> Optional[str]:
    analysis = args if isinstance(args, dict) and "command_options" in args else analyze_cargo_invocation(args, Path.cwd(), os.environ)
    return analysis.get("explicit_target")


def _option_value(args: List[str], option: str) -> Optional[str]:
    analysis = args if isinstance(args, dict) and "command_options" in args else analyze_cargo_invocation(args, Path.cwd(), os.environ)
    field = {
        "--message-format": "message_format", "--manifest-path": "manifest_path",
        "--target": "target", "--target-dir": "target_dir",
    }.get(option)
    if field is None:
        return None
    values = (analysis.get("command_options") or {}).get(field) or []
    return values[-1].get("value") if values else None


def _resolve_step_path(value: str, cwd: Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = cwd / path
    return Path(os.path.abspath(str(path)))


def _nearest_manifest(cwd: Path) -> Optional[Path]:
    current = cwd.resolve()
    while True:
        candidate = current / "Cargo.toml"
        try:
            info = os.stat(str(candidate), follow_symlinks=False)
        except OSError:
            info = None
        if info is not None and (stat.S_ISREG(info.st_mode) or _shared_is_link_entry(candidate, info)):
            return candidate
        if current.parent == current:
            return None
        current = current.parent


def _manifest_for_step(args: List[str], cwd: Path) -> Tuple[Optional[Path], str]:
    analysis = args if isinstance(args, dict) and "command_options" in args else analyze_cargo_invocation(args, cwd, os.environ)
    configured = analysis.get("manifest_path")
    if configured is not None:
        return _resolve_step_path(configured, cwd), "step_--manifest-path"
    return _nearest_manifest(cwd), "nearest_manifest_from_step_cwd"


def _workspace_root_for_manifest(manifest_path: Optional[Path]) -> Optional[Path]:
    if manifest_path is None:
        return None
    current = manifest_path.parent
    nearest = current
    while True:
        candidate = current / "Cargo.toml"
        try:
            info = os.stat(str(candidate), follow_symlinks=False)
        except OSError:
            info = None
        if info is not None and stat.S_ISREG(info.st_mode) and not _shared_is_link_entry(candidate, info):
            try:
                raw, _digest, _size = _shared_read_regular_file(candidate, expected=info)
                content = raw.decode("utf-8-sig", errors="replace")
            except OSError:
                content = ""
            if re.search(r"(?m)^\s*\[workspace\]\s*(?:#.*)?$", content):
                return current.resolve()
        if current.parent == current:
            break
        current = current.parent
    return nearest.resolve()


def _resolve_target_directory(value: str, cwd: Path) -> Path:
    return _resolve_step_path(value, cwd)


def _cargo_config_arguments_with_source_indexes(args: List[str]) -> Tuple[List[str], List[int]]:
    """Compatibility wrapper returning source-indexed options from shared analysis."""
    analysis = args if isinstance(args, dict) and "config_occurrences" in args else analyze_cargo_invocation(args, Path.cwd(), os.environ)
    result: List[str] = []
    source_indexes: List[int] = []
    for occurrence in analysis.get("config_occurrences", []):
        argument_index = occurrence.get("argument_index")
        if argument_index is None or occurrence.get("source") == "alias":
            continue
        if occurrence.get("form") == "separate":
            value_index = occurrence.get("value_argument_index")
            if value_index is None:
                continue
            result.extend(("--config", occurrence.get("value", "")))
            source_indexes.extend((argument_index, value_index))
        else:
            result.append(occurrence.get("option_argument", "--config=" + occurrence.get("value", "")))
            source_indexes.append(argument_index)
    return result, source_indexes


def _cargo_config_arguments(args: List[str]) -> List[str]:
    """Carry only this step's explicit Cargo config options into metadata probes."""
    return _cargo_config_arguments_with_source_indexes(args)[0]


def _map_redact_arg_indexes(
    source_redact_indexes: List[int],
    selected_source_indexes: List[int],
    destination_offset: int = 0,
) -> List[int]:
    """Map explicit step argv indexes into a selected command's argv indexes."""
    source_indexes = set(source_redact_indexes)
    return [
        destination_offset + selected_index
        for selected_index, source_index in enumerate(selected_source_indexes)
        if source_index in source_indexes
    ]


SETTING_ENVIRONMENT_NAMES = {
    "build.target": ("CARGO_BUILD_TARGET",),
    "build.rustc": ("CARGO_BUILD_RUSTC", "RUSTC"),
    "build.rustc-wrapper": ("CARGO_BUILD_RUSTC_WRAPPER", "RUSTC_WRAPPER"),
    "build.rustc-workspace-wrapper": (
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
    ),
    "build.target-dir": ("CARGO_BUILD_TARGET_DIR", "CARGO_TARGET_DIR"),
    "build.build-dir": ("CARGO_BUILD_BUILD_DIR",),
    "unstable.config-include": ("CARGO_UNSTABLE_CONFIG_INCLUDE",),
}


def _cargo_config_value_valid(key: str, value: Any) -> bool:
    if key == "build.target":
        return isinstance(value, str) or (
            isinstance(value, list) and all(isinstance(item, str) for item in value)
        )
    if key == "unstable.config-include":
        return isinstance(value, bool)
    return isinstance(value, str)


def _resolve_cargo_config_settings(
    file_layers: List[dict],
    inline_layers: List[dict],
    env: dict,
    cwd: Path,
    metadata_target_directory: Optional[Path] = None,
) -> Tuple[dict, List[dict]]:
    defaults = {
        "build.target": {"value": None, "source": "cargo_default", "status": "implicit_default"},
        "build.rustc": {"value": "rustc", "source": "cargo_default", "status": "resolved"},
        "build.rustc-wrapper": {"value": None, "source": "cargo_default", "status": "implicit_default"},
        "build.rustc-workspace-wrapper": {
            "value": None, "source": "cargo_default", "status": "implicit_default",
        },
        "build.target-dir": {"value": None, "source": "cargo_default", "status": "unresolved"},
        "build.build-dir": {"value": None, "source": "cargo_default", "status": "implicit_default"},
        "unstable.config-include": {"value": False, "source": "cargo_default", "status": "resolved"},
    }
    selected = {key: dict(value) for key, value in defaults.items()}
    issues = []
    keys = list(defaults)

    def apply_layer(key: str, layer: dict, value: Any, status: str = "resolved") -> None:
        current = {
            "value": value,
            "source": layer.get("source", "cargo_configuration"),
            "status": status,
        }
        if layer.get("path"):
            current["source_file"] = layer["path"]
        if layer.get("argument_index") is not None:
            current["argument_index"] = layer["argument_index"]
        selected[key] = current

    def apply_file_group(group: str) -> None:
        for layer in file_layers:
            if layer.get("precedence_group") != group:
                continue
            for key in keys:
                setting_issues = [
                    issue for issue in layer.get("issues", []) if issue.get("key") == key
                ]
                if setting_issues:
                    issues.extend(dict(issue, source=layer.get("source"), path=layer.get("path")) for issue in setting_issues)
                    apply_layer(key, layer, None, "unresolved")
                if key not in layer.get("settings", {}):
                    continue
                value = layer["settings"][key]
                apply_layer(
                    key, layer, value,
                    "resolved" if _cargo_config_value_valid(key, value) else "unresolved",
                )
                if selected[key]["status"] == "unresolved":
                    issues.append({
                        "code": "cargo_config_setting_type_unresolved",
                        "key": key, "source": layer.get("source"), "path": layer.get("path"),
                    })

    # Ordinary configuration files are merged from low to high precedence.
    apply_file_group("files")

    # Cargo reads environment overrides after hierarchical files. The two
    # target-dir aliases have changed in precedence across Cargo releases, so
    # use metadata's effective path to distinguish conflicting values.
    environment_candidates = {}
    for key, names in SETTING_ENVIRONMENT_NAMES.items():
        present = [(name, env[name]) for name in names if name in env]
        if not present:
            continue
        if key == "build.target-dir" and len(present) > 1:
            paths = [
                (name, value, _resolve_target_directory(value, cwd))
                for name, value in present if isinstance(value, str)
            ]
            matches = [
                item for item in paths
                if metadata_target_directory is not None and item[2] == metadata_target_directory
            ]
            if len(matches) == 1:
                name, value, _path = matches[0]
                environment_candidates[key] = (name, value)
            elif len(paths) and len({str(item[2]) for item in paths}) == 1:
                environment_candidates[key] = (paths[0][0], paths[0][1])
            elif metadata_target_directory is None:
                environment_candidates[key] = (None, None)
            else:
                environment_candidates[key] = (None, None)
        else:
            environment_candidates[key] = present[0]
    for key, (name, value) in environment_candidates.items():
        if name is None:
            selected[key] = {
                "value": str(metadata_target_directory) if key == "build.target-dir" and metadata_target_directory else None,
                "source": "cargo_metadata" if key == "build.target-dir" and metadata_target_directory else "conflicting_environment",
                "status": "resolved" if key == "build.target-dir" and metadata_target_directory else "unresolved",
            }
            if selected[key]["status"] == "unresolved":
                issues.append({"code": "cargo_config_setting_conflicting_environment", "key": key})
            continue
        layer = {"source": name}
        apply_layer(
            key, layer, value,
            "resolved" if _cargo_config_value_valid(key, value) else "unresolved",
        )
        if selected[key]["status"] == "unresolved":
            issues.append({"code": "cargo_config_setting_type_unresolved", "key": key, "source": name})

    # CLI --config files and values are the highest configuration layer and
    # are applied in their original left-to-right argument order.
    cli_events = []
    sequence = 0
    for layer in file_layers:
        if layer.get("precedence_group") == "cli":
            cli_events.append((layer.get("argument_index", -1), sequence, "file", layer))
            sequence += 1
    for layer in inline_layers:
        cli_events.append((layer.get("argument_index", -1), sequence, "inline", layer))
        sequence += 1
    cli_events.sort(key=lambda item: (item[0], item[1]))
    for _argument_index, _sequence, kind, layer in cli_events:
        for key in keys:
            if kind == "inline" and layer.get("key") == key:
                value = layer.get("value")
                status = layer.get("status", "unresolved")
                if status == "resolved" and not _cargo_config_value_valid(key, value):
                    status = "unresolved"
                apply_layer(key, layer, value, status)
                if status == "unresolved":
                    issues.append({
                        "code": "cargo_config_setting_unresolved", "key": key,
                        "source": "cargo_--config", "argument_index": layer.get("argument_index"),
                    })
            elif kind == "file":
                setting_issues = [
                    issue for issue in layer.get("issues", []) if issue.get("key") == key
                ]
                if setting_issues:
                    issues.extend(dict(issue, source=layer.get("source"), path=layer.get("path")) for issue in setting_issues)
                    apply_layer(key, layer, None, "unresolved")
                if key in layer.get("settings", {}):
                    value = layer["settings"][key]
                    status = "resolved" if _cargo_config_value_valid(key, value) else "unresolved"
                    apply_layer(key, layer, value, status)
                    if status == "unresolved":
                        issues.append({
                            "code": "cargo_config_setting_type_unresolved",
                            "key": key, "source": layer.get("source"), "path": layer.get("path"),
                        })
    return selected, issues


def _cargo_config_include_capability(
    cargo_version: dict,
    args_or_analysis: Any,
    settings: dict,
) -> dict:
    parsed = cargo_version.get("parsed") or {}
    release = parsed.get("release")
    channel = (parsed.get("channel") or "").lower()
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", release or "")
    version = tuple(int(part or 0) for part in match.groups()) if match else None
    stable_release = bool(version and version[:2] >= (1, 94) and channel == "stable")
    beta_commit_date = parsed.get("commit_date")
    beta_stable_support = bool(
        version and version[:2] >= (1, 94) and channel == "beta"
        and beta_commit_date and beta_commit_date >= "2025-12-12"
    )
    beta_support_unresolved = bool(
        version and version[:2] >= (1, 94) and channel == "beta" and not beta_commit_date
    )
    nightly = channel == "nightly"
    supported = stable_release or beta_stable_support or nightly
    if isinstance(args_or_analysis, dict) and "global_options" in args_or_analysis:
        parsed = args_or_analysis
    else:
        raw_args = list(args_or_analysis or [])
        parsed = analyze_cargo_invocation(
            raw_args, Path.cwd(), os.environ, cargo_version,
        )
    z_flags = (parsed.get("global_options") or {}).get("z_flags", [])
    cli_enabled = any(
        str(item.get("value", "")).split("=", 1)[0] == "config-include"
        for item in z_flags
    )
    config_enabled = (
        (settings.get("unstable.config-include") or {}).get("status") == "resolved"
        and (settings.get("unstable.config-include") or {}).get("value") is True
    )
    if stable_release:
        active, activation_source = True, "stable_since_1.94"
    elif beta_stable_support:
        active, activation_source = True, "stabilization_present_in_beta_branch"
    elif beta_support_unresolved:
        active, activation_source = None, "beta_feature_availability_unresolved"
    elif nightly:
        active = cli_enabled or config_enabled
        activation_source = (
            "step_-Zconfig-include" if cli_enabled
            else "unstable.config-include" if config_enabled
            else "not_activated"
        )
    elif not release or not channel:
        active, activation_source = False, "cargo_version_unresolved"
    else:
        active, activation_source = False, "not_supported_by_selected_cargo"
    support_status = (
        "supported" if supported else
        "unknown" if beta_support_unresolved or not release or not channel else
        "unsupported"
    )
    return {
        "cargo_release": release,
        "channel": channel or None,
        "support_status": support_status,
        "supported": supported if release and channel and not beta_support_unresolved else None,
        "active": active if release and channel and not beta_support_unresolved else None,
        "activation_source": activation_source,
        "stable_since": "1.94.0",
        "beta_feature_commit_date": beta_commit_date if channel == "beta" else None,
        "beta_stabilization_merge_date": "2025-12-12",
    }


def _config_setting_path(
    setting: dict,
    cwd: Path,
    workspace_root: Optional[Path] = None,
    cargo_home: Optional[Path] = None,
    metadata_path: Optional[Path] = None,
) -> dict:
    value = setting.get("value")
    if setting.get("status") not in {"resolved", "implicit_default"}:
        return {"path": None, "status": "unresolved", "source": setting.get("source")}
    if not isinstance(value, str) or not value:
        if setting.get("source") == "cargo_default" and metadata_path is not None:
            return {"path": str(metadata_path), "status": "resolved", "source": "cargo_default"}
        return {"path": None, "status": "unresolved", "source": setting.get("source")}
    expanded = value
    replacements = {
        "{workspace-root}": str(workspace_root) if workspace_root else None,
        "{cargo-cache-home}": str(cargo_home) if cargo_home else None,
    }
    for template, replacement in replacements.items():
        if template in expanded:
            if replacement is None:
                return {"path": None, "status": "unresolved", "source": setting.get("source"), "template": template}
            expanded = expanded.replace(template, replacement)
    if "{workspace-path-hash}" in expanded:
        if metadata_path is not None:
            return {"path": str(metadata_path), "status": "resolved", "source": "cargo_metadata_template_expansion"}
        return {
            "path": None, "status": "unresolved", "source": setting.get("source"),
            "template": "workspace-path-hash",
        }
    if "{" in expanded or "}" in expanded:
        return {"path": None, "status": "unresolved", "source": setting.get("source"), "template": "unsupported"}
    source = setting.get("source")
    environment_sources = {name for names in SETTING_ENVIRONMENT_NAMES.values() for name in names}
    if source in environment_sources or source in {"cargo_--config", "step_--target-dir"}:
        base = cwd
    elif setting.get("source_file"):
        file_dir = Path(setting["source_file"]).parent
        base = file_dir.parent if file_dir.name == ".cargo" else file_dir
    else:
        base = workspace_root or cwd
    path = Path(expanded).expanduser()
    if not path.is_absolute():
        path = base / path
    return {"path": str(path.resolve()), "status": "resolved", "source": source}


def _configuration_output_source(setting: dict) -> str:
    source = setting.get("source")
    if source in {"cwd_or_parent", "CARGO_HOME", "default_CARGO_HOME", "explicit_--config_file"}:
        return "cargo_config_file"
    return source or "unresolved"


def _toolchain_files(cwd: Path) -> List[dict]:
    records = []
    current = cwd
    while True:
        for name in ("rust-toolchain", "rust-toolchain.toml"):
            path = current / name
            try:
                info = os.stat(str(path), follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode) or _shared_is_link_entry(path, info):
                records.append({"path": str(path.absolute()), "status": "not_regular_file"})
                continue
            try:
                _content, digest, size = _shared_read_regular_file(path, expected=info)
                records.append({"path": str(path.absolute()), "size_bytes": size, "sha256": digest})
            except OSError as exc:
                records.append({"path": str(path.absolute()), "status": "unreadable", "error_type": type(exc).__name__})
        if current.parent == current:
            break
        current = current.parent
    return records


def _is_relevant_environment_name(name: str) -> bool:
    name = name.upper()
    if name in ENVIRONMENT_NAMES:
        return True
    if name.startswith("CARGO_ALIAS_"):
        return True
    if name.startswith((
        "CARGO_TARGET_", "CARGO_PROFILE_", "CARGO_BUILD_", "CARGO_REGISTRIES_", "CARGO_RESOLVER_",
        "RUSTC_", "RUSTDOC_", "RUSTUP_",
    )):
        return True
    return name in {"RUSTC", "RUSTDOC", "RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC_BOOTSTRAP"}


def _redact_environment_value(name: str, value: str) -> str:
    if name.upper().startswith("CARGO_ALIAS_"):
        return REDACTED
    if SECRET_NAME_RE.search(name):
        return REDACTED
    if name.startswith("CARGO_REGISTRIES_"):
        return redact_url_text(value, "<REDACTED_UNPARSEABLE_REGISTRY_URL>")
    return redact_url_text(value)


def collect_step_provenance(
    cargo: str,
    step: dict,
    root: Path,
    base_env: dict,
    execution: dict,
    prepare_environment,
    resolve_cwd,
    cancellation: Any = None,
    invocation_analysis: Optional[dict] = None,
    cargo_version_probe: Optional[dict] = None,
) -> Tuple[dict, Optional[Path], List[dict]]:
    step_cwd = resolve_cwd(root, step["cwd"])
    env = prepare_environment(base_env, execution, step)
    args = list(step["args"])
    analysis = invocation_analysis
    if analysis is None:
        analysis = analyze_cargo_invocation(args, step_cwd, env)
    cwd = analysis.get("_cargo_cwd") or step_cwd
    selector = analysis.get("toolchain_selector")
    probe_args = (["+" + selector] if selector else [])
    selected_manifest, manifest_source = _manifest_for_step(analysis, cwd)
    candidate_workspace_root = _workspace_root_for_manifest(selected_manifest)
    cargo_path = _resolved_executable(cargo, env, cwd)

    # cargo -Vv must see the selector used by this actual pipeline step.
    grace = execution.get("termination_grace_seconds", 5.0)
    cargo_version = parse_cargo_version_probe(cargo_version_probe) if cargo_version_probe is not None else run_probe(
        "cargo_version", [cargo] + probe_args + ["-Vv"], cwd, env,
        termination_grace_seconds=grace, cancellation=cancellation,
    )
    if cargo_version_probe is None:
        cargo_version = parse_cargo_version_probe(cargo_version)
        analysis = analyze_cargo_invocation(
            args, step_cwd, env, cargo_version,
            build_producing_subcommands=(),
        )
    selected_manifest, manifest_source = _manifest_for_step(analysis, cwd)
    candidate_workspace_root = _workspace_root_for_manifest(selected_manifest)
    config_context = analysis.get("_cargo_configuration") or {}
    config_files = config_context.get("records", [])
    file_layers = config_context.get("file_layers", [])
    inline_layers = config_context.get("inline_layers", [])
    include_discoveries = config_context.get("include_discoveries", [])
    include_support = analysis.get("include_support") or {}
    effective_settings, config_setting_issues = _resolve_cargo_config_settings(
        file_layers, inline_layers, env, cwd,
    )

    selector_env = dict(env)
    if selector:
        selector_env["RUSTUP_TOOLCHAIN"] = selector
    explicit = analysis.get("explicit_target")
    env_target = env.get("CARGO_BUILD_TARGET")
    target_setting = effective_settings["build.target"]
    if explicit is not None:
        selected_target = {"value": explicit, "source": "step_--target", "status": "resolved"}
    elif target_setting.get("status") == "resolved":
        selected_target = dict(target_setting)
    elif target_setting.get("status") == "implicit_default":
        selected_target = {"value": None, "source": "cargo_default", "status": "implicit_default"}
    else:
        selected_target = dict(target_setting)

    rustc_setting = effective_settings["build.rustc"]
    rustc_candidate = rustc_setting.get("value") if rustc_setting.get("status") == "resolved" else None
    rustc_source = rustc_setting.get("source")
    rustc_certainty = (
        "inferred_from_path" if rustc_source == "cargo_default" else
        "explicit_cargo_configuration" if rustc_setting.get("status") == "resolved" else "unresolved"
    )
    wrapper_setting = effective_settings["build.rustc-wrapper"]
    wrapper = wrapper_setting.get("value") if wrapper_setting.get("status") == "resolved" else None
    wrapper_source = wrapper_setting.get("source") if wrapper else None
    workspace_wrapper_setting = effective_settings["build.rustc-workspace-wrapper"]
    workspace_wrapper = (
        workspace_wrapper_setting.get("value")
        if workspace_wrapper_setting.get("status") == "resolved" else None
    )
    workspace_wrapper_source = workspace_wrapper_setting.get("source") if workspace_wrapper else None
    if wrapper or workspace_wrapper:
        rustc_certainty = "inferred_with_wrapper" if rustc_candidate else "unresolved_with_wrapper"
    rustc_path = _resolved_executable(rustc_candidate, selector_env, cwd) if rustc_candidate else None
    rustc_probe = {
        "name": "rustc_version",
        "status": "unresolved" if rustc_candidate is None else "unavailable",
        "exit_code": None,
        "timeout_seconds": PROBE_TIMEOUT_SECONDS,
    }
    if rustc_candidate and (rustc_path or Path(rustc_candidate).is_absolute()):
        rustc_probe = run_probe(
            "rustc_version", [rustc_candidate, "-Vv"], cwd, selector_env,
            termination_grace_seconds=grace, cancellation=cancellation,
        )
        rustc_text = rustc_probe.get("stdout_excerpt", "")
        rustc_probe["parsed"] = {
            key: match.group(1).strip()
            for key, pattern in (
                ("release", r"^release:\s*(.+)$"), ("host", r"^host:\s*(.+)$"),
                ("commit_hash", r"^commit-hash:\s*(.+)$"), ("commit_date", r"^commit-date:\s*(.+)$"),
                ("llvm_version", r"^LLVM version:\s*(.+)$"),
            )
            for match in [re.search(pattern, rustc_text, re.MULTILINE)] if match
        }

    rustup_path = _resolved_executable("rustup", selector_env, cwd)
    rustup_probe = (
        run_probe(
            "rustup_active_toolchain", ["rustup", "show", "active-toolchain"], cwd, selector_env,
            termination_grace_seconds=grace, cancellation=cancellation,
        )
        if rustup_path else {"name": "rustup_active_toolchain", "status": "unavailable", "exit_code": None}
    )
    host_target = (rustc_probe.get("parsed") or {}).get("host")
    metadata_command = [cargo] + probe_args
    if include_support.get("activation_source") == "step_-Zconfig-include":
        metadata_command.extend(["-Zconfig-include"])
    metadata_command.extend(["metadata", "--no-deps", "--format-version", "1", "--locked", "--offline"])
    if selected_manifest is not None:
        metadata_command.extend(["--manifest-path", str(selected_manifest)])
    config_arguments, config_source_indexes = _cargo_config_arguments_with_source_indexes(analysis)
    config_argument_offset = len(metadata_command)
    metadata_command.extend(config_arguments)
    explicit_target_dir = analysis.get("explicit_target_dir")
    metadata_env = dict(env)
    if explicit_target_dir is not None:
        # `cargo metadata` has no --target-dir option. Mirror the actual Step's
        # explicit option through Cargo's documented environment interface.
        explicit_target_path = _resolve_target_directory(explicit_target_dir, cwd)
        metadata_env["CARGO_TARGET_DIR"] = str(explicit_target_path)
        metadata_env["CARGO_BUILD_TARGET_DIR"] = str(explicit_target_path)
    metadata_redact_indexes = _map_redact_arg_indexes(
        step.get("redact_arg_indexes", []),
        config_source_indexes,
        config_argument_offset,
    )
    metadata_probe, metadata = _cargo_metadata(
        metadata_command, cwd, metadata_env, metadata_redact_indexes,
        termination_grace_seconds=grace, cancellation=cancellation,
    )
    metadata_workspace = None
    if metadata and metadata.get("workspace_root"):
        metadata_workspace = Path(metadata["workspace_root"]).resolve()
    actual_workspace_root = metadata_workspace or candidate_workspace_root
    candidate_lockfile = actual_workspace_root / "Cargo.lock" if actual_workspace_root else None
    lock_status_before_probe = "unavailable"
    if candidate_lockfile is not None:
        try:
            lock_status_before_probe = "present" if candidate_lockfile.is_file() else "not_present"
        except OSError:
            lock_status_before_probe = "unreadable"
    lockfile_path = candidate_lockfile
    lock_status_after_probe = lock_status_before_probe
    if lockfile_path is not None:
        try:
            lock_status_after_probe = "present" if lockfile_path.is_file() else "not_present"
        except OSError:
            lock_status_after_probe = "unreadable"
    metadata_probe["lockfile_observation"] = {
        "path": str(lockfile_path) if lockfile_path else None,
        "before_probe": lock_status_before_probe,
        "after_probe": lock_status_after_probe,
        "mutation_policy": "cargo metadata is invoked with --locked --offline; a missing lockfile is not generated by the probe",
    }
    if lock_status_before_probe == "not_present" and lock_status_after_probe == "present":
        metadata_probe["lockfile_observation"]["status"] = "unexpectedly_created"
    else:
        metadata_probe["lockfile_observation"]["status"] = lock_status_after_probe
    if metadata is not None:
        metadata["selected_manifest_path"] = str(selected_manifest) if selected_manifest else None
        metadata["manifest_selection_source"] = manifest_source
        metadata["lockfile_path"] = str(lockfile_path) if lockfile_path else None
        metadata["lockfile_status"] = lock_status_after_probe
    metadata_target = None
    if metadata and metadata.get("target_directory"):
        metadata_target = Path(metadata["target_directory"]).expanduser()
        if not metadata_target.is_absolute():
            metadata_target = cwd / metadata_target
        metadata_target = metadata_target.resolve()
    effective_settings, config_setting_issues = _resolve_cargo_config_settings(
        file_layers, inline_layers, env, cwd, metadata_target,
    )
    if metadata_target and effective_settings["build.target-dir"].get("source") == "cargo_default":
        effective_settings["build.target-dir"] = {
            "value": str(metadata_target), "source": "cargo_metadata", "status": "resolved",
            "resolved_path": str(metadata_target),
        }
    target_candidates = []
    for name in SETTING_ENVIRONMENT_NAMES["build.target-dir"]:
        if name in env:
            target_candidates.append({
                "path": str(_resolve_target_directory(env[name], cwd)), "source": name,
            })
    target_setting = effective_settings["build.target-dir"]
    if target_setting.get("status") == "resolved" and isinstance(target_setting.get("value"), str):
        configured_path = _config_setting_path(
            target_setting, cwd, actual_workspace_root,
            Path(env.get("CARGO_HOME", str(Path.home() / ".cargo"))).expanduser(), metadata_target,
        )
        target_setting["resolved_path"] = configured_path.get("path")
        if configured_path.get("status") == "resolved":
            target_candidates.append({"path": configured_path["path"], "source": target_setting.get("source")})
            if metadata_target and Path(configured_path["path"]) != metadata_target and explicit_target_dir is None:
                # Preserve the configuration precedence result. If metadata
                # contradicts it (for example, a Cargo release gives the
                # legacy CARGO_TARGET_DIR alias special treatment), report
                # the observed directory separately and mark the effective
                # setting unresolved instead of promoting the lower value.
                target_setting["status"] = "unresolved"
                target_setting["resolution_issue"] = "cargo_metadata_disagrees_with_effective_configuration"
                config_setting_issues.append({"code": "cargo_config_setting_metadata_mismatch", "key": "build.target-dir"})
    if metadata_target:
        target_candidates.append({"path": str(metadata_target), "source": "cargo_metadata"})
    if explicit_target_dir is not None:
        target_directory = {
            "path": str(_resolve_target_directory(explicit_target_dir, cwd)),
            "source": "step_--target-dir", "configured_value": explicit_target_dir, "status": "resolved",
        }
        effective_settings["build.target-dir"] = {
            "value": explicit_target_dir, "source": "step_--target-dir", "status": "resolved",
            "resolved_path": target_directory["path"],
        }
    elif metadata_target:
        source = _configuration_output_source(target_setting) if target_setting.get("status") == "resolved" else "cargo_metadata"
        target_directory = {
            "path": str(metadata_target), "source": source,
            "configured_value": target_setting.get("value") if source != "cargo_metadata" else None,
            "status": "resolved", "candidates": target_candidates,
        }
    elif target_setting.get("resolved_path"):
        target_directory = {
            "path": target_setting["resolved_path"], "source": target_setting.get("source"),
            "configured_value": target_setting.get("value"), "status": "resolved",
            "candidates": target_candidates,
        }
    else:
        target_directory = {
            "path": None, "source": target_setting.get("source"),
            "configured_value": target_setting.get("value"), "status": "unresolved",
            "candidates": target_candidates,
        }

    if explicit is not None:
        effective_settings["build.target"] = {
            "value": explicit, "source": "step_--target", "status": "resolved",
        }

    cargo_home_path = Path(env.get("CARGO_HOME", str(Path.home() / ".cargo"))).expanduser().resolve()
    build_setting = effective_settings["build.build-dir"]
    metadata_build = None
    if metadata and metadata.get("build_directory"):
        metadata_build = Path(metadata["build_directory"]).expanduser()
        if not metadata_build.is_absolute():
            metadata_build = actual_workspace_root / metadata_build if actual_workspace_root else None
        if metadata_build is not None:
            metadata_build = metadata_build.resolve()
    if build_setting.get("status") == "implicit_default":
        # A metadata probe cannot receive the Step's --target-dir flag. In
        # that case, Cargo's default intermediate directory follows the
        # already-resolved Step target directory, even if probe metadata was
        # collected against a lower-precedence config value.
        build_directory = dict(target_directory)
        build_directory["source"] = "cargo_default_target_directory"
        build_directory["configured_value"] = None
        build_setting["resolved_path"] = build_directory.get("path")
        build_setting["status"] = "implicit_default" if build_directory.get("status") == "resolved" else "unresolved"
    elif metadata_build is not None:
        build_directory = {
            "path": str(metadata_build),
            "source": _configuration_output_source(build_setting) if build_setting.get("status") == "resolved" else "cargo_metadata",
            "configured_value": build_setting.get("value") if build_setting.get("status") == "resolved" else None,
            "status": "resolved",
        }
        build_setting["resolved_path"] = str(metadata_build)
        if build_setting.get("status") == "resolved" and isinstance(build_setting.get("value"), str):
            expected_build = _config_setting_path(
                build_setting, cwd, actual_workspace_root, cargo_home_path, metadata_build,
            )
            if expected_build.get("status") == "resolved" and Path(expected_build["path"]) != metadata_build:
                config_setting_issues.append({"code": "cargo_config_setting_metadata_mismatch", "key": "build.build-dir"})
    elif build_setting.get("status") == "resolved" and isinstance(build_setting.get("value"), str):
        build_directory = _config_setting_path(
            build_setting, cwd, actual_workspace_root, cargo_home_path,
        )
        build_directory["configured_value"] = build_setting.get("value")
        build_setting["resolved_path"] = build_directory.get("path")
    else:
        build_directory = {
            "path": None, "status": "unresolved", "source": build_setting.get("source"),
            "configured_value": build_setting.get("value"),
        }

    env_values = {}
    recorded_environment_names = {name for name in env if _is_relevant_environment_name(name)}
    recorded_environment_names.update(name for name in env if SECRET_NAME_RE.search(name))
    for name in sorted(recorded_environment_names):
        if name not in env:
            continue
        value = env[name]
        env_values[name] = _redact_environment_value(name, value)
    path_value = env.get("PATH", "")
    environment_record = {
        "values": env_values,
        "redaction_policy": "values whose variable names contain token, password, secret, key, credential, or auth are redacted",
        "PATH": {"sha256": sha256_bytes(os.fsencode(path_value)), "entry_count": len(path_value.split(os.pathsep)) if path_value else 0},
    }

    def public(item: dict) -> dict:
        return {key: value for key, value in item.items() if not key.startswith("_")}

    public_config_files = [public(item) for item in config_files]
    public_target_configs = [dict(layer, key="build.target") for layer in file_layers if "build.target" in layer.get("settings", {})]
    public_target_configs.extend(dict(item) for item in inline_layers if item.get("key") == "build.target")
    public_target_dir_configs = [dict(layer, key="build.target-dir") for layer in file_layers if "build.target-dir" in layer.get("settings", {})]
    public_target_dir_configs.extend(dict(item) for item in inline_layers if item.get("key") == "build.target-dir")
    public_rustc_configs = [dict(layer, key="build.rustc") for layer in file_layers if "build.rustc" in layer.get("settings", {})]
    public_rustc_configs.extend(dict(item) for item in inline_layers if item.get("key") == "build.rustc")
    public_wrapper_configs = [
        dict(layer, key=key) for layer in file_layers for key in ("build.rustc-wrapper", "build.rustc-workspace-wrapper")
        if key in layer.get("settings", {})
    ]
    public_wrapper_configs.extend(dict(item) for item in inline_layers if item.get("key") in {"build.rustc-wrapper", "build.rustc-workspace-wrapper"})
    config_issues = [issue for item in config_files for issue in item.get("_include_issues", [])]
    config_issues.extend(config_setting_issues)
    if include_support.get("support_status") == "unknown":
        config_issues.append({"code": "cargo_config_include_support_unresolved"})
    step_record = {
        "cwd": str(cwd),
        "configured_step_cwd": str(step_cwd),
        "cargo": {
            "configured_executable": cargo,
            "resolved_executable": cargo_path,
            "executable_resolution_status": "resolved" if cargo_path else "unresolved",
            "version_probe": cargo_version,
        },
        "rustc": {
            "configured_executable": rustc_candidate,
            "resolved_executable": rustc_path,
            "selection_source": rustc_source,
            "selection_certainty": rustc_certainty,
            "wrapper": wrapper,
            "wrapper_source": wrapper_source,
            "workspace_wrapper": workspace_wrapper,
            "workspace_wrapper_source": workspace_wrapper_source,
            "version_probe": rustc_probe,
        },
        "toolchain": {
            "explicit_selector": selector,
            "RUSTUP_TOOLCHAIN": env.get("RUSTUP_TOOLCHAIN"),
            "rustup_resolved_executable": rustup_path,
            "active_toolchain_probe": rustup_probe,
            "toolchain_files": _toolchain_files(cwd),
        },
        "manifest": {
            "selected_manifest_path": str(selected_manifest) if selected_manifest else None,
            "selection_source": manifest_source,
            "candidate_workspace_root": str(candidate_workspace_root) if candidate_workspace_root else None,
            "lockfile_path": str(lockfile_path) if lockfile_path else None,
            "lockfile_status_before_probe": lock_status_before_probe,
            "lockfile_status_after_probe": lock_status_after_probe,
        },
        "target": {
            "host_target_from_rustc": host_target,
            "explicit_step_target": explicit,
            "CARGO_BUILD_TARGET": env_target,
            "cargo_config_targets": public_target_configs,
            "selected_build_target": selected_target,
        },
        "output": {"target_directory": target_directory, "build_directory": build_directory},
        "cargo_configuration": {
            "files": public_config_files,
            "effective_settings": effective_settings,
            "target_settings": public_target_configs,
            "target_dir_settings": public_target_dir_configs,
            "rustc_settings": public_rustc_configs,
            "wrapper_settings": public_wrapper_configs,
            "build_dir_settings": [
                dict(layer, key="build.build-dir") for layer in file_layers if "build.build-dir" in layer.get("settings", {})
            ] + [dict(item) for item in inline_layers if item.get("key") == "build.build-dir"],
            "cargo_home_search_path": str(cargo_home_path),
            "cargo_home_source": "CARGO_HOME" if env.get("CARGO_HOME") else "default_CARGO_HOME",
            "environment": environment_record,
            "include_support": include_support,
            "include_discoveries": include_discoveries,
            "include_issues": config_issues,
            "invocation_analysis": {
                "requested_subcommand": analysis.get("requested_subcommand"),
                "resolved_subcommand": analysis.get("resolved_subcommand"),
                "alias_chain": list(analysis.get("alias_chain") or []),
                "alias_resolution_status": analysis.get("alias_resolution_status"),
                "classification": analysis.get("classification"),
                "resolution_issues": [
                    {"code": issue.get("code", "cargo_invocation_unresolved")}
                    for issue in analysis.get("resolution_issues", [])
                ],
            },
        },
        "cargo_metadata_probe": metadata_probe,
        "cargo_metadata": metadata,
    }
    selected_target_path = Path(target_directory["path"]) if target_directory.get("path") else None
    unreadable = [item for item in config_files if item.get("effective", True) and item.get("status") in {"unreadable", "not_regular_file", "not_present_required"}]
    return step_record, selected_target_path, unreadable


def _path_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _same_file_state(left, right) -> bool:
    return _shared_same_file_state(left, right)


def _hash_regular_file(path: Path, directory_entry_stat, parent_fd=None, name=None) -> Tuple[Optional[str], int, bool]:
    """Compatibility adapter for the authoritative artifact_inventory hash."""
    digest, byte_count, status, issue = _shared_hash_regular_file(
        path, expected=directory_entry_stat, parent_fd=parent_fd, name=name,
    )
    if status == "unreadable":
        detail = issue or {}
        raise FileVerificationError(
            detail.get("cause", detail.get("code", "file_unreadable")), path,
            detail.get("error_type"), detail.get("errno"),
        )
    if status == "unstable":
        return (issue or {}).get("observed_sha256"), byte_count or 0, False
    return digest, byte_count or 0, True


def prepare_exclusions(
    root: Path,
    evidence_dir: Path,
    target_dirs: Iterable[Tuple[Path, str]],
    build_dirs: Iterable[Tuple[Path, str]] = (),
) -> List[dict]:
    root = root.resolve()
    requests = [(evidence_dir.resolve(), "evidence_directory", "configured evidence output")]
    requests.extend((path.resolve(), "cargo_target_directory", source) for path, source in target_dirs)
    requests.extend((path.resolve(), "cargo_build_directory", source) for path, source in build_dirs)
    exclusions = []
    seen = set()
    for path, reason, source in requests:
        key = (os.path.normcase(str(path)), reason)
        if key in seen:
            continue
        seen.add(key)
        if _path_within(path, root):
            rel = path.relative_to(root).as_posix() or "."
            exclusions.append({"path": rel, "reason": reason, "source": source, "applied": rel != "."})
        else:
            exclusions.append({"path": str(path), "reason": reason, "source": source, "applied": False, "status": "outside_inventory_root"})
    exclusions.sort(key=lambda item: (item["path"].casefold(), item["reason"], item["source"]))
    return exclusions


def inventory_workspace(root: Path, exclusions: List[dict]) -> dict:
    root = root.absolute()
    exclusion_paths = [
        PurePosixPath(item["path"]).as_posix().rstrip("/")
        for item in exclusions if item.get("applied")
    ]
    entries: List[dict] = []
    issues: List[dict] = []

    def excluded(path: Path) -> bool:
        relative = path.relative_to(root).as_posix().casefold()
        return any(
            relative == omit.casefold()
            or omit == "."
            or relative.startswith(omit.casefold() + "/")
            for omit in exclusion_paths
        )

    def walk(directory: Path, expected=None, parent_fd=None, name=None, directory_record=None) -> None:
        try:
            listing = _shared_secure_directory(directory, expected, parent_fd, name)
            with listing as (directory_fd, children):
                walk_children(directory, directory_fd, children)
        except OSError as exc:
            rel = directory.relative_to(root).as_posix() if directory != root else "."
            status = "unstable" if getattr(exc, "code", "").startswith("directory_changed") else "unreadable"
            if directory_record is None:
                entries.append({"relative_path": rel, "file_type": "directory", "size_bytes": None,
                                "mode_bits": None, "sha256": None, "inclusion_status": status})
            else:
                directory_record.update({"inclusion_status": status, "size_bytes": None})
            issues.append({
                "code": "workspace_directory_changed_during_inventory" if status == "unstable"
                        else "workspace_directory_unreadable",
                "path": rel, "error_type": getattr(exc, "error_type", type(exc).__name__),
            })

    def walk_children(directory: Path, directory_fd: int, children: List[str]) -> None:
        for child_name in children:
            path = directory / child_name
            if excluded(path):
                continue
            rel = path.relative_to(root).as_posix()
            try:
                before = _shared_stat_child(path, directory_fd, child_name)
            except OSError as exc:
                entries.append({"relative_path": rel, "file_type": "unknown", "size_bytes": None,
                                "mode_bits": None, "sha256": None, "inclusion_status": "unreadable"})
                issues.append({
                    "code": "workspace_entry_unreadable", "path": rel,
                    "error_type": getattr(exc, "error_type", type(exc).__name__),
                })
                continue
            mode = before.st_mode & 0o7777
            if _shared_is_link_entry(path, before):
                try:
                    target = _shared_read_link(path, directory_fd, child_name, before)
                    resolved_target = (path.parent / target).resolve()
                    external = not _path_within(resolved_target, root.resolve())
                    entries.append({"relative_path": rel, "file_type": "symlink", "size_bytes": len(os.fsencode(target)),
                                    "mode_bits": mode, "sha256": None, "link_target": target,
                                    "target_scope": "external_not_inventoried" if external else "workspace",
                                    "inclusion_status": "included"})
                    if external:
                        issues.append({"code": "external_symlink_target_not_inventoried", "path": rel})
                except OSError as exc:
                    entries.append({"relative_path": rel, "file_type": "symlink", "size_bytes": None,
                                    "mode_bits": mode, "sha256": None, "inclusion_status": "unreadable"})
                    issues.append({"code": "workspace_symlink_unreadable", "path": rel,
                                   "error_type": getattr(exc, "error_type", type(exc).__name__)})
                continue
            if stat.S_ISDIR(before.st_mode):
                record = {"relative_path": rel, "file_type": "directory", "size_bytes": 0,
                          "mode_bits": mode, "sha256": None, "inclusion_status": "included"}
                entries.append(record)
                walk(path, before, directory_fd, child_name, record)
            elif stat.S_ISREG(before.st_mode):
                try:
                    content_digest, byte_count, stable = _hash_regular_file(path, before, directory_fd, child_name)
                    status = "included" if stable else "unstable"
                    entries.append({"relative_path": rel, "file_type": "file", "size_bytes": byte_count,
                                    "mode_bits": mode, "sha256": content_digest if stable else None,
                                    "observed_sha256": content_digest if not stable else None,
                                    "inclusion_status": status})
                    if not stable:
                        issues.append({"code": "workspace_file_changed_during_inventory", "path": rel,
                                       "cause": "file_identity_or_content_changed"})
                except OSError as exc:
                    entries.append({"relative_path": rel, "file_type": "file", "size_bytes": before.st_size,
                                    "mode_bits": mode, "sha256": None, "inclusion_status": "unreadable"})
                    issues.append({"code": "workspace_file_unreadable", "path": rel,
                                   "error_type": getattr(exc, "error_type", type(exc).__name__)})
            else:
                entries.append({"relative_path": rel, "file_type": "non_regular", "size_bytes": before.st_size,
                                "mode_bits": mode, "sha256": None, "special_type": stat.filemode(before.st_mode),
                                "inclusion_status": "unsupported_non_regular"})
                issues.append({"code": "workspace_non_regular_file", "path": rel})

    walk(root)
    entries.sort(key=lambda item: (item["relative_path"].casefold(), item["relative_path"]))
    payload = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "policy": "configured-workspace-content; hidden, modified, and untracked files included; symlinks recorded but never followed",
        "exclusions": exclusions,
        "entries": entries,
    }
    digest = sha256_bytes(canonical_json_bytes(payload))
    return {**payload, "digest": "sha256:" + digest, "issues": issues}


def diff_inventories(before: dict, after: dict) -> dict:
    old = {item["relative_path"]: item for item in before["entries"]}
    new = {item["relative_path"]: item for item in after["entries"]}
    changes = []
    counts = {name: 0 for name in ("created", "deleted", "modified", "unchanged", "unstable", "unreadable")}
    for path in sorted(set(old) | set(new), key=lambda value: (value.casefold(), value)):
        left, right = old.get(path), new.get(path)
        statuses = {item.get("inclusion_status") for item in (left, right) if item}
        if "unstable" in statuses:
            status = "unstable"
        elif "unreadable" in statuses:
            status = "unreadable"
        elif left is None:
            status = "created"
        elif right is None:
            status = "deleted"
        elif left == right:
            status = "unchanged"
        else:
            status = "modified"
        counts[status] += 1
        changes.append({"relative_path": path, "status": status})
    return {"counts": counts, "entries": changes}


def file_fingerprint(root: Path, relative_path: str, inventory: dict) -> dict:
    item = next((entry for entry in inventory["entries"] if entry["relative_path"] == relative_path), None)
    if item and item.get("inclusion_status") == "included" and item.get("file_type") == "file":
        return {"status": "present", "size_bytes": item["size_bytes"], "sha256": item["sha256"]}
    if relative_path == "Cargo.lock" and item is None:
        return {"status": "not_present", "size_bytes": None, "sha256": None}
    if item:
        return {"status": item.get("inclusion_status", "unavailable"), "size_bytes": item.get("size_bytes"), "sha256": item.get("sha256")}
    return {"status": "not_present", "size_bytes": None, "sha256": None}


def manifest_file_fingerprints(root: Path, before: Optional[dict], after: Optional[dict]) -> dict:
    result = {}
    root = root.resolve()
    for name in ("Cargo.toml", "Cargo.lock"):
        path = root / name
        before_value = file_fingerprint(root, name, before) if before else {"status": "unavailable"}
        after_value = file_fingerprint(root, name, after) if after else {"status": "unavailable"}
        result[name] = {"path": str(path), "before": before_value, "after": after_value}
    return result


def _fingerprint_workspace_path(path: Path, root: Path) -> dict:
    """Safely fingerprint a workspace-relative path without following parent links."""
    relative = path.relative_to(root)
    components = relative.parts
    if not components:
        return {"status": "not_regular_file", "size_bytes": None, "sha256": None}

    def walk(directory: Path, index: int, expected=None, parent_fd=None, name=None):
        try:
            with _shared_secure_directory(directory, expected, parent_fd, name) as (directory_fd, _names):
                child_name = components[index]
                child_path = directory / child_name
                try:
                    info = _shared_stat_child(child_path, directory_fd, child_name)
                except FileNotFoundError:
                    return {"status": "not_present", "size_bytes": None, "sha256": None}
                if index < len(components) - 1:
                    if not stat.S_ISDIR(info.st_mode) or _shared_is_link_entry(child_path, info):
                        return {"status": "not_regular_file", "size_bytes": None, "sha256": None}
                    return walk(child_path, index + 1, info, directory_fd, child_name)
                if not stat.S_ISREG(info.st_mode) or _shared_is_link_entry(child_path, info):
                    return {"status": "not_regular_file", "size_bytes": info.st_size, "sha256": None}
                digest, size, hash_status, issue = _shared_hash_regular_file(
                    child_path, expected=info, parent_fd=directory_fd, name=child_name,
                )
                return {
                    "status": "present" if hash_status == "complete" else hash_status,
                    "size_bytes": size if size is not None else info.st_size,
                    "sha256": digest if hash_status == "complete" else None,
                }
        except OSError as exc:
            code = getattr(exc, "code", "")
            return {
                "status": "unstable" if code.startswith("directory_changed") else "unreadable",
                "size_bytes": None, "sha256": None,
                "error_type": getattr(exc, "error_type", type(exc).__name__),
            }

    return walk(root, 0)


def _fingerprint_path(path_value: Optional[str], root: Path, inventory: Optional[dict]) -> dict:
    if not path_value:
        return {"status": "unresolved", "size_bytes": None, "sha256": None}
    root = root.absolute()
    path = Path(path_value)
    if not path.is_absolute():
        path = root / path
    path = Path(os.path.abspath(str(path)))
    lexical_root = Path(os.path.abspath(str(root)))
    if _path_within(path, lexical_root) and inventory is not None:
        relative = path.relative_to(lexical_root).as_posix()
        item = next((entry for entry in inventory["entries"] if entry["relative_path"] == relative), None)
        if item:
            status = item.get("inclusion_status", "unavailable")
            if item.get("file_type") != "file" and status == "included":
                status = "not_regular_file"
            return {
                "status": status,
                "size_bytes": item.get("size_bytes"),
                "sha256": item.get("sha256"),
            }
        # A workspace-lexical path missing from the observation must not fall
        # through and resolve a symlinked parent outside the inventory root.
        return {"status": "not_present", "size_bytes": None, "sha256": None}
    if _path_within(path, lexical_root):
        return _fingerprint_workspace_path(path, lexical_root)
    try:
        before = os.stat(str(path), follow_symlinks=False)
    except FileNotFoundError:
        return {"status": "not_present", "size_bytes": None, "sha256": None}
    except OSError as exc:
        return {"status": "unreadable", "size_bytes": None, "sha256": None, "error_type": type(exc).__name__}
    if not stat.S_ISREG(before.st_mode) or _shared_is_link_entry(path, before):
        return {"status": "not_regular_file", "size_bytes": before.st_size, "sha256": None}
    digest, size, status, issue = _shared_hash_regular_file(path, expected=before)
    if status == "unreadable":
        return {"status": "unreadable", "size_bytes": before.st_size, "sha256": None,
                "error_type": (issue or {}).get("error_type", "OSError")}
    return {
        "status": "present" if status == "complete" else "unstable",
        "size_bytes": size,
        "sha256": digest if status == "complete" else None,
    }


def step_manifest_fingerprints(
    root: Path,
    step_paths: dict,
    before_inventory: Optional[dict],
    after_inventory: Optional[dict],
    previous: Optional[dict] = None,
) -> dict:
    previous_steps = (previous or {}).get("steps", {})
    result = {}
    for step_id, paths in sorted(step_paths.items()):
        prior = previous_steps.get(step_id, {})
        current = {}
        for key, path_key in (("manifest", "selected_manifest_path"), ("lockfile", "lockfile_path")):
            path_value = paths.get(path_key)
            before_value = prior.get(key, {}).get("before")
            if before_value is None:
                before_value = _fingerprint_path(path_value, root, before_inventory)
            after_value = _fingerprint_path(path_value, root, after_inventory) if after_inventory is not None else {
                "status": "unavailable", "size_bytes": None, "sha256": None,
            }
            current[key] = {
                "path": path_value,
                "before": before_value,
                "after": after_value,
            }
        result[step_id] = current
    return result


def interrupted_step_provenance(
    step: dict,
    cargo: str,
    step_cwd: Path,
    env: dict,
    preflight_context: Optional[dict] = None,
    signal_number: Optional[int] = None,
    signal_name: Optional[str] = None,
    not_preflighted: bool = False,
    preflight_completed: bool = False,
) -> dict:
    """Build the ordinary Provenance shape without launching any more probes."""
    context = preflight_context or {}
    analysis = context.get("analysis") or {}
    probe = context.get("cargo_version_probe")
    interrupted = not not_preflighted and not preflight_completed and isinstance(probe, dict)
    cargo_probe = parse_cargo_version_probe(probe) if interrupted or preflight_completed else {
        "name": "cargo_version", "status": "not_run_interrupted", "launch_status": "not_started",
        "signal_number": signal_number, "signal_name": signal_name,
    }
    state = (
        "not_run_interrupted" if not_preflighted else
        "preflight_completed_execution_not_run" if preflight_completed else "interrupted"
    )
    cwd = analysis.get("_cargo_cwd") or step_cwd
    config_context = analysis.get("_cargo_configuration") or {}

    def public(item: dict) -> dict:
        return {key: value for key, value in item.items() if not key.startswith("_")}

    config_files = [public(item) for item in config_context.get("records", []) if isinstance(item, dict)]
    include_discoveries = [
        public(item) for item in config_context.get("include_discoveries", []) if isinstance(item, dict)
    ]
    base_parse = analysis.get("_base_parse") or {}
    requested_subcommand = analysis.get("requested_subcommand") or base_parse.get("requested_subcommand")
    selector = analysis.get("toolchain_selector") or base_parse.get("toolchain_selector")
    partial_analysis = {
        "requested_subcommand": requested_subcommand,
        "resolved_subcommand": analysis.get("resolved_subcommand"),
        "alias_chain": list(analysis.get("alias_chain") or []),
        "alias_resolution_status": analysis.get("alias_resolution_status", "not_completed_interrupted"),
        "classification": analysis.get("classification", "not_completed_interrupted"),
        "resolution_issues": [
            {"code": item.get("code", "cargo_invocation_unresolved")}
            for item in analysis.get("resolution_issues", []) if isinstance(item, dict)
        ],
        "preflight_status": state,
    }
    not_run_probe = lambda name: {
        "name": name, "status": "not_run_interrupted", "launch_status": "not_started",
        "signal_number": signal_number, "signal_name": signal_name,
    }
    return {
        "status": state,
        "preflight_status": state,
        "signal_number": signal_number,
        "signal_name": signal_name,
        "cwd": str(cwd),
        "configured_step_cwd": str(step_cwd),
        "cargo": {
            "configured_executable": cargo,
            "resolved_executable": None,
            "executable_resolution_status": "not_resolved_interrupted",
            "version_probe": cargo_probe,
        },
        "rustc": {
            "configured_executable": None,
            "resolved_executable": None,
            "selection_source": None,
            "selection_certainty": "not_resolved_interrupted",
            "wrapper": None,
            "wrapper_source": None,
            "workspace_wrapper": None,
            "workspace_wrapper_source": None,
            "version_probe": not_run_probe("rustc_version"),
        },
        "toolchain": {
            "explicit_selector": selector,
            "RUSTUP_TOOLCHAIN": env.get("RUSTUP_TOOLCHAIN"),
            "rustup_resolved_executable": None,
            "active_toolchain_probe": not_run_probe("rustup_active_toolchain"),
            "toolchain_files": [],
        },
        "manifest": {
            "selected_manifest_path": None,
            "selection_source": "not_resolved_interrupted",
            "candidate_workspace_root": None,
            "lockfile_path": None,
            "lockfile_status_before_probe": "not_observed_interrupted",
            "lockfile_status_after_probe": "not_observed_interrupted",
        },
        "target": {
            "host_target_from_rustc": None,
            "explicit_step_target": None,
            "CARGO_BUILD_TARGET": env.get("CARGO_BUILD_TARGET"),
            "cargo_config_targets": [],
            "selected_build_target": {"value": None, "source": "not_observed_interrupted", "status": "not_run_interrupted"},
        },
        "output": {
            "target_directory": {"path": None, "source": "not_observed_interrupted", "status": "not_run_interrupted"},
            "build_directory": {"path": None, "source": "not_observed_interrupted", "status": "not_run_interrupted"},
        },
        "cargo_configuration": {
            "files": config_files,
            "effective_settings": {},
            "target_settings": [],
            "target_dir_settings": [],
            "rustc_settings": [],
            "wrapper_settings": [],
            "build_dir_settings": [],
            "cargo_home_search_path": env.get("CARGO_HOME", str(Path.home() / ".cargo")),
            "cargo_home_source": "CARGO_HOME" if env.get("CARGO_HOME") else "default_CARGO_HOME",
            "environment": {"values": {}, "redaction_policy": "not_collected_interrupted", "PATH": None},
            "include_support": {"status": "not_resolved_interrupted"},
            "include_discoveries": include_discoveries,
            "include_issues": [{"code": "cargo_configuration_preflight_interrupted"}],
            "invocation_analysis": partial_analysis,
            "refresh_status": "not_run_interrupted",
        },
        "cargo_metadata_probe": {
            **not_run_probe("cargo_metadata"),
            "extraction_status": "not_run_interrupted",
            "lockfile_observation": {
                "path": None,
                "before_probe": "not_observed_interrupted",
                "after_probe": "not_observed_interrupted",
                "status": "not_observed_interrupted",
            },
        },
        "cargo_metadata": None,
    }


def _step_provenance_structure_valid(step: dict) -> bool:
    """Check required normal/narrow interrupted record containers before indexing."""
    if not isinstance(step, dict):
        return False
    if not all(isinstance(step.get(key), dict) for key in (
        "cargo", "rustc", "manifest", "target", "output",
        "cargo_configuration", "cargo_metadata_probe",
    )):
        return False
    cargo = step["cargo"]
    rustc = step["rustc"]
    target = step["target"]
    configuration = step["cargo_configuration"]
    if not isinstance(cargo.get("version_probe"), dict) or not isinstance(rustc.get("version_probe"), dict):
        return False
    if not isinstance(step["cargo_metadata_probe"], dict):
        return False
    if not isinstance(configuration.get("effective_settings"), dict):
        return False
    if not isinstance(configuration.get("files"), list) or not all(isinstance(item, dict) for item in configuration["files"]):
        return False
    if not isinstance(configuration.get("include_issues"), list) or not all(isinstance(item, dict) for item in configuration["include_issues"]):
        return False
    if not isinstance(target.get("selected_build_target"), dict):
        return False
    output = step.get("output")
    if any(key in output and not isinstance(output[key], dict) for key in ("target_directory", "build_directory")):
        return False
    metadata = step.get("cargo_metadata")
    return metadata is None or isinstance(metadata, dict)


def complete_provenance_status(provenance: dict) -> Tuple[str, List[dict]]:
    if not isinstance(provenance, dict):
        return "incomplete", [{"code": "provenance_structure_invalid"}]
    raw_issues = provenance.get("issues", [])
    issues = [dict(item) for item in raw_issues if isinstance(item, dict)] if isinstance(raw_issues, list) else []
    if not isinstance(raw_issues, list):
        issues.append({"code": "provenance_issues_structure_invalid"})
    agent = provenance.get("agent")
    if not isinstance(agent, dict):
        issues.append({"code": "provenance_agent_structure_invalid"})
        runtime_sources = []
    else:
        runtime_sources = agent.get("runtime_source_files", [])
        if not isinstance(runtime_sources, list):
            issues.append({"code": "runtime_source_files_structure_invalid"})
            runtime_sources = []
    for source in runtime_sources:
        if not isinstance(source, dict):
            issues.append({"code": "runtime_source_structure_invalid"})
        elif source.get("status") != "hashed":
            issue = {"code": "runtime_source_unavailable"}
            if isinstance(source.get("path"), str):
                issue["path"] = source["path"]
            issues.append(issue)
    steps = provenance.get("steps", {})
    if not isinstance(steps, dict):
        issues.append({"code": "provenance_steps_structure_invalid"})
        return "incomplete", issues
    for step_id, step in steps.items():
        if not isinstance(step_id, str) or not _step_provenance_structure_valid(step):
            issues.append({"code": "step_provenance_structure_invalid", "step": str(step_id)})
            continue
        preflight_status = step.get("preflight_status")
        if preflight_status in {"interrupted", "not_run_interrupted", "preflight_completed_execution_not_run"}:
            cargo_status = step["cargo"]["version_probe"].get("status")
            expected = (
                "interrupted" if preflight_status == "interrupted" else
                "succeeded" if preflight_status == "preflight_completed_execution_not_run" else
                "not_run_interrupted"
            )
            if cargo_status != expected:
                issues.append({"code": "step_provenance_structure_invalid", "step": step_id})
            if preflight_status == "interrupted":
                issues.append({
                    "code": "cargo_version_probe_interrupted", "step": step_id,
                    "signal_number": step.get("signal_number"), "signal_name": step.get("signal_name"),
                })
                issues.append({"code": "invocation_preflight_interrupted", "step": step_id})
                if step["cargo_metadata_probe"].get("status") == "succeeded":
                    issues.append({"code": "interrupted_preflight_claims_metadata_success", "step": step_id})
            elif preflight_status == "not_run_interrupted":
                issues.append({"code": "invocation_preflight_not_run_interrupted", "step": step_id})
                if step["cargo_metadata_probe"].get("status") == "succeeded":
                    issues.append({"code": "not_run_preflight_claims_metadata_success", "step": step_id})
            else:
                issues.append({"code": "execution_provenance_not_run_after_preflight", "step": step_id})
                if step["cargo_metadata_probe"].get("status") == "succeeded":
                    issues.append({"code": "not_run_execution_claims_metadata_success", "step": step_id})
            continue

        for key, setting in step["cargo_configuration"]["effective_settings"].items():
            if not isinstance(setting, dict):
                issues.append({"code": "step_provenance_structure_invalid", "step": step_id})
                continue
            if setting.get("status") == "unresolved":
                issues.append({"code": "cargo_effective_setting_unresolved", "step": step_id, "key": key})
        cargo_probe = step["cargo"]["version_probe"]
        rustc_probe = step["rustc"]["version_probe"]
        metadata_probe = step["cargo_metadata_probe"]
        if cargo_probe.get("status") != "succeeded":
            issues.append({"code": "cargo_version_unavailable", "step": step_id, "status": cargo_probe.get("status")})
        if rustc_probe.get("status") != "succeeded":
            issues.append({"code": "rustc_selection_unresolved", "step": step_id, "status": rustc_probe.get("status")})
        if step["rustc"].get("selection_certainty") in {"inferred_with_wrapper", "unresolved_with_wrapper"}:
            issues.append({"code": "rustc_wrapper_selection_not_fully_resolved", "step": step_id})
        if metadata_probe.get("status") != "succeeded":
            issues.append({"code": "cargo_metadata_unavailable", "step": step_id, "status": metadata_probe.get("status")})
        elif metadata_probe.get("extraction_status") != "succeeded":
            issues.append({"code": "cargo_metadata_extraction_unavailable", "step": step_id})
        elif not (step.get("cargo_metadata") or {}).get("workspace_root"):
            issues.append({"code": "cargo_workspace_root_unavailable", "step": step_id})
        elif not (step.get("cargo_metadata") or {}).get("target_directory"):
            issues.append({"code": "cargo_target_directory_unavailable", "step": step_id})
        lock_observation = metadata_probe.get("lockfile_observation") or {}
        if not isinstance(lock_observation, dict):
            issues.append({"code": "step_provenance_structure_invalid", "step": step_id})
            lock_observation = {}
        if lock_observation.get("status") == "unexpectedly_created":
            issues.append({"code": "cargo_metadata_probe_changed_lockfile", "step": step_id})
        if lock_observation.get("before_probe") == "not_present" and metadata_probe.get("status") != "succeeded":
            issues.append({"code": "cargo_lockfile_missing_metadata_unavailable", "step": step_id})
        target_directory = step["output"].get("target_directory") or {}
        if target_directory.get("status") == "unresolved":
            issues.append({"code": "cargo_target_directory_unresolved", "step": step_id})
        build_directory = step["output"].get("build_directory") or {}
        if build_directory.get("status") == "unresolved":
            issues.append({"code": "cargo_build_directory_unresolved", "step": step_id})
        manifest = step["manifest"]
        if not manifest.get("selected_manifest_path"):
            issues.append({"code": "cargo_manifest_path_unresolved", "step": step_id})
        for item in step["cargo_configuration"]["files"]:
            if item.get("effective", True) and item.get("status") in {"unreadable", "not_regular_file", "not_present_required", "not_present", "sensitive_file_not_fingerprinted"}:
                issues.append({"code": "cargo_configuration_file_unavailable", "step": step_id, "path": item.get("path")})
        for issue in step["cargo_configuration"]["include_issues"]:
            issues.append(dict(issue, step=step_id))
        if step["target"]["selected_build_target"].get("status") == "unresolved":
            issues.append({"code": "cargo_target_unresolved", "step": step_id})
    return ("incomplete" if issues else "complete"), issues

