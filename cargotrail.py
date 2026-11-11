#!/usr/bin/env python3
"""Config-driven Cargo build evidence runner.

Python 3.8+. The configuration is the sole source of the Cargo pipeline:
commands and arguments are passed exactly as configured (shell=False).
This program is an evidence collector, not a sandbox.
"""

# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from __future__ import annotations

import argparse
import codecs
import copy
import datetime as dt
import hashlib
import io
import json
import logging
import math
import os
import re
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
import uuid
from collections import Counter
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Dict, Iterable, List, Optional, Tuple

from process_supervision import CancellationContext, run_supervised_process
from artifact_inventory import (
    INVENTORY_NAME as ARTIFACT_INVENTORY_NAME,
    SCHEMA_VERSION as ARTIFACT_INVENTORY_SCHEMA_VERSION,
    build_inventory as build_artifact_inventory,
    calculate_inventory_digest,
    create_exclusive_file,
    is_link_entry,
    is_junction_entry,
    normalize_link_target,
    atomic_replace,
    open_file_no_follow,
    open_regular_writer,
    read_regular_bytes,
    read_link,
    secure_directory,
    sha256_file as sha256_regular_file,
    stat_child,
    same_file_object,
    sync_evidence_tree,
    sync_fd,
    sync_file,
    sync_parent_directory,
)
from provenance import (
    DuplicateJSONKeyError,
    INVENTORY_SCHEMA_VERSION,
    PROVENANCE_SCHEMA_VERSION,
    analyze_cargo_invocation,
    canonical_json_bytes,
    collect_step_provenance,
    complete_provenance_status,
    diff_inventories,
    inventory_workspace,
    interrupted_step_provenance,
    manifest_file_fingerprints,
    prepare_exclusions,
    runtime_provenance,
    redact_args,
    refresh_step_cargo_configuration,
    parse_cargo_version_probe,
    run_probe,
    sha256_bytes as provenance_sha256_bytes,
    strict_json_loads,
    step_manifest_fingerprints,
)

VERSION = "1.5.1"
SCHEMA_VERSION = 1
PROFILE_DEFINITION_SCHEMA_VERSION = 1
STEP_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
PROFILE_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
FMT_DIFF_RE = re.compile(r"^Diff in (.*?)(?::\d+)?:\s*$")
TEST_CASE_RE = re.compile(
    r"^\s*test\s+(.+?)\s+\.\.\.\s+(ok|FAILED|ignored|measured|filtered out)"
    r"(?:\s+\((.*?)\))?\s*$", re.IGNORECASE
)
TEST_SUITE_RE = re.compile(
    r"^\s*test result:\s+(ok|FAILED)\.\s+"
    r"(\d+)\s+passed;\s+(\d+)\s+failed;\s+(\d+)\s+ignored;\s+"
    r"(\d+)\s+measured;\s+(\d+)\s+filtered out;\s+"
    r"finished in (\d+(?:\.\d+)?|\.\d+)s\s*$",
    re.IGNORECASE,
)
TEST_SUITE_PREFIX_RE = re.compile(r"^\s*test result:", re.IGNORECASE)
TOP_KEYS = {"schema_version", "profile", "workspace_root", "execution", "steps"}
PROFILE_KEYS = {"id", "version", "description"}
EXECUTION_KEYS = {
    "cargo_executable", "continue_on_error", "default_timeout_seconds",
    "termination_grace_seconds", "environment", "unset_environment",
}
STEP_KEYS = {
    "id", "args", "enabled", "parser", "cwd", "timeout_seconds",
    "environment", "unset_environment", "redact_arg_indexes", "evidence_requirements",
}
EVIDENCE_REQUIREMENT_KEYS = {
    "require_valid_json_events", "require_build_finished", "require_test_summary", "allow_zero_tests",
}
PARSERS = {"text", "cargo-json", "cargo-json+libtest"}
BUILD_PRODUCING_SUBCOMMANDS = {
    "bench", "build", "check", "clippy", "doc", "fix", "install", "package",
    "publish", "run", "rustc", "rustdoc", "test",
}


def default_evidence_requirements(parser_name: str) -> dict:
    if parser_name == "cargo-json+libtest":
        return {
            "require_valid_json_events": True,
            "require_build_finished": True,
            "require_test_summary": True,
            "allow_zero_tests": False,
        }
    if parser_name == "cargo-json":
        return {
            "require_valid_json_events": True,
            "require_build_finished": True,
            "require_test_summary": False,
            "allow_zero_tests": False,
        }
    return {
        "require_valid_json_events": False,
        "require_build_finished": False,
        "require_test_summary": False,
        "allow_zero_tests": False,
    }


class ConfigError(ValueError):
    """Invalid pipeline configuration or workspace layout."""


LOGGER = logging.getLogger("cargotrail")
LOGGER.addHandler(logging.NullHandler())
CONSOLE_LOG_LEVEL = "INFO"


def configure_logging(console_level: str = "INFO") -> None:
    """Reset the agent logger and configure human-readable console logging.

    The console receives INFO and above by default. A separate DEBUG-level
    Evidence-file stream handler is attached once the evidence directory exists.
    """
    global CONSOLE_LOG_LEVEL
    CONSOLE_LOG_LEVEL = console_level.upper()
    errors = []
    for handler in list(LOGGER.handlers):
        LOGGER.removeHandler(handler)
        try:
            handler.flush()
        except Exception as exc:
            if getattr(handler, "_evidence_log_path", None):
                errors.append(exc)
        if getattr(handler, "_evidence_log_path", None):
            try:
                sync_fd(handler.stream.fileno())
            except Exception as exc:
                errors.append(exc)
        try:
            handler.close()
        except Exception as exc:
            if getattr(handler, "_evidence_log_path", None):
                errors.append(exc)
        if getattr(handler, "_evidence_log_path", None):
            try:
                handler.stream.close()
            except Exception as exc:
                errors.append(exc)
    if errors:
        raise OSError("runner.log synchronization failed: {}".format(type(errors[0]).__name__))
    LOGGER.setLevel(logging.DEBUG)
    LOGGER.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03dZ %(levelname)-8s [pid=%(process)d] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    formatter.converter = time.gmtime
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(getattr(logging, CONSOLE_LOG_LEVEL))
    console.setFormatter(formatter)
    LOGGER.addHandler(console)


def attach_file_logging(path: Path) -> None:
    """Attach the persistent DEBUG-level Python-agent logfile."""
    resolved = Path(os.path.abspath(str(path)))
    for handler in LOGGER.handlers:
        if getattr(handler, "_evidence_log_path", None) == str(resolved):
            return
    binary_stream = open_regular_writer(resolved, append=True)
    text_stream = io.TextIOWrapper(binary_stream, encoding="utf-8", newline="")
    file_handler = logging.StreamHandler(text_stream)
    file_handler._evidence_log_path = str(resolved)
    file_handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03dZ %(levelname)-8s [pid=%(process)d] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    formatter.converter = time.gmtime
    file_handler.setFormatter(formatter)
    LOGGER.addHandler(file_handler)
    LOGGER.info("Python agent logfile opened: %s", resolved.name)


def close_logging() -> None:
    """Flush and close run-specific handlers; safe for repeated main() calls."""
    errors = []
    for handler in list(LOGGER.handlers):
        LOGGER.removeHandler(handler)
        try:
            handler.flush()
        except Exception as exc:
            if getattr(handler, "_evidence_log_path", None):
                errors.append(exc)
        if getattr(handler, "_evidence_log_path", None):
            try:
                sync_fd(handler.stream.fileno())
            except Exception as exc:
                errors.append(exc)
        try:
            handler.close()
        except Exception as exc:
            if getattr(handler, "_evidence_log_path", None):
                errors.append(exc)
        if getattr(handler, "_evidence_log_path", None):
            try:
                handler.stream.close()
            except Exception as exc:
                errors.append(exc)
    LOGGER.addHandler(logging.NullHandler())
    if errors:
        raise OSError("runner.log synchronization failed: {}".format(type(errors[0]).__name__))


def close_file_logging() -> None:
    """Flush and remove evidence-file handlers while keeping console logging."""
    errors = []
    for handler in list(LOGGER.handlers):
        if getattr(handler, "_evidence_log_path", None):
            LOGGER.removeHandler(handler)
            try:
                handler.flush()
            except Exception as exc:
                errors.append(exc)
            try:
                sync_fd(handler.stream.fileno())
            except Exception as exc:
                errors.append(exc)
            try:
                handler.close()
            except Exception as exc:
                errors.append(exc)
            try:
                handler.stream.close()
            except Exception as exc:
                errors.append(exc)
    if errors:
        raise OSError("runner.log synchronization failed: {}".format(type(errors[0]).__name__))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _lstat_optional(path: Path):
    try:
        info = os.stat(str(path), follow_symlinks=False)
    except FileNotFoundError:
        return None
    if is_link_entry(path, info) or not stat.S_ISREG(info.st_mode):
        raise OSError("{} is not a regular file".format(path.name))
    return info


def _entry_exists(path: Path) -> bool:
    try:
        os.stat(str(path), follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def write_json(path: Path, value: Any) -> None:
    data = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with open_regular_writer(path) as stream:
        stream.write(data)
        stream.flush()
        sync_fd(stream.fileno())


def write_json_atomic(path: Path, value: Any) -> None:
    # Keep the temporary sibling on the same filesystem; never use system temp dirs.
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".writing")
    try:
        write_json(temporary, value)
        atomic_replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except FileNotFoundError:
            pass


def write_jsonl(path: Path, records: Iterable[dict]) -> None:
    with open_regular_writer(path) as stream:
        for record in records:
            stream.write(
                json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
                + b"\n"
            )
        stream.flush()
        sync_fd(stream.fileno())


def write_jsonl_atomic(path: Path, records: Iterable[dict]) -> None:
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".writing")
    try:
        write_jsonl(temporary, records)
        atomic_replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except FileNotFoundError:
            pass


def append_jsonl(path: Path, value: dict) -> None:
    with open_regular_writer(path, append=True) as stream:
        stream.write(
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            + b"\n"
        )
        stream.flush()
        sync_fd(stream.fileno())


def decode_log(source: Path, destination: Path) -> None:
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    source_fd = open_file_no_follow(source, os.O_RDONLY)
    with os.fdopen(source_fd, "rb") as src, io.TextIOWrapper(
            open_regular_writer(destination), encoding="utf-8", newline="") as dst:
        while True:
            chunk = src.read(1024 * 1024)
            if not chunk:
                break
            dst.write(decoder.decode(chunk))
        dst.write(decoder.decode(b"", final=True))
        dst.flush()
        sync_fd(dst.buffer.fileno())


def validate_keys(value: dict, allowed: set, label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ConfigError("{}: unknown keys: {}".format(label, ", ".join(sorted(unknown))))


def validate_timeout(value: Any, label: str, allow_zero: bool = False) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError("{} must be a number or null".format(label))
    if not math.isfinite(float(value)):
        raise ConfigError("{} must be finite".format(label))
    if value < 0 or (value == 0 and not allow_zero):
        raise ConfigError("{} must be {}".format(label, "non-negative" if allow_zero else "positive"))
    return float(value)


def validate_environment(value: Any, label: str) -> Dict[str, str]:
    if not isinstance(value, dict):
        raise ConfigError("{} must be an object".format(label))
    result = {}
    for key, item in value.items():
        if not isinstance(key, str) or not ENV_NAME_RE.fullmatch(key):
            raise ConfigError("{} contains an invalid environment variable name".format(label))
        if not isinstance(item, str) or "\x00" in item:
            raise ConfigError("{}[{}] must be a NUL-free string".format(label, key))
        result[key] = item
    return result


def validate_unset_environment(value: Any, label: str) -> List[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError("{} must be an array of environment variable names".format(label))
    for item in value:
        if not ENV_NAME_RE.fullmatch(item):
            raise ConfigError("{} contains an invalid environment variable name".format(label))
    if len(set(value)) != len(value):
        raise ConfigError("{} contains duplicate names".format(label))
    return list(value)


def cargo_subcommand(args: List[str]) -> Optional[str]:
    """Compatibility wrapper over the authoritative invocation analysis."""
    analysis = analyze_cargo_invocation(args, Path.cwd(), os.environ, build_producing_subcommands=BUILD_PRODUCING_SUBCOMMANDS)
    return analysis.get("requested_subcommand")


def cargo_message_format(args: List[str]) -> Optional[str]:
    """Compatibility wrapper over the authoritative invocation analysis."""
    analysis = analyze_cargo_invocation(args, Path.cwd(), os.environ, build_producing_subcommands=BUILD_PRODUCING_SUBCOMMANDS)
    if any(issue.get("code") == "cargo_option_value_missing" for issue in analysis.get("resolution_issues", [])):
        raise ConfigError("cargo_option_value_missing")
    return analysis.get("message_format")


def load_config(config_path: Path) -> Tuple[dict, bytes, str]:
    try:
        raw = config_path.read_bytes()
    except OSError as exc:
        raise ConfigError("Cannot read config: {}".format(exc))
    try:
        source = strict_json_loads(raw.decode("utf-8-sig"))
    except DuplicateJSONKeyError:
        raise ConfigError("Duplicate key in JSON configuration") from None
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError("Invalid UTF-8 JSON configuration: {}".format(exc))
    if not isinstance(source, dict):
        raise ConfigError("Configuration root must be an object")
    validate_keys(source, TOP_KEYS, "config")

    version = source.get("schema_version")
    if isinstance(version, bool) or not isinstance(version, int) or version != SCHEMA_VERSION:
        raise ConfigError("schema_version must be integer {}".format(SCHEMA_VERSION))
    profile = None
    if "profile" in source:
        raw_profile = source["profile"]
        if not isinstance(raw_profile, dict):
            raise ConfigError("profile must be an object")
        validate_keys(raw_profile, PROFILE_KEYS, "profile")
        profile_id = raw_profile.get("id")
        if not isinstance(profile_id, str) or not PROFILE_ID_RE.fullmatch(profile_id):
            raise ConfigError("profile.id must match ^[a-z][a-z0-9._-]{0,63}$")
        profile_version = raw_profile.get("version")
        if isinstance(profile_version, bool) or not isinstance(profile_version, int) or profile_version <= 0:
            raise ConfigError("profile.version must be a positive integer")
        profile = {"id": profile_id, "version": profile_version}
        if "description" in raw_profile:
            description = raw_profile["description"]
            if not isinstance(description, str) or len(description) > 512 or "\x00" in description:
                raise ConfigError("profile.description must be a NUL-free string of at most 512 characters")
            profile["description"] = description
    workspace_root = source.get("workspace_root", ".")
    if not isinstance(workspace_root, str) or not workspace_root or "\x00" in workspace_root:
        raise ConfigError("workspace_root must be a non-empty NUL-free string")

    execution = source.get("execution", {})
    if not isinstance(execution, dict):
        raise ConfigError("execution must be an object")
    validate_keys(execution, EXECUTION_KEYS, "execution")
    cargo = execution.get("cargo_executable", "cargo")
    if not isinstance(cargo, str) or not cargo or "\x00" in cargo:
        raise ConfigError("cargo_executable must be a non-empty NUL-free string")
    continue_on_error = execution.get("continue_on_error", True)
    if not isinstance(continue_on_error, bool):
        raise ConfigError("continue_on_error must be boolean")
    default_timeout = validate_timeout(execution.get("default_timeout_seconds"), "default_timeout_seconds")
    grace = validate_timeout(
        execution.get("termination_grace_seconds", 5),
        "termination_grace_seconds",
        allow_zero=True,
    )
    if grace is None:
        grace = 5.0
    global_env = validate_environment(execution.get("environment", {}), "execution.environment")
    global_unset = validate_unset_environment(
        execution.get("unset_environment", []), "execution.unset_environment"
    )
    if set(global_env).intersection(global_unset):
        raise ConfigError("execution.environment and execution.unset_environment must not contain the same names")

    raw_steps = source.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ConfigError("steps must be a non-empty array; no implicit pipeline exists")
    steps = []
    seen = set()
    for index, item in enumerate(raw_steps):
        label = "steps[{}]".format(index)
        if not isinstance(item, dict):
            raise ConfigError("{} must be an object".format(label))
        validate_keys(item, STEP_KEYS, label)
        step_id = item.get("id")
        if not isinstance(step_id, str) or not STEP_ID_RE.fullmatch(step_id):
            raise ConfigError("{}.id is invalid".format(label))
        if step_id in seen:
            raise ConfigError("Duplicate step id: {}".format(step_id))
        seen.add(step_id)

        args = item.get("args")
        if (
            not isinstance(args, list)
            or not args
            or any(not isinstance(arg, str) or "\x00" in arg for arg in args)
        ):
            raise ConfigError("{}.args must be a non-empty array of NUL-free strings".format(label))
        enabled = item.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ConfigError("{}.enabled must be boolean".format(label))
        parser_name = item.get("parser", "text")
        if not isinstance(parser_name, str) or parser_name not in PARSERS:
            raise ConfigError("{}.parser must be one of {}".format(label, ", ".join(sorted(PARSERS)))
        )
        raw_requirements = item.get("evidence_requirements", {})
        if not isinstance(raw_requirements, dict):
            raise ConfigError("{}.evidence_requirements must be an object".format(label))
        validate_keys(raw_requirements, EVIDENCE_REQUIREMENT_KEYS, label + ".evidence_requirements")
        for key, value in raw_requirements.items():
            if not isinstance(value, bool):
                raise ConfigError("{}.evidence_requirements.{} must be boolean".format(label, key))
        if parser_name == "text" and raw_requirements:
            raise ConfigError("{}.parser=text cannot have Cargo evidence requirements".format(label))
        defaults = default_evidence_requirements(parser_name)
        evidence_requirements = dict(defaults)
        evidence_requirements.update(raw_requirements)
        if evidence_requirements["require_test_summary"] and parser_name != "cargo-json+libtest":
            raise ConfigError("{}.evidence_requirements.require_test_summary requires parser=cargo-json+libtest".format(label))
        if "allow_zero_tests" in raw_requirements and not evidence_requirements["require_test_summary"]:
            raise ConfigError("{}.evidence_requirements.allow_zero_tests requires require_test_summary=true".format(label))
        if parser_name in ("cargo-json", "cargo-json+libtest"):
            if not evidence_requirements["require_valid_json_events"]:
                raise ConfigError(
                    "{}.evidence_requirements.require_valid_json_events must be true for Cargo JSON parsers".format(label)
                )

        cwd = item.get("cwd", ".")
        if not isinstance(cwd, str) or not cwd or "\x00" in cwd:
            raise ConfigError("{}.cwd must be a non-empty NUL-free relative path".format(label))
        win_cwd = PureWindowsPath(cwd)
        if Path(cwd).is_absolute() or win_cwd.is_absolute() or win_cwd.drive:
            raise ConfigError("{}.cwd must be relative to workspace_root".format(label))
        timeout = validate_timeout(item.get("timeout_seconds"), "{}.timeout_seconds".format(label))
        env = validate_environment(item.get("environment", {}), "{}.environment".format(label))
        unset_env = validate_unset_environment(
            item.get("unset_environment", []), "{}.unset_environment".format(label)
        )
        if set(env).intersection(unset_env):
            raise ConfigError("{}.environment and unset_environment must not contain the same names".format(label))
        redact = item.get("redact_arg_indexes", [])
        if not isinstance(redact, list) or any(
            isinstance(number, bool) or not isinstance(number, int) or number < 0 or number >= len(args)
            for number in redact
        ):
            raise ConfigError("{}.redact_arg_indexes must contain indexes into args".format(label))
        steps.append({
            "id": step_id,
            "args": list(args),
            "enabled": enabled,
            "parser": parser_name,
            "cwd": cwd,
            "timeout_seconds": timeout,
            "environment": env,
            "unset_environment": unset_env,
            "redact_arg_indexes": sorted(set(redact)),
            "evidence_requirements": evidence_requirements,
        })

    if not any(step["enabled"] for step in steps):
        raise ConfigError("At least one step must be enabled")
    config = {
        "schema_version": SCHEMA_VERSION,
        "workspace_root": workspace_root,
        "execution": {
            "cargo_executable": cargo,
            "continue_on_error": continue_on_error,
            "default_timeout_seconds": default_timeout,
            "termination_grace_seconds": grace,
            "environment": global_env,
            "unset_environment": global_unset,
        },
        "steps": steps,
        "_config_path": str(config_path.resolve()),
        "_config_sha256": sha256_bytes(raw),
    }
    if profile is not None:
        config["profile"] = profile
    return config, raw, config["_config_sha256"]


def resolve_root(config: dict, config_path: Path, override: Optional[str] = None) -> Path:
    if override:
        root = Path(override).expanduser().resolve()
    else:
        configured = Path(config["workspace_root"]).expanduser()
        if not configured.is_absolute():
            configured = config_path.parent / configured
        root = configured.resolve()
    if not (root / "Cargo.toml").is_file():
        raise ConfigError("Cargo.toml not found in workspace_root: {}".format(root))
    return root


def resolve_cwd(root: Path, value: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_absolute() or PureWindowsPath(value).is_absolute() or PureWindowsPath(value).drive:
        raise ConfigError("Step cwd must be relative to workspace root: {}".format(value))
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        raise ConfigError("Step cwd escapes workspace_root: {}".format(value))
    if not resolved.is_dir():
        raise ConfigError("Step cwd is not a directory: {}".format(resolved))
    return resolved


def redact_environment(environment: Dict[str, str]) -> Dict[str, str]:
    # Do not serialize environment values, even when their names look harmless.
    return {key: "<REDACTED>" for key in sorted(environment)}


def redacted_config(config: dict) -> dict:
    execution = config["execution"]
    result = {
        "schema_version": config["schema_version"],
        "workspace_root": config["workspace_root"],
        "execution": {
            "cargo_executable": execution["cargo_executable"],
            "continue_on_error": execution["continue_on_error"],
            "default_timeout_seconds": execution["default_timeout_seconds"],
            "termination_grace_seconds": execution["termination_grace_seconds"],
            "environment": redact_environment(execution["environment"]),
            "unset_environment": list(execution["unset_environment"]),
        },
        "steps": [
            {
                "id": step["id"],
                "args": redact_args(step["args"], step["redact_arg_indexes"]),
                "enabled": step["enabled"],
                "parser": step["parser"],
                "cwd": step["cwd"],
                "timeout_seconds": step["timeout_seconds"],
                "environment": redact_environment(step["environment"]),
                "unset_environment": list(step["unset_environment"]),
                "redact_arg_indexes": list(step["redact_arg_indexes"]),
                "evidence_requirements": dict(
                    step.get("evidence_requirements", default_evidence_requirements(step["parser"]))
                ),
            }
            for step in config["steps"]
        ],
    }
    if "profile" in config:
        result["profile"] = dict(config["profile"])
    return result


def profile_definition(config: dict) -> dict:
    """Return the canonical normalized, redacted execution definition.

    Profile metadata and workspace/runtime observations are deliberately kept
    outside this payload. Callers should hash canonical_json_bytes(payload).
    """
    normalized = redacted_config(config)
    return {
        "schema_version": PROFILE_DEFINITION_SCHEMA_VERSION,
        "configuration_schema_version": normalized["schema_version"],
        "execution": normalized["execution"],
        "steps": normalized["steps"],
    }


def profile_definition_sha256(config: dict) -> str:
    return sha256_bytes(canonical_json_bytes(profile_definition(config)))


def execution_profile_report(config: dict) -> dict:
    profile = config.get("profile")
    if profile is None:
        return {"status": "not_declared"}
    report = {
        "status": "declared",
        "id": profile["id"],
        "version": profile["version"],
    }
    if "description" in profile:
        report["description"] = profile["description"]
    report["definition"] = {
        "schema_version": PROFILE_DEFINITION_SCHEMA_VERSION,
        "hash_algorithm": "sha256",
        "sha256": profile_definition_sha256(config),
        "digest_scope": "canonical-normalized-redacted-execution-definition",
    }
    return report


def execution_profile_summary(profile_report: dict) -> dict:
    if profile_report["status"] != "declared":
        return {"status": "not_declared"}
    return {
        "status": "declared",
        "id": profile_report["id"],
        "version": profile_report["version"],
        "definition_sha256": profile_report["definition"]["sha256"],
    }


def redacted_command(cargo: str, args: List[str], indexes: List[int]) -> List[str]:
    return [cargo] + redact_args(args, indexes)


def create_output_dir(requested: Optional[str] = None) -> Path:
    if requested:
        original = Path(requested).expanduser()
        if original.is_symlink():
            raise ConfigError("Refusing output directory if it is a symlink")
        output = original.resolve()
        if output.exists() and not output.is_dir():
            raise ConfigError("Output path is not a directory: {}".format(output))
        if output.exists() and any(output.iterdir()):
            raise ConfigError("Refusing to overwrite non-empty output directory: {}".format(output))
        output.mkdir(parents=True, exist_ok=True)
        return output
    parent = Path.cwd().resolve()
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    base = "cargo-evidence-{}-{}".format(stamp, os.getpid())
    output = parent / base
    suffix = 0
    while output.exists():
        suffix += 1
        output = parent / "{}-{}".format(base, suffix)
    output.mkdir()
    return output


def fingerprint(event: dict) -> str:
    canonical = json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(canonical)


def flatten_spans(message: dict) -> List[dict]:
    result = []

    def visit(node: dict, depth: int) -> None:
        for span in node.get("spans", []) or []:
            if not isinstance(span, dict):
                continue
            result.append({
                "depth": depth,
                "file_name": span.get("file_name"),
                "byte_start": span.get("byte_start"),
                "byte_end": span.get("byte_end"),
                "line_start": span.get("line_start"),
                "line_end": span.get("line_end"),
                "column_start": span.get("column_start"),
                "column_end": span.get("column_end"),
                "is_primary": span.get("is_primary", False),
                "label": span.get("label"),
                "replacement": span.get("suggested_replacement"),
                "applicability": span.get("suggestion_applicability"),
                "text": span.get("text"),
            })
        for child in node.get("children", []) or []:
            if isinstance(child, dict):
                visit(child, depth + 1)

    visit(message, 0)
    return result


def normalize_diagnostic(event: dict, event_index: int) -> Optional[dict]:
    message = event.get("message")
    if not isinstance(message, dict):
        return None
    code_data = message.get("code")
    code = code_data.get("code") if isinstance(code_data, dict) else code_data
    spans = message.get("spans", []) or []
    primary = next((span for span in spans if isinstance(span, dict) and span.get("is_primary")), None)
    if primary is None and spans and isinstance(spans[0], dict):
        primary = spans[0]
    target = event.get("target")
    return {
        "schema_version": 1,
        "diagnostic_id": fingerprint(event),
        "event_index": event_index,
        "package_id": event.get("package_id"),
        "manifest_path": event.get("manifest_path"),
        "target": target,
        "severity": message.get("level"),
        "code": code,
        "message": message.get("message"),
        "primary_location": ({
            "file": primary.get("file_name"),
            "line": primary.get("line_start"),
            "column": primary.get("column_start"),
        } if primary else None),
        "spans": flatten_spans(message),
        "rendered": message.get("rendered"),
        "original_message": message,
        "original_event": event,
    }


def parse_cargo_json(stdout_path: Path, step_dir: Path) -> dict:
    event_counts = Counter()
    severity_counts = Counter()
    lint_counts = Counter()
    unique = {}
    finished = []
    test_events = []
    raw_count = 0
    non_json_count = 0
    diagnostic_count = 0
    malformed_events = []
    cargo_reason_hint = re.compile(rb'^\s*\{.*"reason"\s*:')
    non_json_counts = [0]

    def preserve_non_json(
        raw_line: bytes,
        line_number: int,
        malformed: bool = False,
        malformed_code: str = "malformed_cargo_json_event",
        malformed_message: str = "A Cargo JSON event could not be parsed or has an invalid reason field.",
    ) -> None:
        non_json.write(raw_line)
        non_json_counts[0] += 1
        if malformed:
            malformed_events.append({
                "line": line_number,
                "code": malformed_code,
                "message": malformed_message,
            })

    raw_path = step_dir / "raw.jsonl"
    non_json_bin = step_dir / "non-json.stdout.bin"
    diagnostics_path = step_dir / "diagnostics.jsonl"
    source_fd = open_file_no_follow(stdout_path, os.O_RDONLY)
    with os.fdopen(source_fd, "rb") as source, open_regular_writer(raw_path) as raw_out, \
            open_regular_writer(non_json_bin) as non_json, open_regular_writer(diagnostics_path) as diagnostics:
        for index, raw_line in enumerate(source):
            if not raw_line.strip():
                continue
            try:
                event = strict_json_loads(raw_line.decode("utf-8"))
            except DuplicateJSONKeyError:
                preserve_non_json(
                    raw_line, index + 1, True,
                    "duplicate_key_cargo_json_event",
                    "A Cargo JSON event contains duplicate object keys.",
                )
                continue
            except (UnicodeDecodeError, json.JSONDecodeError):
                preserve_non_json(raw_line, index + 1, cargo_reason_hint.search(raw_line) is not None)
                continue
            if not isinstance(event, dict):
                preserve_non_json(raw_line, index + 1)
                continue

            reason = event.get("reason")
            if not isinstance(reason, str) or not reason.strip():
                preserve_non_json(raw_line, index + 1, "reason" in event)
                continue

            # Preserve each valid Cargo JSON event's original bytes.
            raw_out.write(raw_line)
            raw_count += 1
            event_counts[reason] += 1
            if reason == "compiler-message":
                item = normalize_diagnostic(event, index)
                if item is not None:
                    diagnostics.write(
                        json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
                    )
                    diagnostic_count += 1
                    severity_counts[item.get("severity") or "unknown"] += 1
                    if item.get("code"):
                        lint_counts[item["code"]] += 1
                    key = item["diagnostic_id"]
                    if key not in unique:
                        unique[key] = dict(item, occurrence_count=0)
                    unique[key]["occurrence_count"] += 1
            elif reason == "build-finished":
                finished.append({
                    "success": event.get("success"),
                    "success_valid": isinstance(event.get("success"), bool),
                    "event_index": index,
                    "event": event,
                })
            elif reason in {"test", "test-suite"}:
                test_events.append({"reason": reason, "event_index": index, "event": event})

    non_json_count = non_json_counts[0]
    if non_json_count:
        decode_log(non_json_bin, step_dir / "non-json.stdout.log")
    else:
        non_json_bin.unlink(missing_ok=True)

    write_jsonl(step_dir / "diagnostics-unique.jsonl", unique.values())
    write_jsonl(step_dir / "test-json-events.jsonl", test_events)
    issues = list(malformed_events)
    if len(finished) > 1:
        issues.append({
            "code": "duplicate_build_finished",
            "message": "More than one build-finished event was observed.",
        })
    for item in finished:
        if not item["success_valid"]:
            issues.append({
                "code": "invalid_build_finished_success",
                "message": "build-finished.success must be a boolean.",
                "line": item["event_index"] + 1,
            })
    build_finished_success = None
    if len(finished) == 1 and finished[0]["success_valid"]:
        build_finished_success = finished[0]["success"]
    return {
        "raw_event_count": raw_count,
        "non_json_line_count": non_json_count,
        "event_counts": dict(event_counts),
        "diagnostic_event_count": diagnostic_count,
        "unique_diagnostic_count": len(unique),
        "severity_counts": dict(severity_counts),
        "lint_counts": dict(lint_counts),
        "build_finished": finished,
        "build_finished_success": build_finished_success,
        "test_json_events": test_events,
        "issues": issues,
    }


def parse_libtest(stdout_path: Path, stderr_path: Path, step_dir: Path) -> dict:
    cases = []
    suites = []
    issues = []
    summary_observed = False
    for source in (stdout_path, stderr_path):
        source_fd = open_file_no_follow(source, os.O_RDONLY)
        with os.fdopen(source_fd, "r", encoding="utf-8", errors="replace") as stream:
            for line_number, raw_line in enumerate(stream, 1):
                line = ANSI_RE.sub("", raw_line.rstrip("\r\n"))
                case = TEST_CASE_RE.match(line)
                if case:
                    cases.append({
                        "name": case.group(1),
                        "status": case.group(2).lower(),
                        "duration": case.group(3),
                        "source": source.name,
                        "line": line_number,
                    })
                    continue
                suite = TEST_SUITE_RE.match(line)
                if suite or TEST_SUITE_PREFIX_RE.match(line):
                    summary_observed = True
                    errors = []
                    status = suite.group(1).lower() if suite else None
                    counts = {}
                    duration = None
                    if suite:
                        counts = dict(zip(
                            ("passed", "failed", "ignored", "measured", "filtered_out"),
                            (int(suite.group(index)) for index in range(2, 7)),
                        ))
                        duration = suite.group(7)
                        failures = counts["failed"]
                        if status == "ok" and failures > 0:
                            errors.append("ok_with_failed_tests")
                        elif status == "failed" and failures == 0:
                            errors.append("failed_without_failed_tests")
                    else:
                        errors.append("unsupported_or_incomplete_summary_format")
                    suite_record = {
                        "status": status,
                        "counts": counts,
                        "summary_text": line,
                        "duration_seconds": duration,
                        "source": source.name,
                        "line": line_number,
                        "valid": not errors,
                        "errors": errors,
                    }
                    suites.append(suite_record)
                    if errors:
                        issues.append({
                            "code": "inconsistent_test_summary" if any(
                                error in errors for error in ("ok_with_failed_tests", "failed_without_failed_tests")
                            ) else "malformed_test_summary",
                            "message": "Test summary is invalid: {}.".format(", ".join(errors)),
                            "source": source.name,
                            "line": line_number,
                        })
    case_counts = {
        status: sum(1 for item in cases if item["status"] == status)
        for status in ("ok", "failed", "ignored", "measured", "filtered out")
    }
    valid_suites = [item for item in suites if item["valid"]]
    suite_totals = ({
        key: sum(item["counts"][key] for item in valid_suites)
        for key in ("passed", "failed", "ignored", "measured", "filtered_out")
    } if valid_suites else {})
    observed = bool(cases or suites)
    result = {
        "schema_version": 1,
        "parser": "rust-libtest-text",
        "observation": "observed" if observed else "not_observed",
        "case_count": len(cases),
        "cases": cases,
        "suite_count": len(suites),
        "suites": suites,
        "case_status_counts": case_counts,
        "suite_totals": suite_totals,
        "test_summary_observed": summary_observed,
        "valid_suite_count": sum(1 for item in suites if item["valid"]),
        "issues": issues,
    }
    write_jsonl(step_dir / "test-cases.jsonl", cases)
    write_jsonl(step_dir / "test-suites.jsonl", suites)
    write_json(step_dir / "test-results.json", result)
    return result


def parse_fmt_output(stdout_path: Path, stderr_path: Path, step_id: str, exit_code: Optional[int]) -> List[dict]:
    records = []
    seen = set()
    for path in (stdout_path, stderr_path):
        source_fd = open_file_no_follow(path, os.O_RDONLY)
        with os.fdopen(source_fd, "r", encoding="utf-8", errors="replace") as stream:
            for raw_line in stream:
                line = ANSI_RE.sub("", raw_line.rstrip("\r\n"))
                match = FMT_DIFF_RE.match(line)
                if match:
                    filename = match.group(1).strip()
                    if filename not in seen:
                        seen.add(filename)
                        records.append({
                            "kind": "formatting-diff",
                            "step": step_id,
                            "severity": "error",
                            "code": "rustfmt::formatting-diff",
                            "message": "rustfmt reported formatting differences",
                            "file": filename,
                        })
    if exit_code not in (None, 0) and not records:
        records.append({
            "kind": "format-check-failed",
            "step": step_id,
            "severity": "error",
            "code": None,
            "message": "cargo fmt exited unsuccessfully; inspect stdout.log and stderr.log",
            "file": None,
        })
    return records


def run_process(
    command: List[str], cwd: Path, env: dict, stdout_path: Path, stderr_path: Path,
    timeout: Optional[float], grace: float, cancellation: Any = None,
) -> dict:
    """Compatibility-local entry point; implementation lives in the supervisor module."""
    return run_supervised_process(
        command, cwd, env, stdout_path, stderr_path, timeout, grace,
        cancellation=cancellation,
    )


def prepare_step_environment(base: dict, execution: dict, step: dict) -> dict:
    env = dict(base)
    for key in execution["unset_environment"]:
        env.pop(key, None)
    env.update(execution["environment"])
    for key in step["unset_environment"]:
        env.pop(key, None)
    env.update(step["environment"])
    return env


def _invocation_error(step_id: str, code: str) -> ConfigError:
    return ConfigError("steps.{}.args Cargo invocation preflight failed ({})".format(step_id, code))


def validate_invocation_policy(step: dict, analysis: dict) -> None:
    parse_issues = analysis.get("parse_issues") or []
    if parse_issues:
        raise _invocation_error(step["id"], parse_issues[0].get("code", "cargo_invocation_parse_unresolved"))
    if not analysis.get("requested_subcommand") and not analysis.get("top_level_command"):
        raise _invocation_error(step["id"], "cargo_subcommand_missing")

    parser_name = step["parser"]
    if parser_name != "text":
        message_format = analysis.get("message_format")
        if message_format is None or not message_format.startswith("json"):
            raise ConfigError(
                "steps.{}.parser={} requires an effective --message-format=json option before `--`".format(
                    step["id"], parser_name,
                )
            )
        if analysis.get("resolved_subcommand") == "fmt":
            raise ConfigError(
                "steps.{}.parser={} is not supported for effective cargo fmt; use parser=text".format(
                    step["id"], parser_name,
                )
            )
    if parser_name == "cargo-json+libtest" and analysis.get("resolved_subcommand") != "test":
        raise ConfigError("steps.{}.parser=cargo-json+libtest requires effective cargo test".format(step["id"]))

    if parser_name in ("cargo-json", "cargo-json+libtest"):
        requirements = step["evidence_requirements"]
        if not requirements["require_valid_json_events"]:
            raise ConfigError(
                "steps.{}.evidence_requirements.require_valid_json_events must be true for Cargo JSON parsers".format(
                    step["id"],
                )
            )
        if (
            analysis.get("classification") in {"build_producing_command", "unresolved"}
            and not requirements["require_build_finished"]
        ):
            raise ConfigError(
                "steps.{}.evidence_requirements.require_build_finished cannot be false for a build-producing or unresolved Cargo invocation".format(
                    step["id"],
                )
            )


class PreflightOutcome:
    def __init__(
        self,
        status: str,
        contexts: Optional[Dict[str, dict]] = None,
        interrupted_step_id: Optional[str] = None,
        not_preflighted_step_ids: Optional[List[str]] = None,
        signal_number: Optional[int] = None,
        signal_name: Optional[str] = None,
    ):
        self.status = status
        self.contexts = contexts or {}
        self.interrupted_step_id = interrupted_step_id
        self.not_preflighted_step_ids = not_preflighted_step_ids or []
        self.signal_number = signal_number
        self.signal_name = signal_name


def _preflight_signal(cancellation: Any, probe: Optional[dict] = None) -> Tuple[Optional[int], Optional[str]]:
    probe = probe or {}
    number = probe.get("signal_number")
    name = probe.get("signal_name")
    if cancellation is not None:
        number = number or getattr(cancellation, "signal_number", None)
        name = name or getattr(cancellation, "signal_name", None)
    if number is not None and not name:
        try:
            name = signal.Signals(number).name
        except (ValueError, TypeError):
            name = "SIGNAL_{}".format(number)
    return number, name


def _preflight_interrupted(
    contexts: Dict[str, dict],
    enabled_steps: List[dict],
    interrupted_step_id: Optional[str],
    cancellation: Any,
    probe: Optional[dict] = None,
) -> PreflightOutcome:
    number, name = _preflight_signal(cancellation, probe)
    if number is None:
        number = getattr(signal, "SIGINT", 2)
    if not name:
        try:
            name = signal.Signals(number).name
        except (ValueError, TypeError):
            name = "SIGNAL_{}".format(number)
    if interrupted_step_id is None:
        not_preflighted = [
            step["id"] for step in enabled_steps
            if step["id"] not in contexts
            or (contexts[step["id"]].get("preflight_status") == "not_run_interrupted")
        ]
    else:
        interrupted_index = next(
            (index for index, step in enumerate(enabled_steps) if step["id"] == interrupted_step_id),
            len(enabled_steps),
        )
        not_preflighted = [step["id"] for step in enabled_steps[interrupted_index + 1:]]
    for step_id in not_preflighted:
        contexts.setdefault(step_id, {"preflight_status": "not_run_interrupted"})
    return PreflightOutcome(
        "interrupted", contexts, interrupted_step_id, not_preflighted, number, name,
    )


def preflight_cargo_invocations(
    config: dict,
    root: Path,
    cancellation: Any = None,
) -> PreflightOutcome:
    """Resolve every enabled invocation before evidence output is created."""
    base_env = os.environ.copy()
    base_env["CARGO_TERM_COLOR"] = "never"
    base_env["NO_COLOR"] = "1"
    execution = config["execution"]
    contexts = {}
    enabled_steps = [step for step in config["steps"] if step["enabled"]]
    for step_index, step in enumerate(enabled_steps):
        if cancellation is not None and cancellation.cancelled:
            return _preflight_interrupted(contexts, enabled_steps, None, cancellation)
        cwd = resolve_cwd(root, step["cwd"])
        env = prepare_step_environment(base_env, execution, step)
        preliminary = analyze_cargo_invocation(
            step["args"], cwd, env,
            build_producing_subcommands=BUILD_PRODUCING_SUBCOMMANDS,
        )
        if preliminary.get("parse_issues"):
            raise _invocation_error(step["id"], preliminary["parse_issues"][0].get("code", "cargo_invocation_parse_unresolved"))
        probe_cwd = preliminary.get("_cargo_cwd") or cwd
        selector = preliminary.get("toolchain_selector")
        probe_command = [execution["cargo_executable"]]
        if selector:
            probe_command.append("+" + selector)
        probe_command.append("-Vv")
        if cancellation is not None and cancellation.cancelled:
            contexts[step["id"]] = {
                "analysis": preliminary,
                "preflight_status": "not_run_interrupted",
            }
            return _preflight_interrupted(contexts, enabled_steps, None, cancellation)
        cargo_version_probe = run_probe(
            "cargo_version", probe_command, probe_cwd, env,
            termination_grace_seconds=execution["termination_grace_seconds"],
            cancellation=cancellation,
        )
        if cargo_version_probe.get("status") == "interrupted" or (
            cancellation is not None and cancellation.cancelled
        ):
            contexts[step["id"]] = {
                "analysis": preliminary,
                "cargo_version_probe": cargo_version_probe,
                "preflight_status": "interrupted",
            }
            return _preflight_interrupted(
                contexts, enabled_steps, step["id"], cancellation, cargo_version_probe,
            )
        cargo_version_probe = parse_cargo_version_probe(cargo_version_probe)
        analysis = analyze_cargo_invocation(
            step["args"], cwd, env, cargo_version_probe,
            build_producing_subcommands=BUILD_PRODUCING_SUBCOMMANDS,
            analysis_context=preliminary,
        )
        validate_invocation_policy(step, analysis)
        contexts[step["id"]] = {
            "analysis": analysis,
            "cargo_version_probe": cargo_version_probe,
            "preflight_status": "completed",
        }
    if cancellation is not None and cancellation.cancelled:
        return _preflight_interrupted(contexts, enabled_steps, None, cancellation)
    return PreflightOutcome("completed", contexts)


def process_step(
    cargo: str, step: dict, root: Path, output: Path, base_env: dict, execution: dict,
    cancellation: Any = None, invocation_analysis: Optional[dict] = None,
) -> dict:
    cwd = resolve_cwd(root, step["cwd"])
    env = prepare_step_environment(base_env, execution, step)
    analysis = invocation_analysis or analyze_cargo_invocation(
        step["args"], cwd, env,
        build_producing_subcommands=BUILD_PRODUCING_SUBCOMMANDS,
    )
    validate_invocation_policy(step, analysis)
    requirements = step.get("evidence_requirements")
    if requirements is None:
        requirements = default_evidence_requirements(step["parser"])
    else:
        requirements = dict(requirements)
    if step["parser"] in ("cargo-json", "cargo-json+libtest"):
        requirements["require_valid_json_events"] = True
        if analysis.get("classification") == "build_producing_command":
            requirements["require_build_finished"] = True
    step_dir = output / step["id"]
    step_dir.mkdir(parents=False, exist_ok=False)
    stdout_bin = step_dir / "stdout.bin"
    stderr_bin = step_dir / "stderr.bin"
    stdout_log = step_dir / "stdout.log"
    stderr_log = step_dir / "stderr.log"

    timeout = step["timeout_seconds"]
    if timeout is None:
        timeout = execution["default_timeout_seconds"]
    command = [cargo] + list(step["args"])
    started_at = utc_now()
    process_args = (
        command, cwd, env, stdout_bin, stderr_bin, timeout,
        execution["termination_grace_seconds"],
    )
    proc = run_process(*process_args, cancellation) if cancellation is not None else run_process(*process_args)
    decode_log(stdout_bin, stdout_log)
    decode_log(stderr_bin, stderr_log)
    exit_code = proc["exit_code"]

    cargo_data = {
        "raw_event_count": 0,
        "non_json_line_count": 0,
        "event_counts": {},
        "diagnostic_event_count": 0,
        "unique_diagnostic_count": 0,
        "severity_counts": {},
        "lint_counts": {},
        "build_finished": [],
        "build_finished_success": None,
        "test_json_events": [],
        "fmt_diff_observed": False,
        "issues": [],
    }
    if step["parser"] in ("cargo-json", "cargo-json+libtest"):
        cargo_data = parse_cargo_json(stdout_bin, step_dir)
    elif analysis.get("resolved_subcommand") == "fmt":
        fmt_diagnostics = parse_fmt_output(stdout_log, stderr_log, step["id"], exit_code)
        write_jsonl(step_dir / "diagnostics.jsonl", fmt_diagnostics)
        write_jsonl(step_dir / "diagnostics-unique.jsonl", fmt_diagnostics)
        cargo_data["fmt_diff_observed"] = any(item.get("kind") == "formatting-diff" for item in fmt_diagnostics)
        cargo_data["diagnostic_event_count"] = len(fmt_diagnostics)
        cargo_data["unique_diagnostic_count"] = len(fmt_diagnostics)
        cargo_data["severity_counts"] = dict(Counter(item["severity"] for item in fmt_diagnostics))

    test_data = None
    if step["parser"] == "cargo-json+libtest":
        test_data = parse_libtest(stdout_log, stderr_log, step_dir)
        case_failures = test_data["case_status_counts"].get("failed", 0)
        suite_failures = test_data["suite_totals"].get("failed", 0)
        failed_suites = sum(1 for item in test_data["suites"] if item["status"] == "failed")
        executed_test_count = sum(
            test_data["suite_totals"].get(key, 0) for key in ("passed", "failed", "measured")
        )
        test_data["executed_test_count"] = executed_test_count
        if case_failures or suite_failures or failed_suites:
            test_state = "test-failures-observed"
        elif not test_data["test_summary_observed"]:
            test_state = "test-summary-missing"
        elif test_data["valid_suite_count"] == test_data["suite_count"] and test_data["suite_count"]:
            if executed_test_count == 0:
                test_state = "zero-tests-allowed" if requirements["allow_zero_tests"] else "zero-tests-not-allowed"
            else:
                test_state = "passed-with-test-summary-observed"
        else:
            test_state = "invalid-test-summary"
        test_data["state"] = test_state
        test_data["cargo_json_test_event_count"] = len(cargo_data["test_json_events"])
        test_data["allow_zero_tests"] = requirements["allow_zero_tests"]
        write_json(step_dir / "test-results.json", test_data)

    evidence_issues = []
    evidence_status = "not_applicable"
    if step["parser"] in ("cargo-json", "cargo-json+libtest"):
        evidence_issues.extend(cargo_data.get("issues", []))
        has_test_summary_evidence = bool(
            test_data and test_data.get("valid_suite_count") and
            test_data["valid_suite_count"] == test_data.get("suite_count")
        )
        if (
            (requirements["require_valid_json_events"] or not has_test_summary_evidence)
            and not cargo_data.get("raw_event_count")
        ):
            evidence_issues.append({
                "code": "missing_valid_json_events",
                "message": "No valid Cargo JSON events were observed.",
            })
        if requirements["require_build_finished"] and not cargo_data.get("build_finished"):
            evidence_issues.append({
                "code": "missing_build_finished",
                "message": "Required build-finished event was not observed.",
            })
        if test_data is not None:
            evidence_issues.extend(test_data.get("issues", []))
        if test_data is not None and requirements["require_test_summary"]:
            if not test_data["test_summary_observed"]:
                evidence_issues.append({
                    "code": "missing_test_summary",
                    "message": "Required libtest result summary was not observed.",
                })
            elif (
                test_data["valid_suite_count"] == test_data["suite_count"]
                and test_data["suite_count"]
                and test_data.get("executed_test_count", 0) == 0
                and not requirements["allow_zero_tests"]
            ):
                evidence_issues.append({
                    "code": "zero_tests_not_allowed",
                    "message": "A valid test summary was observed, but all test counters were zero and allow_zero_tests is false.",
                })
        invalid_codes = {
            "malformed_cargo_json_event", "duplicate_build_finished", "invalid_build_finished_success",
            "duplicate_key_cargo_json_event", "malformed_test_summary", "inconsistent_test_summary",
        }
        if any(issue.get("code") in invalid_codes for issue in evidence_issues):
            evidence_status = "invalid"
        elif evidence_issues:
            evidence_status = "incomplete"
        else:
            evidence_status = "complete"

    process_tree = proc.get("process_tree") or {}
    cleanup_verified = process_tree.get("cleanup_verified")
    if cleanup_verified is None:
        cleanup_verified = process_tree.get("cleanup_complete", False)

    # A launch failure means no process was started. For started processes,
    # failed cleanup verification takes precedence over the original supervisor
    # error because it describes the state we could not establish.
    if proc.get("spawn_error"):
        status = "launch_error"
    elif process_tree and not cleanup_verified:
        status = "process_cleanup_failed"
    elif proc.get("supervision_error"):
        status = "supervision_error"
    elif proc["interrupted"]:
        status = "interrupted"
    elif proc["timed_out"]:
        status = "timed_out"
    elif evidence_status == "invalid":
        status = "parser_error"
    elif (
        exit_code != 0
        or cargo_data.get("build_finished_success") is False
        or cargo_data.get("fmt_diff_observed", False)
        or (test_data and test_data.get("state") == "test-failures-observed")
        or cargo_data.get("severity_counts", {}).get("error", 0) > 0
        or proc.get("orphan_processes_detected", False)
    ):
        status = "failed"
    elif evidence_status == "incomplete":
        status = "incomplete"
    else:
        status = "passed"

    if proc.get("spawn_error"):
        execution_status = "not_started"
    elif proc.get("interrupted"):
        execution_status = "interrupted"
    elif proc.get("timed_out"):
        execution_status = "timed_out"
    elif exit_code is not None:
        execution_status = "completed"
    else:
        execution_status = "unknown"

    diagnostic_summary = {
        "events": cargo_data.get("diagnostic_event_count", 0),
        "unique": cargo_data.get("unique_diagnostic_count", 0),
        "by_severity": cargo_data.get("severity_counts", {}),
        "by_code": cargo_data.get("lint_counts", {}),
    }
    record = {
        "schema_version": 1,
        "id": step["id"],
        "args": redact_args(step["args"], step["redact_arg_indexes"]),
        "parser": step["parser"],
        "cwd": str(cwd),
        "timeout_seconds": timeout,
        "environment_override_names": sorted(step["environment"].keys()),
        "environment_unset_names": sorted(step["unset_environment"]),
        "started_at": started_at,
        "finished_at": utc_now(),
        "duration_ms": proc["duration_ms"],
        "exit_code": exit_code,
        "interrupted": proc["interrupted"],
        "signal_number": proc.get("signal_number"),
        "signal_name": proc.get("signal_name"),
        "timed_out": proc["timed_out"],
        "spawn_error": proc["spawn_error"],
        "supervision_error": proc.get("supervision_error"),
        "native_exit_code": proc.get("native_exit_code"),
        "orphan_processes_detected": proc.get("orphan_processes_detected", False),
        "process_tree": proc.get("process_tree"),
        "execution_status": execution_status,
        "status": status,
        "evidence_status": evidence_status,
        "evidence_issues": evidence_issues,
        "evidence_requirements": dict(requirements),
        "cargo_json": step["parser"] in ("cargo-json", "cargo-json+libtest"),
        "cargo_json_event_count": cargo_data.get("raw_event_count", 0),
        "build_finished_success": cargo_data.get("build_finished_success"),
        "diagnostics": diagnostic_summary,
        "tests": test_data,
        "files": {
            "stdout_binary": step["id"] + "/stdout.bin",
            "stderr_binary": step["id"] + "/stderr.bin",
            "stdout_log": step["id"] + "/stdout.log",
            "stderr_log": step["id"] + "/stderr.log",
        },
    }
    if proc.get("startup") is not None:
        record["process_startup"] = proc["startup"]
    if step["parser"] in ("cargo-json", "cargo-json+libtest"):
        record["files"].update({
            "raw_jsonl": step["id"] + "/raw.jsonl",
            "diagnostics_jsonl": step["id"] + "/diagnostics.jsonl",
            "diagnostics_unique_jsonl": step["id"] + "/diagnostics-unique.jsonl",
            "test_json_events_jsonl": step["id"] + "/test-json-events.jsonl",
        })
        if cargo_data.get("non_json_line_count", 0):
            record["files"]["non_json_stdout_binary"] = step["id"] + "/non-json.stdout.bin"
            record["files"]["non_json_stdout_log"] = step["id"] + "/non-json.stdout.log"
    elif analysis.get("resolved_subcommand") == "fmt":
        record["files"]["diagnostics_jsonl"] = step["id"] + "/diagnostics.jsonl"
    if test_data is not None:
        record["files"].update({
            "test_cases_jsonl": step["id"] + "/test-cases.jsonl",
            "test_suites_jsonl": step["id"] + "/test-suites.jsonl",
            "test_results_json": step["id"] + "/test-results.json",
        })
    write_json(step_dir / "summary.json", record)
    return record


def planned_archive_path(output: Path) -> Path:
    """Choose an unused archive and sidecar name without creating either."""
    stem = output.name
    candidate = output.parent / (stem + ".tar.gz")
    suffix = 0
    while (_entry_exists(candidate) or _entry_exists(candidate.with_name(candidate.name + ".partial"))
           or _entry_exists(candidate.with_name(candidate.name + ".integrity.json"))):
        suffix += 1
        candidate = output.parent / (stem + "-{}.tar.gz".format(suffix))
    return candidate


def create_archive(output: Path, destination: Optional[Path] = None) -> Path:
    """Create a sorted, non-overwriting PAX TAR.GZ beside the evidence directory."""
    candidate = destination or planned_archive_path(output)
    partial = candidate.with_name(candidate.name + ".partial")
    reservation_fd = None
    reservation_identity = None
    published = False
    partial_created = False
    try:
        with secure_directory(candidate.parent, verify_names=False) as (archive_parent_fd, _parent_names):
            reservation_fd = create_exclusive_file(candidate, parent_fd=archive_parent_fd, name=candidate.name)
            reservation_identity = os.fstat(reservation_fd)
            partial_fd = create_exclusive_file(partial, parent_fd=archive_parent_fd, name=partial.name)
            partial_created = True
            with os.fdopen(partial_fd, "wb") as partial_stream:
              with tarfile.open(fileobj=partial_stream, mode="w:gz", format=tarfile.PAX_FORMAT) as archive:
                def add_children(directory: Path, directory_fd: int, names: List[str], prefix: str) -> None:
                    for child_name in names:
                        path = directory / child_name
                        info = stat_child(path, directory_fd, child_name)
                        arcname = prefix + "/" + child_name
                        if os.name == "nt":
                            tar_info = tarfile.TarInfo(arcname)
                            tar_info.mode = stat.S_IMODE(info.st_mode)
                            tar_info.uid = getattr(info, "st_uid", 0)
                            tar_info.gid = getattr(info, "st_gid", 0)
                            tar_info.mtime = info.st_mtime
                            if is_link_entry(path, info):
                                tar_info.type = tarfile.SYMTYPE
                                tar_info.linkname = read_link(path, directory_fd, child_name, info)
                            elif stat.S_ISDIR(info.st_mode):
                                tar_info.type = tarfile.DIRTYPE
                                tar_info.size = 0
                            elif stat.S_ISREG(info.st_mode):
                                tar_info.type = tarfile.REGTYPE
                                tar_info.size = info.st_size
                        else:
                            tar_info = archive.gettarinfo(str(path), arcname=arcname)
                        if is_link_entry(path, info):
                            if not tar_info.issym() and not tar_info.islnk():
                                raise OSError("Evidence link type changed while archiving: {}".format(arcname))
                            archive.addfile(tar_info)
                        elif stat.S_ISDIR(info.st_mode):
                            if not tar_info.isdir():
                                raise OSError("Evidence directory type changed while archiving: {}".format(arcname))
                            with secure_directory(path, info, directory_fd, child_name) as (child_fd, child_names):
                                archive.addfile(tar_info)
                                add_children(path, child_fd, child_names, arcname)
                        elif stat.S_ISREG(info.st_mode):
                            if not tar_info.isfile() or tar_info.size != info.st_size:
                                raise OSError("Evidence file type changed while archiving: {}".format(arcname))
                            source_fd = open_file_no_follow(
                                path, os.O_RDONLY, expected=info, parent_fd=directory_fd, name=child_name,
                            )
                            with os.fdopen(source_fd, "rb") as source:
                                archive.addfile(tar_info, source)
                        else:
                            raise OSError("Evidence contains a non-regular archive entry: {}".format(arcname))

                with secure_directory(output.parent) as (evidence_parent_fd, _evidence_parent_names):
                    root_info = stat_child(output, evidence_parent_fd, output.name)
                    if os.name == "nt":
                        root_tar_info = tarfile.TarInfo(output.name)
                        root_tar_info.type = tarfile.DIRTYPE
                        root_tar_info.mode = stat.S_IMODE(root_info.st_mode)
                        root_tar_info.uid = getattr(root_info, "st_uid", 0)
                        root_tar_info.gid = getattr(root_info, "st_gid", 0)
                        root_tar_info.mtime = root_info.st_mtime
                    else:
                        root_tar_info = archive.gettarinfo(str(output), arcname=output.name)
                    if not root_tar_info.isdir():
                        raise OSError("Evidence root is not a regular directory")
                    with secure_directory(output, root_info, evidence_parent_fd, output.name) as (root_fd, names):
                        archive.addfile(root_tar_info)
                        add_children(output, root_fd, names, output.name)
              partial_stream.flush()
            sync_file(partial)
            current_reservation = stat_child(candidate, archive_parent_fd, candidate.name)
            if not same_file_object(reservation_identity, current_reservation):
                raise OSError("Reserved archive destination changed before publication")
            os.close(reservation_fd)
            reservation_fd = None
        try:
            atomic_replace(partial, candidate)
        except BaseException as exc:
            # A directory-sync error follows a visible rename. Preserve that
            # candidate so Runner can recheck it at the same path on retry.
            if getattr(exc, "namespace_sync_failed", False) and getattr(exc, "published_path", None) == str(candidate):
                published = True
            raise
        published = True
        return candidate
    except BaseException:
        if partial_created:
            try:
                partial.unlink(missing_ok=True)
            except FileNotFoundError:
                pass
        if reservation_fd is not None and not published:
            try:
                current_reservation = os.stat(str(candidate), follow_symlinks=False)
                if reservation_identity is not None and same_file_object(reservation_identity, current_reservation):
                    candidate.unlink(missing_ok=True)
            except FileNotFoundError:
                pass
        raise
    finally:
        if reservation_fd is not None:
            os.close(reservation_fd)


def verify_archive_snapshot(archive_path: Path, output: Path, inventory: dict) -> None:
    """Require the exact evidence tree before checking archived artifact data."""

    def normalize_member_name(name: str) -> str:
        if not isinstance(name, str) or not name or "\x00" in name:
            raise OSError("Archive contains an invalid member path")
        portable_name = name.replace("\\", "/")
        windows_name = PureWindowsPath(name)
        if portable_name.startswith("/") or windows_name.is_absolute() or windows_name.drive:
            raise OSError("Archive contains an absolute member path: {}".format(name))
        parts = portable_name.split("/")
        if ".." in parts:
            raise OSError("Archive contains a path traversal member: {}".format(name))
        normalized = "/".join(part for part in parts if part not in ("", "."))
        if not normalized:
            raise OSError("Archive contains an empty member path")
        return normalized

    root_name = normalize_member_name(output.name)
    if "/" in root_name or root_name != output.name:
        raise OSError("Evidence directory name is not a safe archive root")

    expected_files = {}
    for record in inventory.get("artifacts", []):
        if not isinstance(record, dict):
            raise OSError("Artifact inventory contains an invalid record")
        relative = record.get("path")
        normalized_relative = normalize_member_name(relative)
        if normalized_relative != relative:
            raise OSError("Artifact inventory path is not normalized: {}".format(relative))
        if normalized_relative in expected_files or normalized_relative == ARTIFACT_INVENTORY_NAME:
            raise OSError("Artifact inventory contains a duplicate or reserved path: {}".format(relative))
        expected_files[normalized_relative] = record
    expected_files[ARTIFACT_INVENTORY_NAME] = None

    expected_directories = {root_name}
    expected_paths = {}
    for relative, record in expected_files.items():
        parts = relative.split("/")
        for index in range(1, len(parts)):
            expected_directories.add(root_name + "/" + "/".join(parts[:index]))
        expected_paths[root_name + "/" + relative] = record
    expected_members = expected_directories | set(expected_paths)
    if expected_directories & set(expected_paths):
        raise OSError("Artifact inventory has a file path that conflicts with a required directory")

    def read_snapshot_link_handle_relative(relative: str) -> Tuple[Optional[str], str]:
        """Read an inventoried link only through held parent-directory handles."""
        parts = PurePosixPath(relative).parts
        if not parts or any(part in ("", ".", "..") for part in parts):
            raise OSError("Evidence link path is not normalized: {}".format(relative))

        def descend(directory: Path, directory_fd: int, remaining: Tuple[str, ...]):
            child_name = remaining[0]
            child_path = directory / child_name
            info = stat_child(child_path, directory_fd, child_name)
            if len(remaining) > 1:
                if is_link_entry(child_path, info) or not stat.S_ISDIR(info.st_mode):
                    raise OSError("Evidence link parent changed type during snapshot verification: {}".format(relative))
                with secure_directory(
                        child_path, info, directory_fd, child_name, verify_names=False) as (child_fd, _names):
                    return descend(child_path, child_fd, remaining[1:])
            if is_junction_entry(child_path, info):
                raise OSError("Windows junctions are unsupported for successful archive verification: {}".format(relative))
            if not is_link_entry(child_path, info):
                raise OSError("Evidence link type changed after inventory generation: {}".format(relative))
            return normalize_link_target(read_link(child_path, directory_fd, child_name, info))

        # Anchor the root itself to a held parent descriptor, then retain each
        # traversed directory handle until its child operation has completed.
        with secure_directory(output.parent, verify_names=False) as (output_parent_fd, _names):
            root_info = stat_child(output, output_parent_fd, output.name)
            if is_link_entry(output, root_info) or not stat.S_ISDIR(root_info.st_mode):
                raise OSError("Evidence root changed type during snapshot verification")
            with secure_directory(
                    output, root_info, output_parent_fd, output.name, verify_names=False) as (root_fd, _root_names):
                return descend(output, root_fd, parts)

    archive_fd = open_file_no_follow(archive_path, os.O_RDONLY)
    with os.fdopen(archive_fd, "rb") as archive_stream, tarfile.open(
            fileobj=archive_stream, mode="r:gz") as archive:
        normalized_members = []
        seen_names = set()
        for member in archive.getmembers():
            normalized_name = normalize_member_name(member.name)
            if normalized_name in seen_names:
                raise OSError("Archive contains duplicate normalized member names: {}".format(normalized_name))
            seen_names.add(normalized_name)
            normalized_members.append((normalized_name, member))
        if seen_names != expected_members:
            raise OSError("Archive members differ from the inventoried evidence snapshot")

        # Build the lookup only after all TAR names have been normalized and
        # uniqueness has been established.
        members_by_name = {name: member for name, member in normalized_members}
        for directory in expected_directories:
            if not members_by_name[directory].isdir():
                raise OSError("Archive directory type differs from the evidence snapshot: {}".format(directory))
        for archive_name, record in expected_paths.items():
            member = members_by_name[archive_name]
            if record is not None and record.get("entry_type") == "symlink":
                if not member.issym():
                    raise OSError("Archive symlink type differs from the evidence snapshot")
            elif record is not None and record.get("entry_type") == "non_regular":
                if not (member.ischr() or member.isblk() or member.isfifo()):
                    raise OSError("Archive special-file type differs from the evidence snapshot")
            elif not member.isfile():
                raise OSError("Archive regular-file type differs from the evidence snapshot")

        for relative, record in expected_files.items():
            archive_name = root_name + "/" + relative
            member = members_by_name[archive_name]
            if record is None:
                source = output / ARTIFACT_INVENTORY_NAME
                expected_hash, expected_size = sha256_regular_file(source)
            else:
                expected_hash = record.get("sha256")
                expected_size = record.get("size_bytes")
            if record is not None and record.get("entry_type") == "symlink":
                if record.get("link_target_status") != "reported" or not record.get("link_target"):
                    raise OSError("Archive contains a link target that cannot be verified exactly: {}".format(relative))
                try:
                    current_target, current_status = read_snapshot_link_handle_relative(relative)
                except OSError as exc:
                    raise OSError("Evidence link target could not be re-read: {}".format(relative)) from exc
                archived_target, archived_status = normalize_link_target(member.linkname)
                if (current_status != "reported" or archived_status != "reported"
                        or current_target != record["link_target"]
                        or archived_target != record["link_target"]):
                    raise OSError("Archive link target differs from the inventoried evidence snapshot: {}".format(relative))
                continue
            if record is not None and record.get("entry_type") == "non_regular":
                continue
            source = archive.extractfile(member)
            if source is None:
                raise OSError("Archive regular member could not be read")
            digest = hashlib.sha256()
            size = 0
            with source:
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    size += len(block)
                    digest.update(block)
            if size != expected_size or (expected_hash is not None and digest.hexdigest() != expected_hash):
                raise OSError(
                    "Archive member bytes differ from the evidence snapshot: {} size={} expected_size={} sha256={} expected_sha256={}".format(
                        relative, size, expected_size, digest.hexdigest(), expected_hash,
                    )
                )


class Runner:
    def __init__(
        self, config: dict, root: Path, output: Path, archive_requested: bool,
        cancellation: Any = None, invocation_context: Optional[dict] = None,
        preflight_outcome: Optional[PreflightOutcome] = None,
    ):
        self.config = config
        self.root = root
        self.output = output
        self.execution = config["execution"]
        self.cancellation = cancellation
        self.invocation_context = invocation_context or {}
        self.preflight_outcome = preflight_outcome
        self.steps: List[dict] = []
        self.interrupted = False
        self.runner_error = None
        self.launch_error = None
        self.supervision_error = None
        self.process_cleanup_error = None
        self.archive_requested = archive_requested
        self.archive_path = None
        self.archive_sidecar_path = None
        self.archive_error = None
        self._finalization_state = {
            "provenance": False, "manifest_summary": False, "inventory": False,
            "archive": False, "sidecar_reserved": False, "complete": False,
        }
        self._finalization_errors = {}
        self._runner_error_before_finalization = None
        self._archive_error_before_finalization = None
        self._archive_owned = False
        self._sidecar_owned = False
        self._preserve_archive_on_failure = False
        self._preserve_sidecar_on_failure = False
        runtime = runtime_provenance(VERSION, Path(__file__).resolve().parent)
        semantic_config = redacted_config(config)
        self.provenance = {
            "schema_version": PROVENANCE_SCHEMA_VERSION,
            "status": "incomplete",
            "agent": runtime["agent"],
            "python": runtime["python"],
            "platform": runtime["platform"],
            "config": {
                "bytes_sha256": config["_config_sha256"],
                "semantic_sha256": provenance_sha256_bytes(canonical_json_bytes(semantic_config)),
                "semantic_digest_scope": "normalized-redacted-config",
                "semantic_digest_description": (
                    "Canonical UTF-8 JSON of validated effective configuration with defaults applied. "
                    "It includes workspace_root and declared profile metadata; environment values and "
                    "redacted arguments remain redacted, so secret values are not compared."
                ),
            },
            "workspace": {
                "configured_root": str(root),
                "cargo_workspace_root": None,
                "cargo_workspace_roots": [],
                "inventory_file": "workspace-inventory.json",
                "digest_before": None,
                "digest_after": None,
                "change_status": "not_observed",
            "inventory_status": "not_collected",
            "provenance_status": "incomplete",
                "observation_guarantee": (
                    "Before/after observations are not atomic; concurrent changes between or during scans "
                    "cannot be fully excluded."
                ),
                "inventory_scope": "configured workspace content only",
                "excluded_paths": [],
                "manifest_files": {},
            },
            "steps": {},
            "issues": [
                {"code": "runtime_source_unavailable", "path": name}
                for name in runtime.get("source_errors", [])
            ],
            "scope_limits": [
                "Registry and Git dependency sources outside the configured workspace are not inventoried.",
                "External path dependencies, linker tools, native libraries, Cargo caches, and operating-system inputs are not fully inventoried.",
                "Runtime source digests identify the listed source files; they do not attest a release archive or external trustworthiness.",
                "A workspace inventory is observational and does not lock or snapshot the workspace.",
            ],
        }
        self.inventory_exclusions = []
        self.inventory_before = None
        self.target_directories = []
        self.build_directories = []
        self.step_manifest_paths = {}
        self.execution_profile = execution_profile_report(config)
        self.manifest = {
            "schema_version": SCHEMA_VERSION,
            "runner_version": VERSION,
            "status": "running",
            "started_at": utc_now(),
            "finished_at": None,
            "workspace_root": str(root),
            "evidence_directory": str(output),
            "config": {"path": config["_config_path"], "sha256": config["_config_sha256"]},
            "execution_profile": self.execution_profile,
            "provenance": self.provenance,
            "logging": {
                "python_log": "runner.log",
                "file_level": "DEBUG",
                "console_level": CONSOLE_LOG_LEVEL,
            },
            "steps": [],
            "archive": {"requested": archive_requested, "status": "requested" if archive_requested else "not_requested"},
            "artifact_inventory": {
                "path": ARTIFACT_INVENTORY_NAME,
                "schema_version": ARTIFACT_INVENTORY_SCHEMA_VERSION,
            },
        }
        with open_regular_writer(output / "steps.jsonl"):
            pass
        write_json(output / "config.redacted.json", redacted_config(config))
        self.persist()
        LOGGER.info(
            "Python agent run initialized: version=%s workspace=%s evidence=%s configured_steps=%d",
            VERSION, self.root, self.output, len(self.config["steps"]),
        )
        LOGGER.debug("Configuration fingerprint: sha256=%s", config["_config_sha256"])

    def persist(self) -> None:
        self.manifest["steps"] = self.steps
        self.manifest["provenance"] = self.provenance
        self.manifest["updated_at"] = utc_now()
        summary = self.make_summary()
        self.manifest["status"] = summary["status"]
        write_json_atomic(self.output / "manifest.json", self.manifest)
        write_json_atomic(self.output / "summary.json", summary)
        write_jsonl_atomic(self.output / "steps.jsonl", self.steps)

    def make_summary(self, artifact_inventory: Optional[dict] = None) -> dict:
        counts = Counter(step.get("status", "unknown") for step in self.steps)
        enabled_count = sum(1 for step in self.config["steps"] if step["enabled"])
        completed = sum(1 for step in self.steps if step.get("status") in {
            "passed", "failed", "incomplete", "parser_error", "timed_out", "launch_error",
            "supervision_error", "runner_error", "process_cleanup_failed"
        })
        failed = sum(counts.get(key, 0) for key in (
            "failed", "timed_out", "launch_error", "supervision_error", "runner_error",
            "process_cleanup_failed"
        ))
        diagnostics = []
        for step in self.steps:
            path = self.output / step["id"] / "diagnostics-unique.jsonl"
            if not _entry_exists(path):
                path = self.output / step["id"] / "diagnostics.jsonl"
            if _entry_exists(path):
                diagnostic_fd = open_file_no_follow(path, os.O_RDONLY)
                with os.fdopen(diagnostic_fd, "r", encoding="utf-8") as stream:
                    for line in stream:
                        if line.strip():
                            try:
                                diagnostics.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
        technical_errors = sum(counts.get(key, 0) for key in (
            "launch_error", "supervision_error", "process_cleanup_failed", "runner_error", "timed_out",
            "parser_error",
        ))
        if technical_errors or self.runner_error or self.launch_error or self.supervision_error or self.process_cleanup_error or self.archive_error:
            status = "error"
        elif self.interrupted:
            status = "incomplete"
        elif failed:
            status = "failed"
        elif completed == enabled_count and counts.get("passed", 0) == enabled_count:
            status = "passed"
        else:
            status = "incomplete"
        inventory_artifacts = (artifact_inventory or {}).get("artifacts", [])
        inventory_summary = {
            "artifact_inventory_status": (artifact_inventory or {}).get("status", "pending"),
            "artifact_count": (artifact_inventory or {}).get("artifact_count", 0),
            "hashed_artifact_count": sum(1 for item in inventory_artifacts if item.get("sha256")),
            "incomplete_artifact_count": sum(1 for item in inventory_artifacts if item.get("status") != "complete"),
            "unclassified_artifact_count": sum(1 for item in inventory_artifacts if item.get("role") == "unclassified"),
            "inventory_digest": (artifact_inventory or {}).get("inventory_digest"),
        }
        return {
            "schema_version": 1,
            "status": status,
            "configured_enabled_steps": enabled_count,
            "completed_steps": completed,
            "passed_steps": counts.get("passed", 0),
            "failed_steps": counts.get("failed", 0),
            "incomplete_steps": sum(1 for step in self.steps if (
                step.get("status") == "incomplete" or step.get("evidence_status") == "incomplete"
            )),
            "parser_error_steps": counts.get("parser_error", 0),
            "timed_out_steps": counts.get("timed_out", 0),
            "launch_error_steps": counts.get("launch_error", 0),
            "supervision_error_steps": counts.get("supervision_error", 0),
            "runner_error_steps": counts.get("runner_error", 0),
            "process_cleanup_failed_steps": counts.get("process_cleanup_failed", 0),
            "orphan_process_steps": sum(1 for step in self.steps if step.get("orphan_processes_detected")),
            "interrupted_steps": counts.get("interrupted", 0),
            "not_run_steps": counts.get("not_run_fail_fast", 0) + counts.get("not_run_interrupted", 0),
            "disabled_steps": counts.get("disabled", 0),
            "diagnostics": {
                "records": len(diagnostics),
                "by_severity": dict(Counter(item.get("severity") or "unknown" for item in diagnostics)),
                "by_code": dict(Counter(item.get("code") or "<no-code>" for item in diagnostics)),
            },
            "runner_error": self.runner_error,
            "launch_error": self.launch_error,
            "supervision_error": self.supervision_error,
            "process_cleanup_error": self.process_cleanup_error,
            "archive_error": self.archive_error,
            "execution_profile": execution_profile_summary(self.execution_profile),
            **inventory_summary,
        }

    def _record_interrupted_provenance(self, step: dict, state: str) -> None:
        base_env = os.environ.copy()
        base_env["CARGO_TERM_COLOR"] = "never"
        base_env["NO_COLOR"] = "1"
        step_cwd = resolve_cwd(self.root, step["cwd"])
        env = prepare_step_environment(base_env, self.execution, step)
        context = self.invocation_context.get(step["id"]) or {}
        outcome = self.preflight_outcome
        number = getattr(outcome, "signal_number", None) if outcome is not None else None
        name = getattr(outcome, "signal_name", None) if outcome is not None else None
        if self.cancellation is not None:
            number = number or getattr(self.cancellation, "signal_number", None)
            name = name or getattr(self.cancellation, "signal_name", None)
        record = interrupted_step_provenance(
            step, self.execution["cargo_executable"], step_cwd, env, context,
            signal_number=number, signal_name=name,
            not_preflighted=state == "not_run_interrupted",
            preflight_completed=state == "preflight_completed_execution_not_run",
        )
        self.provenance["steps"][step["id"]] = record
        self.step_manifest_paths[step["id"]] = {
            "selected_manifest_path": record["manifest"].get("selected_manifest_path"),
            "lockfile_path": record["manifest"].get("lockfile_path"),
        }

    def execute(self) -> None:
        base_env = os.environ.copy()
        # Keep command output deterministic; explicit per-step environment may override.
        base_env["CARGO_TERM_COLOR"] = "never"
        base_env["NO_COLOR"] = "1"
        workspace_roots = []
        enabled_steps = [step for step in self.config["steps"] if step["enabled"]]
        if self.preflight_outcome is not None and self.preflight_outcome.status == "interrupted":
            self.interrupted = True
            interrupted_id = self.preflight_outcome.interrupted_step_id
            for step in enabled_steps:
                context = self.invocation_context.get(step["id"]) or {}
                if step["id"] == interrupted_id:
                    state = "interrupted"
                elif context.get("preflight_status") == "completed":
                    state = "preflight_completed_execution_not_run"
                else:
                    state = "not_run_interrupted"
                self._record_interrupted_provenance(step, state)
        else:
            for step_index, step in enumerate(enabled_steps):
                if self.cancellation is not None and self.cancellation.cancelled:
                    self.interrupted = True
                    for remaining in enabled_steps[step_index:]:
                        context = self.invocation_context.get(remaining["id"]) or {}
                        state = (
                            "preflight_completed_execution_not_run"
                            if context.get("preflight_status") == "completed" else "not_run_interrupted"
                        )
                        self._record_interrupted_provenance(remaining, state)
                    break
                try:
                    invocation = self.invocation_context.get(step["id"]) or {}
                    step_provenance, target_directory, unreadable_configs = collect_step_provenance(
                        self.execution["cargo_executable"], step, self.root, base_env, self.execution,
                        prepare_step_environment, resolve_cwd, self.cancellation,
                        invocation_analysis=invocation.get("analysis"),
                        cargo_version_probe=invocation.get("cargo_version_probe"),
                    )
                    self.provenance["steps"][step["id"]] = step_provenance
                    if target_directory:
                        source = (step_provenance.get("output", {}).get("target_directory") or {}).get("source", "unknown")
                        self.target_directories.append((target_directory, "step:{}:{}".format(step["id"], source)))
                    build_directory = (step_provenance.get("output", {}).get("build_directory") or {}).get("path")
                    if build_directory:
                        build_source = (step_provenance.get("output", {}).get("build_directory") or {}).get("source", "unknown")
                        self.build_directories.append((Path(build_directory), "step:{}:{}".format(step["id"], build_source)))
                    manifest_info = step_provenance.get("manifest") or {}
                    self.step_manifest_paths[step["id"]] = {
                        "selected_manifest_path": manifest_info.get("selected_manifest_path"),
                        "lockfile_path": manifest_info.get("lockfile_path"),
                    }
                    metadata = step_provenance.get("cargo_metadata") or {}
                    cargo_workspace = metadata.get("workspace_root")
                    if cargo_workspace:
                        try:
                            canonical_workspace = str(Path(cargo_workspace).resolve())
                        except OSError:
                            canonical_workspace = str(cargo_workspace)
                        workspace_roots.append(canonical_workspace)
                    for item in unreadable_configs:
                        self.provenance["issues"].append({
                            "code": "cargo_configuration_unreadable", "step": step["id"], "path": item.get("path"),
                        })
                    if self.cancellation is not None and self.cancellation.cancelled:
                        self.interrupted = True
                        break
                except Exception as exc:
                    LOGGER.warning("[step=%s] Provenance probes could not be completed: %s", step["id"], type(exc).__name__)
                    self.provenance["steps"][step["id"]] = {
                        "status": "unavailable", "error_type": type(exc).__name__, "cwd": step["cwd"],
                        "cargo": {"version_probe": {"status": "unavailable"}},
                        "rustc": {"version_probe": {"status": "unavailable"}},
                        "cargo_metadata_probe": {"status": "unavailable"},
                        "cargo_configuration": {"files": []},
                        "target": {"selected_build_target": {"status": "unresolved"}},
                    }
                    self.provenance["issues"].append({"code": "step_provenance_collection_failed", "step": step["id"]})
                    if self.cancellation is not None and self.cancellation.cancelled:
                        self.interrupted = True
                        break

        # A signal can arrive while a prior step's Provenance probes are running.
        # Fill any later enabled records without launching another probe.
        if self.interrupted:
            for step in enabled_steps:
                if step["id"] in self.provenance["steps"]:
                    continue
                context = self.invocation_context.get(step["id"]) or {}
                state = (
                    "preflight_completed_execution_not_run"
                    if context.get("preflight_status") == "completed" else "not_run_interrupted"
                )
                self._record_interrupted_provenance(step, state)

        workspace_roots = sorted(set(workspace_roots), key=str.casefold)
        self.provenance["workspace"]["cargo_workspace_roots"] = workspace_roots
        if workspace_roots:
            self.provenance["workspace"]["cargo_workspace_root"] = workspace_roots[0] if len(workspace_roots) == 1 else None
            if any(Path(item).resolve() != self.root.resolve() for item in workspace_roots):
                self.provenance["workspace"]["workspace_root_match"] = "different_from_configured_root"
                self.provenance["issues"].append({"code": "cargo_workspace_root_differs_from_configured_root"})
            else:
                self.provenance["workspace"]["workspace_root_match"] = "matches_configured_root"
        else:
            self.provenance["workspace"]["workspace_root_match"] = "unavailable"

        self.inventory_exclusions = prepare_exclusions(
            self.root, self.output, self.target_directories, self.build_directories,
        )
        for item in self.inventory_exclusions:
            if item.get("reason") == "cargo_target_directory" and item.get("path") == ".":
                self.provenance["issues"].append({"code": "cargo_target_directory_is_workspace_root"})
            if item.get("reason") == "cargo_build_directory" and item.get("path") == ".":
                self.provenance["issues"].append({"code": "cargo_build_directory_is_workspace_root"})
        try:
            self.inventory_before = inventory_workspace(self.root, self.inventory_exclusions)
            self.provenance["workspace"]["digest_before"] = self.inventory_before["digest"]
            self.provenance["workspace"]["excluded_paths"] = self.inventory_exclusions
            self.provenance["workspace"]["inventory_status"] = (
                "complete" if not self.inventory_before.get("issues") else "incomplete"
            )
            manifest_files = manifest_file_fingerprints(self.root, self.inventory_before, None)
            manifest_files["steps"] = step_manifest_fingerprints(
                self.root, self.step_manifest_paths, self.inventory_before, None,
            )
            self.provenance["workspace"]["manifest_files"] = manifest_files
            self.provenance["issues"].extend(self.inventory_before.get("issues", []))
            self._write_workspace_inventory()
        except Exception as exc:
            LOGGER.warning("Workspace provenance baseline could not be collected: %s", type(exc).__name__)
            self.provenance["issues"].append({"code": "workspace_inventory_before_unavailable", "error_type": type(exc).__name__})
            self.provenance["workspace"]["change_status"] = "unavailable"
        self.persist()
        for step in self.config["steps"]:
            if not step["enabled"]:
                LOGGER.debug("[step=%s] Step disabled by configuration", step["id"])
                self.steps.append({"id": step["id"], "enabled": False, "status": "disabled", "exit_code": None})
                self.persist()
                continue
            if self.cancellation is not None and self.cancellation.cancelled:
                self.interrupted = True
            if self.interrupted:
                self.mark_remaining("not_run_interrupted")
                break
            safe_command = redacted_command(
                self.execution["cargo_executable"], step["args"], step["redact_arg_indexes"]
            )
            LOGGER.info(
                "[step=%s] Step started; command=%s",
                step["id"], json.dumps(safe_command, ensure_ascii=False),
            )
            LOGGER.debug(
                "[step=%s] Step execution context: cwd=%s timeout_seconds=%s parser=%s",
                step["id"], resolve_cwd(self.root, step["cwd"]),
                step["timeout_seconds"] if step["timeout_seconds"] is not None else self.execution["default_timeout_seconds"],
                step["parser"],
            )
            started = time.monotonic()
            try:
                record = process_step(
                    self.execution["cargo_executable"], step, self.root, self.output,
                    base_env, self.execution, self.cancellation,
                    invocation_analysis=(self.invocation_context.get(step["id"]) or {}).get("analysis"),
                )
            except KeyboardInterrupt:
                LOGGER.warning("[step=%s] Python agent interrupted while the step was active", step["id"])
                self.interrupted = True
                if self.cancellation is not None:
                    self.cancellation.request(getattr(signal, "SIGINT", 2))
                number = getattr(self.cancellation, "signal_number", None) if self.cancellation else None
                number = number if number is not None else getattr(signal, "SIGINT", 2)
                self.steps.append({
                    "id": step["id"], "enabled": True, "status": "interrupted",
                    "exit_code": 128 + number, "interrupted": True,
                    "signal_number": number,
                    "signal_name": getattr(self.cancellation, "signal_name", None) if self.cancellation else "SIGINT",
                    "duration_ms": round((time.monotonic() - started) * 1000),
                    "process_startup": {
                        "stage": "python_agent", "process_created": None,
                        "job_assigned": None, "thread_resumed": None,
                        "root_process_exited": None, "job_empty": None,
                        "cleanup_verified": False,
                        "error": "Python agent interrupted before a structured process result was returned",
                    },
                })
                self.mark_remaining("not_run_interrupted", current_id=step["id"])
                break
            except Exception as exc:
                self.runner_error = "{}: {}".format(type(exc).__name__, exc)
                LOGGER.exception("[step=%s] Python agent failed while processing the step", step["id"])
                self.steps.append({
                    "id": step["id"], "enabled": True, "status": "runner_error",
                    "exit_code": None, "error": self.runner_error,
                    "duration_ms": round((time.monotonic() - started) * 1000),
                    "process_startup": {
                        "stage": "python_agent", "process_created": None,
                        "job_assigned": None, "thread_resumed": None,
                        "root_process_exited": None, "job_empty": None,
                        "cleanup_verified": False, "error": self.runner_error,
                    },
                })
                self.persist()
                self.mark_remaining("not_run_fail_fast", current_id=step["id"])
                return
            self.steps.append(record)
            self.persist()
            process_tree = record.get("process_tree") or {}
            LOGGER.info(
                "[step=%s] Step finished: status=%s exit_code=%s duration_ms=%s timed_out=%s interrupted=%s cleanup_complete=%s",
                step["id"], record.get("status"), record.get("exit_code"),
                record.get("duration_ms"), record.get("timed_out", False),
                record.get("interrupted", False), process_tree.get("cleanup_complete"),
            )
            LOGGER.debug("[step=%s] Step result details: %s", step["id"], json.dumps(record, ensure_ascii=False, sort_keys=True))
            if record["status"] == "interrupted":
                self.interrupted = True
                if self.cancellation is not None and self.cancellation.cancelled:
                    record["signal_number"] = self.cancellation.signal_number
                    record["signal_name"] = self.cancellation.signal_name
                self.mark_remaining("not_run_interrupted", current_id=step["id"])
                break
            if self.cancellation is not None and self.cancellation.cancelled:
                self.interrupted = True
                self.mark_remaining("not_run_interrupted", current_id=step["id"])
                break
            if record["status"] == "process_cleanup_failed":
                process_tree = record.get("process_tree") or {}
                detail = "; ".join(process_tree.get("errors") or [])
                message = "Process-tree cleanup could not be verified for step {!r}".format(step["id"])
                if detail:
                    message += ": " + detail
                message += "; remaining steps were not executed"
                self.process_cleanup_error = message
                LOGGER.critical("[step=%s] %s", step["id"], self.process_cleanup_error)
                self.persist()
                self.mark_remaining("not_run_fail_fast", current_id=step["id"])
                break
            if record["status"] == "parser_error":
                detail = "; ".join(issue.get("message", issue.get("code", "invalid evidence"))
                                   for issue in record.get("evidence_issues", []))
                LOGGER.critical(
                    "[step=%s] Invalid Cargo evidence; remaining steps will not run%s",
                    step["id"], ": " + detail if detail else "",
                )
                self.mark_remaining("not_run_fail_fast", current_id=step["id"])
                break
            if record["status"] in {"runner_error", "launch_error", "supervision_error", "timed_out"}:
                detail = (record.get("error") or record.get("spawn_error") or
                          record.get("supervision_error") or "Step ended with status {}".format(record["status"]))
                if record["status"] == "launch_error":
                    self.launch_error = "Could not start step {!r}: {}".format(step["id"], detail)
                    message = self.launch_error
                elif record["status"] == "supervision_error":
                    process_tree = record.get("process_tree") or {}
                    cleanup_verified = process_tree.get("cleanup_verified", process_tree.get("cleanup_complete", False))
                    cleanup_note = "cleanup was verified" if cleanup_verified else "cleanup was not verified"
                    self.supervision_error = "Supervisor failed for step {!r}; {}: {}".format(
                        step["id"], cleanup_note, detail,
                    )
                    message = self.supervision_error
                elif record["status"] == "runner_error":
                    self.runner_error = detail
                    message = self.runner_error
                else:
                    self.runner_error = "Step {!r} timed out: {}".format(step["id"], detail)
                    message = self.runner_error
                LOGGER.critical("[step=%s] %s; remaining steps will not run", step["id"], message)
                self.persist()
                self.mark_remaining("not_run_fail_fast", current_id=step["id"])
                break
            if record["status"] != "passed" and not self.execution["continue_on_error"]:
                LOGGER.warning("[step=%s] Fail-fast enabled; remaining steps will not run", step["id"])
                self.mark_remaining("not_run_fail_fast", current_id=step["id"])
                break

    def mark_remaining(self, status: str, current_id: Optional[str] = None) -> None:
        seen = {step["id"] for step in self.steps}
        for step in self.config["steps"]:
            if step["id"] not in seen:
                self.steps.append({
                    "id": step["id"], "enabled": step["enabled"],
                    "status": "disabled" if not step["enabled"] else status,
                    "exit_code": None,
                })
        self.persist()

    def finalize(self) -> None:
        if self._finalization_state["complete"]:
            return
        if self._finalization_errors:
            # A prior attempt wrote a structured failure snapshot. Re-entering
            # the same Runner clears only that phase error and recomputes the
            # evidence files that include it before trying the phase again.
            self.runner_error = self._runner_error_before_finalization
            self.archive_error = self._archive_error_before_finalization
            self._runner_error_before_finalization = None
            self._archive_error_before_finalization = None
            self._finalization_errors = {}
            if self.archive_requested:
                self.manifest["archive"].pop("error", None)
                self.manifest["archive"].update({
                    "status": "requested", "path": str(self.archive_path),
                    "integrity_sidecar_path": str(self.archive_sidecar_path),
                })
            self._finalization_state.update({
                "manifest_summary": False, "inventory": False,
                "archive": False, "complete": False,
            })

        phase = "provenance"
        archive_attempted = False
        try:
            LOGGER.info("Finalizing Python agent run; steps=%d interrupted=%s", len(self.steps), self.interrupted)
            if self.archive_requested and self.archive_path is None:
                self.archive_path = planned_archive_path(self.output)
                self.archive_sidecar_path = self.archive_path.with_name(
                    self.archive_path.name + ".integrity.json",
                )
                self.manifest["archive"].update({
                    "status": "requested", "path": str(self.archive_path),
                    "integrity_sidecar_path": str(self.archive_sidecar_path),
                })

            if not self._finalization_state["provenance"]:
                provenance_before = copy.deepcopy(self.provenance)
                try:
                    self._finish_provenance()
                except BaseException:
                    self.provenance = provenance_before
                    try:
                        self._write_workspace_inventory()
                        write_json_atomic(self.output / "provenance.json", self.provenance)
                    except Exception:
                        pass
                    raise
                self._finalization_state["provenance"] = True

            self.manifest["finished_at"] = self.manifest.get("finished_at") or utc_now()
            self.manifest["steps"] = self.steps
            phase = "manifest_summary"
            if not self._finalization_state["manifest_summary"]:
                self.persist()
                self._finalization_state["manifest_summary"] = True

            summary = self.make_summary()
            LOGGER.info("Evidence directory: %s", self.output)
            if self.archive_requested:
                LOGGER.info("Evidence archive creation requested: %s", self.archive_path)
                LOGGER.info("Archive integrity sidecar planned: %s", self.archive_sidecar_path)
            LOGGER.info("Overall Python agent status: %s", summary["status"].upper())
            LOGGER.info("Python agent run finalized; status=%s", summary["status"])
            close_file_logging()

            phase = "artifact_inventory"
            inventory = None
            if self.archive_requested or not self._finalization_state["inventory"]:
                inventory = self._write_artifact_inventory()
                self._finalization_state["inventory"] = True

            phase = "evidence_sync"
            sync_evidence_tree(self.output)

            if self.archive_requested:
                phase = "archive_verification"
                assert self.archive_path is not None and self.archive_sidecar_path is not None
                archive_path = self.archive_path
                sidecar_path = self.archive_sidecar_path
                if inventory is None:
                    inventory = strict_json_loads(
                        read_regular_bytes(self.output / ARTIFACT_INVENTORY_NAME).decode("utf-8"),
                    )

                archive_info = _lstat_optional(archive_path)
                if archive_info is not None:
                    if not self._archive_owned:
                        raise OSError("An archive appeared at the planned path without this Runner creating it")
                    sync_file(archive_path)
                    sync_parent_directory(archive_path)
                    try:
                        verify_archive_snapshot(archive_path, self.output, inventory)
                    except OSError:
                        # An owned archive can become stale when a prior
                        # failed finalization persisted its structured error.
                        # Remove it only after snapshot verification failed
                        # and its no-follow identity still matches our read.
                        current_archive = _lstat_optional(archive_path)
                        if current_archive is None or not same_file_object(archive_info, current_archive):
                            raise
                        archive_path.unlink()
                        self._archive_owned = False
                        archive_attempted = True
                        phase = "archive_publication"
                        create_archive(self.output, archive_path)
                        self._archive_owned = True
                        phase = "archive_verification"
                        verify_archive_snapshot(archive_path, self.output, inventory)
                    self._preserve_archive_on_failure = False
                else:
                    archive_attempted = True
                    phase = "archive_publication"
                    create_archive(self.output, archive_path)
                    self._archive_owned = True
                    self._preserve_archive_on_failure = False
                    phase = "archive_verification"
                    verify_archive_snapshot(archive_path, self.output, inventory)
                self._finalization_state["archive"] = True

                sidecar_info = _lstat_optional(sidecar_path)
                if sidecar_info is not None and sidecar_info.st_size > 0:
                    if not self._sidecar_owned:
                        raise OSError("An integrity sidecar exists but is not owned by this Runner")
                    sync_file(sidecar_path)
                    sync_parent_directory(sidecar_path)
                    try:
                        self._verify_integrity_sidecar(sidecar_path, archive_path, inventory)
                    except OSError:
                        phase = "sidecar_publication"
                        write_json_atomic(sidecar_path, self._build_integrity_sidecar(archive_path, inventory))
                        sync_file(sidecar_path)
                        sync_parent_directory(sidecar_path)
                        self._verify_integrity_sidecar(sidecar_path, archive_path, inventory)
                    self._preserve_sidecar_on_failure = False
                    self._finalization_state["complete"] = True
                    return
                if sidecar_info is not None and not self._sidecar_owned:
                    raise OSError("An empty integrity sidecar exists but is not owned by this Runner")
                if sidecar_info is None:
                    phase = "sidecar_reservation"
                    with secure_directory(sidecar_path.parent, verify_names=False) as (sidecar_parent_fd, _names):
                        sidecar_fd = create_exclusive_file(
                            sidecar_path, parent_fd=sidecar_parent_fd, name=sidecar_path.name,
                        )
                    self._sidecar_owned = True
                    self._finalization_state["sidecar_reserved"] = True
                    os.close(sidecar_fd)

                phase = "sidecar_publication"
                sidecar = self._build_integrity_sidecar(archive_path, inventory)
                try:
                    write_json_atomic(sidecar_path, sidecar)
                    sync_file(sidecar_path)
                    sync_parent_directory(sidecar_path)
                except BaseException as publication_error:
                    try:
                        visible_sidecar = _lstat_optional(sidecar_path)
                    except OSError:
                        visible_sidecar = None
                        self._preserve_sidecar_on_failure = _entry_exists(sidecar_path)
                    if visible_sidecar is not None and visible_sidecar.st_size > 0:
                        if getattr(publication_error, "namespace_sync_failed", False):
                            self._preserve_sidecar_on_failure = True
                            self._preserve_archive_on_failure = True
                        elif not getattr(publication_error, "durability_sync_failed", False):
                            try:
                                sync_file(sidecar_path)
                                sync_parent_directory(sidecar_path)
                                self._verify_integrity_sidecar(sidecar_path, archive_path, inventory)
                                self._preserve_sidecar_on_failure = False
                                self._preserve_archive_on_failure = False
                                self._finalization_state["complete"] = True
                                return
                            except Exception as recovery_error:
                                if getattr(recovery_error, "namespace_sync_failed", False):
                                    self._preserve_sidecar_on_failure = True
                                    self._preserve_archive_on_failure = True
                                publication_error.recovery_error_type = type(recovery_error).__name__
                    raise
                self._preserve_sidecar_on_failure = False
                self._verify_integrity_sidecar(sidecar_path, archive_path, inventory)
                self._finalization_state["complete"] = True
                return

            self._finalization_state["complete"] = True
        except (Exception, KeyboardInterrupt) as exc:
            if isinstance(exc, KeyboardInterrupt) and self.cancellation is not None:
                self.cancellation.request(getattr(signal, "SIGINT", 2))
            if archive_attempted and self.archive_path is not None:
                # create_archive publishes only after reserving an absent
                # destination. A fault after publication but before return is
                # therefore attributable to this attempt.
                if _entry_exists(self.archive_path):
                    self._archive_owned = True
                    if (getattr(exc, "namespace_sync_failed", False)
                            and getattr(exc, "published_path", None) == str(self.archive_path)):
                        self._preserve_archive_on_failure = True
            self._record_finalization_failure(phase, exc)

    def _build_integrity_sidecar(self, archive_path: Path, inventory: dict) -> dict:
        inventory_path = self.output / ARTIFACT_INVENTORY_NAME
        inventory_sha256, inventory_size = sha256_regular_file(inventory_path)
        manifest_sha256, _manifest_size = sha256_regular_file(self.output / "manifest.json")
        archive_sha256, archive_size = sha256_regular_file(archive_path)
        return {
            "schema_version": 1,
            "status": "created",
            "archive": {
                "filename": archive_path.name,
                "size_bytes": archive_size,
                "sha256": archive_sha256,
            },
            "artifact_inventory": {
                "filename": inventory_path.name,
                "size_bytes": inventory_size,
                "sha256": inventory_sha256,
                "inventory_digest": inventory["inventory_digest"],
            },
            "manifest": {"sha256": manifest_sha256},
            "created_at": utc_now(),
        }

    def _verify_integrity_sidecar(self, sidecar_path: Path, archive_path: Path, inventory: dict) -> None:
        data = strict_json_loads(read_regular_bytes(sidecar_path).decode("utf-8"))
        inventory_path = self.output / ARTIFACT_INVENTORY_NAME
        inventory_sha256, inventory_size = sha256_regular_file(inventory_path)
        manifest_sha256, _manifest_size = sha256_regular_file(self.output / "manifest.json")
        archive_sha256, archive_size = sha256_regular_file(archive_path)
        expected = {
            "schema_version": 1,
            "status": "created",
            "archive": {"filename": archive_path.name, "size_bytes": archive_size, "sha256": archive_sha256},
            "artifact_inventory": {
                "filename": inventory_path.name, "size_bytes": inventory_size,
                "sha256": inventory_sha256, "inventory_digest": inventory["inventory_digest"],
            },
            "manifest": {"sha256": manifest_sha256},
        }
        for key, value in expected.items():
            if data.get(key) != value:
                raise OSError("Integrity sidecar reference mismatch for {}".format(key))

    def _record_finalization_failure(self, phase: str, exc: BaseException) -> None:
        recovery_type = getattr(exc, "recovery_error_type", None)
        suffix = " (retry sync failed: {})".format(recovery_type) if recovery_type else ""
        code = getattr(exc, "error_code", None)
        code_text = " [{}]".format(code) if code else ""
        message = "Finalization phase {} failed: {}{}: {}{}".format(
            phase, type(exc).__name__, code_text, exc, suffix,
        )
        self._finalization_errors[phase] = message
        if self._runner_error_before_finalization is None:
            self._runner_error_before_finalization = self.runner_error
        if self._archive_error_before_finalization is None:
            self._archive_error_before_finalization = self.archive_error
        self.runner_error = (self._runner_error_before_finalization + "; " if self._runner_error_before_finalization else "") + message
        if self.archive_requested:
            self.archive_error = message
            self.manifest["archive"].update({"status": "failed", "error": message})
        if self._sidecar_owned and self.archive_sidecar_path is not None and not self._preserve_sidecar_on_failure:
            try:
                if _lstat_optional(self.archive_sidecar_path) is not None:
                    self.archive_sidecar_path.unlink()
                    self._sidecar_owned = False
                    self._finalization_state["sidecar_reserved"] = False
            except OSError as cleanup_error:
                message += "; sidecar cleanup failed: {}: {}".format(type(cleanup_error).__name__, cleanup_error)
                self.archive_error = message
        if self._archive_owned and self.archive_path is not None and not self._preserve_archive_on_failure:
            try:
                self.archive_path.unlink(missing_ok=True)
                self._archive_owned = False
            except OSError as cleanup_error:
                message += "; archive cleanup failed: {}: {}".format(type(cleanup_error).__name__, cleanup_error)
                self.archive_error = message
        self._finalization_state.update({
            "manifest_summary": False, "inventory": False, "archive": False, "complete": False,
        })
        LOGGER.exception(message)
        try:
            self.persist()
            self._finalization_state["manifest_summary"] = True
        except Exception:
            LOGGER.exception("Could not persist finalization failure state")
        close_file_logging()
        if self.archive_requested:
            try:
                self._write_artifact_inventory()
                self._finalization_state["inventory"] = True
            except Exception:
                LOGGER.exception("Could not rebuild artifact inventory after finalization failure")

    def _write_artifact_inventory(self) -> dict:
        step_ids = [step["id"] for step in self.config["steps"]]
        inventory = build_artifact_inventory(self.output, step_ids)
        # Write the digest reference once, then take the inventory snapshot of
        # that finalized summary. The summary SHA slot is normalized by the
        # canonical digest, so the digest remains stable across this update.
        summary = self.make_summary(inventory)
        write_json_atomic(self.output / "summary.json", summary)
        inventory = build_artifact_inventory(self.output, step_ids)
        summary = self.make_summary(inventory)
        # Refresh the summary's exact file hash after adding the inventory digest.
        summary_artifact = next(
            (item for item in inventory["artifacts"] if item.get("path") == "summary.json"), None,
        )
        inventory["inventory_digest"] = calculate_inventory_digest(inventory)
        summary["inventory_digest"] = inventory["inventory_digest"]
        write_json_atomic(self.output / "summary.json", summary)
        if summary_artifact is not None:
            digest, size = sha256_regular_file(self.output / "summary.json")
            summary_artifact.update({
                "sha256": digest, "size_bytes": size, "status": "complete",
                "hashing_status": "complete", "verification_status": "computed",
            })
            # Recomputing uses the normalized summary slot, so the digest stays
            # unchanged while the artifact entry receives the exact final hash.
            inventory["inventory_digest"] = calculate_inventory_digest(inventory)
            if inventory["inventory_digest"] != summary["inventory_digest"]:
                raise RuntimeError("Artifact inventory digest changed after final summary hashing")
        write_json_atomic(self.output / ARTIFACT_INVENTORY_NAME, inventory)
        return inventory

    def _write_workspace_inventory(self, after: Optional[dict] = None, differences: Optional[dict] = None) -> None:
        report = {
            "schema_version": INVENTORY_SCHEMA_VERSION,
            "configured_root": str(self.root),
            "cargo_workspace_roots": self.provenance["workspace"].get("cargo_workspace_roots", []),
            "observation_guarantee": self.provenance["workspace"]["observation_guarantee"],
            "exclusions": self.inventory_exclusions,
            "before": self.inventory_before,
            "after": after,
            "differences": differences,
            "limitations": self.provenance["scope_limits"],
            "digest_before": self.provenance["workspace"].get("digest_before"),
            "digest_after": self.provenance["workspace"].get("digest_after"),
            "inventory_status": self.provenance["workspace"].get("inventory_status"),
            "change_status": self.provenance["workspace"].get("change_status"),
            "provenance_status": self.provenance.get("status"),
        }
        write_json_atomic(self.output / "workspace-inventory.json", report)

    def _finish_provenance(self) -> None:
        after = None
        differences = None
        if self.inventory_before is not None:
            try:
                after = inventory_workspace(self.root, self.inventory_exclusions)
                differences = diff_inventories(self.inventory_before, after)
                workspace = self.provenance["workspace"]
                workspace["digest_after"] = after["digest"]
                previous_manifest_files = workspace.get("manifest_files")
                manifest_files = manifest_file_fingerprints(self.root, self.inventory_before, after)
                manifest_files["steps"] = step_manifest_fingerprints(
                    self.root, self.step_manifest_paths, self.inventory_before, after, previous_manifest_files,
                )
                workspace["manifest_files"] = manifest_files
                counts = differences["counts"]
                if counts["created"] or counts["deleted"] or counts["modified"]:
                    workspace["change_status"] = "changed"
                    self.provenance["issues"].append({"code": "workspace_changed_during_agent_run", "counts": counts})
                elif counts["unstable"]:
                    workspace["change_status"] = "unstable"
                elif counts["unreadable"]:
                    workspace["change_status"] = "unreadable"
                else:
                    workspace["change_status"] = "unchanged"
                self.provenance["issues"].extend(after.get("issues", []))
            except Exception as exc:
                LOGGER.warning("Workspace provenance final inventory could not be collected: %s", type(exc).__name__)
                self.provenance["issues"].append({"code": "workspace_inventory_after_unavailable", "error_type": type(exc).__name__})
                self.provenance["workspace"]["change_status"] = "unavailable"
        else:
            self.provenance["issues"].append({"code": "workspace_inventory_incomplete"})

        configured_step_args = {
            step["id"]: list(step["args"]) for step in self.config.get("steps", [])
        }
        for step_id, step_record in self.provenance.get("steps", {}).items():
            if step_record.get("preflight_status") in {
                "interrupted", "not_run_interrupted", "preflight_completed_execution_not_run",
            }:
                step_record.setdefault("cargo_configuration", {}).setdefault(
                    "refresh_status", "not_run_interrupted",
                )
                continue
            invocation = self.invocation_context.get(step_id) or {}
            for issue in refresh_step_cargo_configuration(
                step_record, original_args=configured_step_args.get(step_id, []),
                invocation_analysis=invocation.get("analysis"),
            ):
                self.provenance["issues"].append(dict(issue, step=step_id))

        status, issues = complete_provenance_status(self.provenance)
        self.provenance["issues"] = issues
        self.provenance["status"] = status
        inventory_issues = []
        if self.inventory_before:
            inventory_issues.extend(self.inventory_before.get("issues", []))
        if after:
            inventory_issues.extend(after.get("issues", []))
        self.provenance["workspace"]["inventory_issues"] = inventory_issues
        self.provenance["workspace"]["inventory_status"] = (
            "complete" if self.inventory_before is not None and after is not None and not inventory_issues
            else "incomplete"
        )
        self.provenance["workspace"]["provenance_status"] = status
        self._write_workspace_inventory(after, differences)
        write_json_atomic(self.output / "provenance.json", self.provenance)


def dry_run(config: dict, root: Path, invocation_context: Optional[dict] = None) -> None:
    cargo = config["execution"]["cargo_executable"]
    invocation_context = invocation_context or {}
    plan = []
    for step in config["steps"]:
        if not step["enabled"]:
            continue
        analysis = (invocation_context.get(step["id"]) or {}).get("analysis") or {}
        plan.append({
            "step": step["id"],
            "cwd": str(resolve_cwd(root, step["cwd"])),
            "argv": redacted_command(cargo, step["args"], step["redact_arg_indexes"]),
            "parser": step["parser"],
            "command_classification": analysis.get("classification", "unresolved"),
            "resolved_command": analysis.get("resolved_subcommand"),
        })
    sys.stdout.write(json.dumps(plan, indent=2, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def exit_code_for_status(status: str) -> int:
    """Map the overall run status to the process exit code: 0 passed, 1 failed or incomplete, 2 error."""
    if status == "passed":
        return 0
    return 2 if status == "error" else 1


def _main(argv: Optional[List[str]] = None, cancellation_context: Any = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run only the Cargo commands declared in a JSON configuration; no default pipeline exists."
    )
    parser.add_argument(
        "--version", action="version",
        version="CargoTrail {}".format(VERSION),
    )
    parser.add_argument("--config", required=True, help="Required JSON pipeline configuration")
    parser.add_argument("--root", help="Override workspace_root; directory containing Cargo.toml")
    parser.add_argument("--output-dir", help="Evidence directory; must be empty if it already exists")
    parser.add_argument("--archive", action="store_true", help="Create a POSIX-PAX TAR.GZ beside the evidence directory")
    parser.add_argument("--dry-run", action="store_true", help="Emit redacted argv plan without running configured Cargo steps")
    parser.add_argument("--validate-config", action="store_true", help="Validate config, workspace, Cargo invocation policy, and Cargo version")
    parser.add_argument(
        "--log-level", type=str.upper, choices=("DEBUG", "INFO", "WARNING", "ERROR"), default="INFO",
        help="Console log verbosity; runner.log always records DEBUG and above",
    )
    args = parser.parse_args(argv)
    configure_logging(args.log_level)
    LOGGER.debug("Python agent entrypoint invoked; version=%s", VERSION)

    try:
        config_path = Path(args.config).expanduser().resolve()
        config, _raw, _config_hash = load_config(config_path)
        root = resolve_root(config, config_path, args.root)
        # Validate all enabled working directories before creating any evidence output.
        planned = [step for step in config["steps"] if step["enabled"]]
        for step in planned:
            resolve_cwd(root, step["cwd"])
        preflight_outcome = preflight_cargo_invocations(config, root, cancellation_context)
        invocation_context = preflight_outcome.contexts
        if preflight_outcome.status == "interrupted" and (args.validate_config or args.dry_run):
            number = preflight_outcome.signal_number or getattr(signal, "SIGINT", 2)
            return 128 + number
        if args.validate_config:
            LOGGER.info("CONFIG VALID; workspace=%s enabled_steps=%d", root, len(planned))
            return 0
        if args.dry_run:
            LOGGER.info("Dry-run plan generated; no configured Cargo steps will be executed")
            dry_run(config, root, invocation_context)
            return 0
        output = create_output_dir(args.output_dir)
    except (ConfigError, OSError, ValueError):
        LOGGER.exception("Preflight failed; no Cargo command was executed")
        return 2

    try:
        attach_file_logging(output / "runner.log")
    except OSError:
        LOGGER.exception("Cannot create the Python agent logfile; refusing to execute without persistent logging")
        return 2
    LOGGER.info(
        "Python agent run started; version=%s config=%s workspace=%s evidence=%s",
        VERSION, config_path, root, output,
    )
    LOGGER.debug("Loaded configuration fingerprint: sha256=%s", config["_config_sha256"])

    runner = None
    try:
        runner = Runner(
            config, root, output, args.archive, cancellation_context,
            invocation_context=invocation_context,
            preflight_outcome=preflight_outcome,
        )
        try:
            runner.execute()
        except KeyboardInterrupt:
            if cancellation_context is not None:
                cancellation_context.request(getattr(signal, "SIGINT", 2))
            runner.interrupted = True
            runner.mark_remaining("not_run_interrupted")
        runner.finalize()
    except KeyboardInterrupt:
        if runner is not None:
            if cancellation_context is not None:
                cancellation_context.request(getattr(signal, "SIGINT", 2))
            runner.interrupted = True
            runner.archive_error = runner.archive_error or "KeyboardInterrupt during finalization"
            LOGGER.exception("Finalization was interrupted; it will not be invoked recursively")
        LOGGER.warning("Run interrupted; partial evidence was retained where possible")
        number = getattr(cancellation_context, "signal_number", None) if cancellation_context else None
        return 128 + (number if number is not None else getattr(signal, "SIGINT", 2))
    except Exception:
        LOGGER.exception("Unrecoverable Python agent error")
        return 2

    summary = runner.make_summary()
    LOGGER.info("Evidence directory: %s", output)
    if args.archive:
        LOGGER.info("Evidence archive: %s", runner.archive_path if runner.archive_path else "NOT CREATED")
    LOGGER.info("Overall Python agent status: %s", summary["status"].upper())
    if runner.archive_error or runner.runner_error:
        if runner.archive_error:
            LOGGER.error("Archive error: %s", runner.archive_error)
        if runner.runner_error:
            LOGGER.error("Runner error: %s", runner.runner_error)
        return 2
    if runner.interrupted:
        LOGGER.warning("Python agent run ended with interruption")
        number = getattr(cancellation_context, "signal_number", None) if cancellation_context else None
        number = number or getattr(preflight_outcome, "signal_number", None)
        return 128 + (number if number is not None else getattr(signal, "SIGINT", 2))
    exit_code = exit_code_for_status(summary["status"])
    LOGGER.info("Python agent run ended; status=%s exit_code=%d", summary["status"], exit_code)
    return exit_code


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point; always flushes/closes Python logging handlers."""
    cancellation = CancellationContext()
    previous_handlers = {}
    if threading.current_thread() is threading.main_thread():
        def request_stop(signum, _frame):
            cancellation.request(signum)

        for name in ("SIGINT", "SIGTERM", "SIGHUP"):
            sig = getattr(signal, name, None)
            if sig is None:
                continue
            try:
                previous_handlers[sig] = signal.signal(sig, request_stop)
            except (ValueError, OSError):
                continue
    try:
        exit_code = _main(argv, cancellation)
        if cancellation.cancelled:
            return 128 + cancellation.signal_number
        return exit_code
    finally:
        for sig, previous_handler in reversed(list(previous_handlers.items())):
            try:
                signal.signal(sig, previous_handler)
            except (ValueError, OSError):
                pass
        close_logging()


if __name__ == "__main__":
    raise SystemExit(main())
