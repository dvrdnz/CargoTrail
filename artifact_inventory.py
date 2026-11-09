"""Deterministic inventory and integrity helpers for evidence directories.

The inventory digest normalizes the ``summary.json`` artifact SHA field. The
summary contains the inventory digest, so hashing that exact field into the
digest would create an impossible SHA-256 self-reference. The artifact record
still contains the exact SHA-256 of the final summary bytes; consumers verify
that hash directly and normalize only that one field when reproducing the
inventory digest.
"""

# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from __future__ import annotations

import hashlib
import json
import os
import stat
import errno
import contextlib
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Dict, Iterable, List, Optional, Tuple


SCHEMA_VERSION = 1
INVENTORY_NAME = "artifact-inventory.json"
HASH_BLOCK_SIZE = 1024 * 1024
WINDOWS_MOUNT_POINT_REPARSE_TAG = 0xA0000003
WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400


class FileVerificationError(OSError):
    """A no-follow file operation could not verify the object it opened."""

    def __init__(self, code: str, path: Path, error_type: Optional[str] = None, errno_value: Optional[int] = None):
        self.code = code
        self.path = Path(path)
        self.error_type = error_type or type(self).__name__
        super().__init__(errno_value or errno.EIO, "{}: {}".format(code, Path(path).name))


def _is_reparse_point(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT) or bool(
        getattr(info, "st_reparse_tag", 0),
    )


def _same_file_object(left: os.stat_result, right: os.stat_result) -> bool:
    if not stat.S_IFMT(left.st_mode) == stat.S_IFMT(right.st_mode):
        return False
    left_dev, right_dev = getattr(left, "st_dev", None), getattr(right, "st_dev", None)
    left_ino, right_ino = getattr(left, "st_ino", None), getattr(right, "st_ino", None)
    if left_dev in (None, 0) or right_dev in (None, 0) or left_ino in (None, 0) or right_ino in (None, 0):
        return False
    return left_dev == right_dev and left_ino == right_ino


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    if not _same_file_object(left, right):
        return False
    return _identity(left) == _identity(right)


def _path_stat(path: Path, parent_fd: Optional[int] = None, name: Optional[str] = None) -> os.stat_result:
    if os.name == "nt" and parent_fd is not None and name is not None:
        fd = _open_windows_relative(parent_fd, name, allow_reparse=True, access=0x00000080)
        try:
            return _windows_stat_from_fd(fd)
        finally:
            os.close(fd)
    if parent_fd is not None and name is not None and os.name != "nt":
        if os.stat not in getattr(os, "supports_dir_fd", set()) \
                or os.stat not in getattr(os, "supports_follow_symlinks", set()):
            raise FileVerificationError("descriptor_relative_stat_unavailable", Path(path), errno_value=errno.ENOTSUP)
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    return os.stat(str(path), follow_symlinks=False)


def _verify_parent_handle(path: Path, parent_fd: Optional[int]) -> None:
    if os.name != "nt" or parent_fd is None:
        return
    parent_handle_info = os.fstat(parent_fd)
    if not stat.S_ISDIR(parent_handle_info.st_mode) or _is_reparse_point(parent_handle_info):
        raise FileVerificationError("parent_directory_changed", Path(path))


def _windows_handle(fd: int):
    import msvcrt
    from ctypes import wintypes
    return wintypes.HANDLE(msvcrt.get_osfhandle(fd))


def _windows_stat_from_fd(fd: int) -> os.stat_result:
    import ctypes
    from ctypes import wintypes

    class _AttributeTagInfo(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("reparse_tag", wintypes.DWORD)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel.GetFileInformationByHandleEx
    query.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    query.restype = wintypes.BOOL
    tag_info = _AttributeTagInfo()
    if not query(_windows_handle(fd), 9, ctypes.byref(tag_info), ctypes.sizeof(tag_info)):
        error = ctypes.get_last_error()
        raise OSError(error, "GetFileInformationByHandleEx(FileAttributeTagInfo) failed")
    info = os.fstat(fd)
    extra = {
        "st_file_attributes": tag_info.attributes,
        "st_reparse_tag": tag_info.reparse_tag,
        "st_atime_ns": getattr(info, "st_atime_ns", int(info.st_atime * 1e9)),
        "st_mtime_ns": getattr(info, "st_mtime_ns", int(info.st_mtime * 1e9)),
        "st_ctime_ns": getattr(info, "st_ctime_ns", int(info.st_ctime * 1e9)),
    }
    return os.stat_result(tuple(info), extra)


def _open_windows_relative(parent_fd: int, name: str, flags: int = os.O_RDONLY,
                           mode: int = 0o666, allow_reparse: bool = False,
                           directory: bool = False, access: Optional[int] = None) -> int:
    """Open one child name relative to a held Windows directory handle."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    if not name or name in (".", "..") or "\\" in name or "/" in name or "\0" in name:
        raise FileVerificationError("invalid_relative_child_name", Path(name or "."))

    class _UnicodeString(ctypes.Structure):
        _fields_ = [("Length", wintypes.USHORT), ("MaximumLength", wintypes.USHORT),
                    ("Buffer", wintypes.LPWSTR)]

    class _ObjectAttributes(ctypes.Structure):
        _fields_ = [("Length", wintypes.ULONG), ("RootDirectory", wintypes.HANDLE),
                    ("ObjectName", ctypes.POINTER(_UnicodeString)), ("Attributes", wintypes.ULONG),
                    ("SecurityDescriptor", wintypes.LPVOID), ("SecurityQualityOfService", wintypes.LPVOID)]

    class _IoStatusUnion(ctypes.Union):
        _fields_ = [("Status", wintypes.LONG), ("Pointer", wintypes.LPVOID)]

    class _IoStatusBlock(ctypes.Structure):
        _fields_ = [("Status", _IoStatusUnion), ("Information", ctypes.c_size_t)]

    ntdll = ctypes.WinDLL("ntdll")
    create = ntdll.NtCreateFile
    create.argtypes = [ctypes.POINTER(wintypes.HANDLE), wintypes.ULONG,
                       ctypes.POINTER(_ObjectAttributes), ctypes.POINTER(_IoStatusBlock),
                       ctypes.POINTER(ctypes.c_longlong), wintypes.ULONG, wintypes.ULONG,
                       wintypes.ULONG, wintypes.ULONG, wintypes.LPVOID, wintypes.ULONG]
    create.restype = wintypes.LONG
    buffer = ctypes.create_unicode_buffer(name)
    name_bytes = len(name.encode("utf-16-le"))
    unicode_name = _UnicodeString(name_bytes, name_bytes + 2, ctypes.cast(buffer, wintypes.LPWSTR))
    attributes = _ObjectAttributes(
        ctypes.sizeof(_ObjectAttributes), _windows_handle(parent_fd),
        ctypes.pointer(unicode_name), 0x40, None, None,
    )
    status_block = _IoStatusBlock()
    handle = wintypes.HANDLE()
    if access is None:
        if flags & os.O_RDWR:
            access = 0xC0000000
        elif flags & os.O_WRONLY:
            access = 0x40000000
        else:
            access = 0x80000000
        if flags & os.O_APPEND:
            access |= 0x00000004
    if flags & os.O_CREAT and flags & os.O_EXCL:
        disposition = 2  # FILE_CREATE
    elif flags & os.O_CREAT and flags & os.O_TRUNC:
        disposition = 5  # FILE_OVERWRITE_IF
    elif flags & os.O_CREAT:
        disposition = 3  # FILE_OPEN_IF
    elif flags & os.O_TRUNC:
        disposition = 4  # FILE_OVERWRITE
    else:
        disposition = 1  # FILE_OPEN
    # The post-open identity/reparse check uses handle metadata even for
    # write-only or newly created files.
    access |= 0x00000080  # FILE_READ_ATTRIBUTES
    status = create(
        ctypes.byref(handle), access | 0x00100000, ctypes.byref(attributes),
        ctypes.byref(status_block), None, 0, 0x7, disposition,
        0x00200020 | (0x00000001 if directory else 0), None, 0,
    )
    if status < 0:
        code = status & 0xFFFFFFFF
        # Convert the common NT status codes to Win32 errors for callers.
        error = {0xC0000034: 2, 0xC000003A: 3, 0xC0000022: 5,
                 0xC0000035: 183, 0xC0000103: 267}.get(code, 1)
        raise OSError(error, "NtCreateFile relative open failed for {}".format(name))
    try:
        if flags & os.O_RDWR:
            crt_mode = os.O_RDWR
        elif flags & os.O_WRONLY:
            crt_mode = os.O_WRONLY
        else:
            crt_mode = os.O_RDONLY
        fd_flags = os.O_BINARY | crt_mode
        if flags & os.O_APPEND:
            fd_flags |= os.O_APPEND
        fd = msvcrt.open_osfhandle(int(handle.value), fd_flags)
        handle = None
        if not allow_reparse and _is_reparse_point(_windows_stat_from_fd(fd)):
            os.close(fd)
            raise FileVerificationError("reparse_point_not_followed", Path(name))
        return fd
    finally:
        if handle is not None and handle.value:
            ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)


def _windows_listdir(fd: int) -> List[str]:
    """Enumerate a held directory handle using FileIdBothDirectoryInfo."""
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel.GetFileInformationByHandleEx
    query.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    query.restype = wintypes.BOOL
    handle = _windows_handle(fd)
    buffer = ctypes.create_string_buffer(65536)
    names = []
    info_class = 11  # FileIdBothDirectoryRestartInfo
    while True:
        if not query(handle, info_class, buffer, len(buffer)):
            error = ctypes.get_last_error()
            if error == 18:  # ERROR_NO_MORE_FILES
                return names
            raise OSError(error, "GetFileInformationByHandleEx(directory) failed")
        info_class = 10  # FileIdBothDirectoryInfo
        offset = 0
        while True:
            next_offset = int.from_bytes(buffer.raw[offset:offset + 4], "little")
            name_length = int.from_bytes(buffer.raw[offset + 60:offset + 64], "little")
            name_start = offset + 104
            if name_length % 2 or name_start + name_length > len(buffer):
                raise OSError(errno.EIO, "invalid Windows directory record")
            name = buffer.raw[name_start:name_start + name_length].decode("utf-16-le")
            if name not in (".", ".."):
                names.append(name)
            if not next_offset:
                break
            if next_offset < 104 or offset + next_offset >= len(buffer):
                raise OSError(errno.EIO, "invalid Windows directory record offset")
            offset += next_offset


def _open_windows_handle(path: Path, flags: int, mode: int, directory: bool = False) -> int:
    """Open a leaf with OPEN_REPARSE_POINT and transfer its handle to a CRT fd."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    get_information = kernel.GetFileInformationByHandle
    get_information.argtypes = (wintypes.HANDLE, wintypes.LPVOID)
    get_information.restype = wintypes.BOOL
    close_handle = kernel.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    desired = 0x80000000 if flags & os.O_WRONLY == 0 else 0x40000000
    if flags & os.O_RDWR:
        desired = 0xC0000000
    if flags & os.O_APPEND:
        desired |= 0x00000004
    if flags & os.O_CREAT and flags & os.O_EXCL:
        disposition = 1  # CREATE_NEW
    elif flags & os.O_CREAT and flags & os.O_TRUNC:
        disposition = 2  # CREATE_ALWAYS
    elif flags & os.O_CREAT:
        disposition = 4  # OPEN_ALWAYS
    elif flags & os.O_TRUNC:
        disposition = 5  # TRUNCATE_EXISTING
    else:
        disposition = 3  # OPEN_EXISTING
    handle = create_file(
        str(path), desired, 0x00000001 | 0x00000002 | 0x00000004,
        None, disposition, 0x00200000 | (0x02000000 if directory else 0), None,
        # FILE_FLAG_OPEN_REPARSE_POINT; directories also require BACKUP_SEMANTICS.
    )
    invalid = ctypes.c_void_p(-1).value
    if handle in (None, invalid):
        error = ctypes.get_last_error()
        raise OSError(error, "CreateFileW failed for {}".format(path.name))
    try:
        class _HandleInfo(ctypes.Structure):
            _fields_ = [
                ("attributes", wintypes.DWORD), ("creation_low", wintypes.DWORD),
                ("creation_high", wintypes.DWORD), ("access_low", wintypes.DWORD),
                ("access_high", wintypes.DWORD), ("write_low", wintypes.DWORD),
                ("write_high", wintypes.DWORD), ("volume_serial", wintypes.DWORD),
                ("size_high", wintypes.DWORD), ("size_low", wintypes.DWORD),
                ("links", wintypes.DWORD), ("index_high", wintypes.DWORD),
                ("index_low", wintypes.DWORD),
            ]
        information = _HandleInfo()
        if not get_information(handle, ctypes.byref(information)):
            error = ctypes.get_last_error()
            raise OSError(error, "GetFileInformationByHandle failed for {}".format(path.name))
        if information.attributes & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
            raise FileVerificationError("reparse_point_not_followed", path)
        fd_flags = os.O_BINARY | (os.O_RDWR if flags & os.O_RDWR else (os.O_WRONLY if flags & os.O_WRONLY else os.O_RDONLY))
        if flags & os.O_APPEND:
            fd_flags |= os.O_APPEND
        fd = msvcrt.open_osfhandle(int(handle), fd_flags)
        handle = None
        return fd
    finally:
        if handle not in (None, invalid):
            close_handle(handle)


def open_file_no_follow(
    path: Path,
    flags: int = os.O_RDONLY,
    mode: int = 0o666,
    expected: Optional[os.stat_result] = None,
    parent_fd: Optional[int] = None,
    name: Optional[str] = None,
    regular: bool = True,
) -> int:
    """Open a file leaf without following links and verify its descriptor identity."""
    path = Path(path)
    if parent_fd is None:
        opened_fd = None
        try:
            with secure_directory(path.parent, verify_names=not bool(flags & os.O_CREAT)) as (held_parent_fd, _names):
                opened_fd = open_file_no_follow(
                    path, flags, mode, expected, held_parent_fd, path.name, regular,
                )
        except BaseException:
            # The parent re-verification runs when the with-block exits; do not
            # lose the descriptor if it fails after the leaf was opened.
            if opened_fd is not None:
                with contextlib.suppress(OSError):
                    os.close(opened_fd)
            raise
        return opened_fd
    _verify_parent_handle(path, parent_fd)
    if expected is None and not (flags & os.O_CREAT and flags & os.O_EXCL):
        try:
            expected = _path_stat(path, parent_fd, name)
        except OSError as exc:
            raise FileVerificationError("file_stat_failed", path, type(exc).__name__, exc.errno)
    if os.name == "nt":
        fd = _open_windows_relative(parent_fd, name, flags, mode) if name is not None else _open_windows_handle(path, flags, mode)
    else:
        if not hasattr(os, "O_NOFOLLOW"):
            raise FileVerificationError("no_follow_unavailable", path, errno_value=errno.ENOTSUP)
        open_flags = flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
        if regular:
            if not hasattr(os, "O_NONBLOCK"):
                raise FileVerificationError("nonblocking_open_unavailable", path, errno_value=errno.ENOTSUP)
            open_flags |= os.O_NONBLOCK
        if parent_fd is not None and name is not None:
            if os.open not in getattr(os, "supports_dir_fd", set()):
                raise FileVerificationError("descriptor_relative_open_unavailable", path, errno_value=errno.ENOTSUP)
            fd = os.open(name, open_flags | os.O_NOFOLLOW, mode, dir_fd=parent_fd)
        else:
            fd = os.open(str(path), open_flags | os.O_NOFOLLOW, mode)
    try:
        opened = os.fstat(fd)
        if regular and not stat.S_ISREG(opened.st_mode):
            raise FileVerificationError("not_regular_file", path)
        if _is_reparse_point(opened):
            raise FileVerificationError("reparse_point_not_followed", path)
        if expected is not None and not _cross_source_identity(expected, opened):
            raise FileVerificationError("file_changed_before_open", path)
        _verify_parent_handle(path, parent_fd)
        current = _path_stat(path, parent_fd, name)
        if regular and not stat.S_ISREG(current.st_mode):
            raise FileVerificationError("not_regular_file", path)
        if _is_reparse_point(current) or (expected is not None and not _cross_source_identity(current, opened)):
            raise FileVerificationError("file_changed_before_read", path)
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_regular_writer(path: Path, append: bool = False):
    """Open a regular-file writer without following a preinstalled link."""
    path = Path(path)
    fd = None
    try:
        with secure_directory(path.parent, verify_names=False) as (parent_fd, _names):
            try:
                expected = stat_child(path, parent_fd, path.name)
            except FileNotFoundError:
                expected = None
            if expected is not None:
                if not stat.S_ISREG(expected.st_mode) or _is_reparse_point(expected):
                    raise FileVerificationError("writer_target_not_regular", path)
                flags = os.O_WRONLY | (os.O_APPEND if append else 0)
                fd = open_file_no_follow(
                    path, flags, expected=expected, parent_fd=parent_fd, name=path.name,
                )
                if not append:
                    os.ftruncate(fd, 0)
            else:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | (os.O_APPEND if append else 0)
                fd = create_exclusive_file(path, 0o600, parent_fd, path.name)
    except BaseException:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)
        raise
    return os.fdopen(fd, "ab" if append else "wb")


def create_exclusive_file(path: Path, mode: int = 0o600,
                          parent_fd: Optional[int] = None, name: Optional[str] = None) -> int:
    """Create a new leaf without following or replacing a preexisting entry."""
    return open_file_no_follow(
        Path(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        mode=mode, expected=None, parent_fd=parent_fd, name=name,
    )


def same_file_object(left: os.stat_result, right: os.stat_result) -> bool:
    return _same_file_object(left, right)


def read_regular_bytes(path: Path) -> bytes:
    content, _digest, _size = read_regular_file(Path(path))
    return content


@contextlib.contextmanager
def secure_directory(path: Path, expected: Optional[os.stat_result] = None,
                     parent_fd: Optional[int] = None, name: Optional[str] = None,
                     verify_names: bool = True):
    """Hold a verified directory handle and yield its sorted child names."""
    path = Path(path)
    fd = None
    try:
        _verify_parent_handle(path, parent_fd)
        before = _path_stat(path, parent_fd, name)
        if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode) or _is_reparse_point(before):
            raise FileVerificationError("directory_not_regular", path)
        if expected is not None and not _same_file_object(expected, before):
            raise FileVerificationError("directory_changed_before_open", path)
        if os.name == "nt":
            if parent_fd is not None and name is not None:
                fd = _open_windows_relative(parent_fd, name, os.O_RDONLY, directory=True)
            else:
                fd = _open_windows_handle(path, os.O_RDONLY, 0, directory=True)
            opened = os.fstat(fd)
        else:
            if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
                raise FileVerificationError("safe_directory_open_unavailable", path, errno_value=errno.ENOTSUP)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            if parent_fd is not None and name is not None:
                fd = os.open(name, flags, dir_fd=parent_fd)
            else:
                fd = os.open(str(path), flags)
            opened = os.fstat(fd)
        if not stat.S_ISDIR(opened.st_mode) or not _same_file_object(before, opened):
            raise FileVerificationError("directory_changed_before_open", path)
        if expected is not None and not _same_file_object(expected, opened):
            raise FileVerificationError("directory_changed_before_open", path)
        if os.name != "nt" and os.listdir not in getattr(os, "supports_fd", set()):
            raise FileVerificationError("descriptor_relative_list_unavailable", path, errno_value=errno.ENOTSUP)
        names = os.listdir(fd) if os.name != "nt" else _windows_listdir(fd)
        after = os.fstat(fd)
        _verify_parent_handle(path, parent_fd)
        current = _path_stat(path, parent_fd, name)
        if not _same_file_object(opened, after) or not _same_file_object(after, current):
            raise FileVerificationError("directory_changed_during_scan", path)
        sorted_names = sorted(names, key=lambda value: (value.casefold(), value))
    except FileVerificationError:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)
        raise
    except OSError as exc:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)
        raise FileVerificationError("directory_unreadable", path, type(exc).__name__, exc.errno)

    try:
        yield fd, sorted_names
    except BaseException:
        # Preserve the operation's exception and its attributes; descriptor
        # cleanup must never replace a publication/sync failure.
        with contextlib.suppress(OSError):
            os.close(fd)
        raise

    try:
        names_after = os.listdir(fd) if os.name != "nt" else _windows_listdir(fd)
        after_yield = os.fstat(fd)
        _verify_parent_handle(path, parent_fd)
        current_after_yield = _path_stat(path, parent_fd, name)
        same_opened_state = (
            _same_file_state(opened, after_yield) if verify_names
            else _same_file_object(opened, after_yield)
        )
        if ((verify_names and sorted(names_after, key=lambda value: (value.casefold(), value)) != sorted_names)
                or not same_opened_state
                or not _cross_source_identity(after_yield, current_after_yield)):
            raise FileVerificationError("directory_changed_during_scan", path)
    except FileVerificationError:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise
    except OSError as exc:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise FileVerificationError("directory_unreadable", path, type(exc).__name__, exc.errno)
    else:
        os.close(fd)

ROOT_ROLES = {
    "manifest.json": "run_manifest",
    "summary.json": "run_summary",
    "steps.jsonl": "step_records",
    "config.redacted.json": "redacted_configuration",
    "runner.log": "agent_log",
    "provenance.json": "execution_provenance",
    "workspace-inventory.json": "workspace_input_inventory",
}

STEP_ROLES = {
    "summary.json": "step_summary",
    "stdout.bin": "process_stdout",
    "stderr.bin": "process_stderr",
    "stdout.log": "process_stdout_text",
    "stderr.log": "process_stderr_text",
    "raw.jsonl": "cargo_json_events",
    "non-json.stdout.bin": "non_json_stdout_raw",
    "non-json.stdout.log": "non_json_stdout_text",
    "diagnostics.jsonl": "normalized_diagnostics",
    "diagnostics-unique.jsonl": "deduplicated_diagnostics",
    "test-json-events.jsonl": "cargo_test_events",
    "test-cases.jsonl": "test_cases",
    "test-suites.jsonl": "test_suites",
    "test-results.json": "test_results",
}


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


def sha256_file(path: Path) -> Tuple[str, int]:
    """Hash a stable regular file, rejecting links and identity changes."""
    digest, size, status, issue = hash_regular_file(Path(path))
    if status != "complete" or digest is None or size is None:
        code = issue.get("code", "file_not_verified") if issue else "file_not_verified"
        raise FileVerificationError(code, Path(path), (issue or {}).get("error_type"), (issue or {}).get("errno"))
    return digest, size


def _identity(info: os.stat_result, include_change_time: bool = True) -> Tuple[object, ...]:
    identity = (
        getattr(info, "st_dev", None), getattr(info, "st_ino", None),
        info.st_size, getattr(info, "st_mtime_ns", int(info.st_mtime * 1e9)),
    )
    if include_change_time:
        identity += (getattr(info, "st_ctime_ns", int(info.st_ctime * 1e9)),)
    return identity


def _cross_source_identity(info: os.stat_result, descriptor_info: os.stat_result) -> bool:
    # Windows path stat and descriptor fstat expose different meanings for
    # st_ctime on some filesystems. Compare their stable identity/size/mtime,
    # then compare ctime across the two fstat samples below.
    return _identity(info, include_change_time=os.name != "nt") == _identity(
        descriptor_info, include_change_time=os.name != "nt",
    )


def _hash_regular_file(path: Path, directory_stat: os.stat_result) -> Tuple[Optional[str], Optional[int], str, Optional[dict]]:
    """Compatibility wrapper around the shared hash implementation."""
    return hash_regular_file(path, expected=directory_stat)


def hash_regular_file(
    path: Path,
    expected: Optional[os.stat_result] = None,
    parent_fd: Optional[int] = None,
    name: Optional[str] = None,
) -> Tuple[Optional[str], Optional[int], str, Optional[dict]]:
    """Return a trusted hash only when the same regular file stayed stable."""
    _content, digest, size, status, issue = _read_stable_file(
        path, expected, parent_fd, name, retain_content=False,
    )
    return digest if status == "complete" else None, size, status, issue


def read_regular_file(path: Path, expected: Optional[os.stat_result] = None,
                      parent_fd: Optional[int] = None, name: Optional[str] = None) -> Tuple[bytes, str, int]:
    """Read bytes and their trusted hash from one verified file handle."""
    content, digest, size, status, issue = _read_stable_file(
        path, expected, parent_fd, name, retain_content=True,
    )
    if status != "complete" or content is None or digest is None or size is None:
        detail = issue or {}
        raise FileVerificationError(
            detail.get("cause", detail.get("code", "file_not_verified")), Path(path),
            detail.get("error_type"), detail.get("errno"),
        )
    return content, digest, size


def _read_stable_file(
    path: Path,
    expected: Optional[os.stat_result] = None,
    parent_fd: Optional[int] = None,
    name: Optional[str] = None,
    retain_content: bool = False,
):
    """Authoritative no-follow open/read/identity transaction."""
    path = Path(path)
    if parent_fd is None:
        try:
            with secure_directory(path.parent, verify_names=False) as (held_parent_fd, _names):
                return _read_stable_file(
                    path, expected, held_parent_fd, path.name, retain_content,
                )
        except OSError as exc:
            return None, None, None, "unreadable", {
                "code": "artifact_unreadable", "cause": getattr(exc, "code", "parent_directory_unreadable"),
                "error_type": getattr(exc, "error_type", type(exc).__name__), "errno": exc.errno,
            }
    try:
        initial = expected if expected is not None else _path_stat(path, parent_fd, name)
    except OSError as exc:
        return None, None, None, "unreadable", {
            "code": "artifact_unreadable", "error_type": type(exc).__name__, "errno": exc.errno,
        }
    if not stat.S_ISREG(initial.st_mode) or stat.S_ISLNK(initial.st_mode) or _is_reparse_point(initial):
        return None, None, None, "unreadable", {"code": "artifact_not_regular"}
    try:
        descriptor = open_file_no_follow(
            path, os.O_RDONLY, expected=initial, parent_fd=parent_fd, name=name,
        )
    except FileVerificationError as exc:
        # The initial no-follow stat established a regular-file identity. A
        # non-regular descriptor or reparse point at open time therefore means
        # that the directory entry changed between stat and open, not that the
        # original artifact was inherently unreadable. Keep that distinction
        # even when the replacement is a FIFO opened with O_NONBLOCK.
        identity_changed = exc.code.startswith(("file_changed", "directory_changed")) or exc.code in {
            "not_regular_file", "reparse_point_not_followed",
        }
        status = "unstable" if identity_changed else "unreadable"
        return None, None, None, status, {
            "code": "artifact_changed_before_hash" if status == "unstable" else "artifact_unreadable",
            "cause": exc.code, "error_type": exc.error_type, "errno": exc.errno,
        }
    except OSError as exc:
        changed = False
        try:
            current = _path_stat(path, parent_fd, name)
            changed = (
                not stat.S_ISREG(current.st_mode) or stat.S_ISLNK(current.st_mode)
                or not _cross_source_identity(initial, current) or _is_reparse_point(current)
            )
        except OSError:
            changed = True
        if changed:
            return None, None, None, "unstable", {
                "code": "artifact_changed_before_hash", "cause": "path_identity_changed",
                "error_type": type(exc).__name__, "errno": exc.errno,
            }
        return None, None, None, "unreadable", {
            "code": "artifact_unreadable", "error_type": type(exc).__name__, "errno": exc.errno,
        }
    digest = hashlib.sha256()
    bytes_read = 0
    started = False
    chunks = [] if retain_content else None
    try:
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            current_before = _path_stat(path, parent_fd, name)
            if not stat.S_ISREG(before.st_mode) or not _cross_source_identity(initial, before) \
                    or not _cross_source_identity(current_before, before):
                return None, None, None, "unstable", {"code": "artifact_changed_before_hash"}
            started = True
            while True:
                block = stream.read(HASH_BLOCK_SIZE)
                if not block:
                    break
                bytes_read += len(block)
                digest.update(block)
                if retain_content:
                    chunks.append(block)
            after = os.fstat(stream.fileno())
        current_after = _path_stat(path, parent_fd, name)
    except OSError as exc:
        if started:
            try:
                current_after = _path_stat(path, parent_fd, name)
                changed = (
                    not _cross_source_identity(before, current_after)
                    or not _same_file_state(before, current_after)
                    or _is_reparse_point(current_after)
                )
            except OSError:
                changed = True
            if changed:
                observed = digest.hexdigest()
                return None, observed, bytes_read, "unstable", {
                    "code": "artifact_changed_while_hashing",
                    "observed_sha256": observed,
                    "cause": "path_identity_changed_during_read",
                }
        return None, None, bytes_read if started else None, "unreadable", {
            "code": "artifact_unreadable", "error_type": type(exc).__name__, "errno": exc.errno,
        }
    observed = digest.hexdigest() if started else None
    stable = (
        stat.S_ISREG(after.st_mode) and not _is_reparse_point(current_after)
        and _same_file_state(before, after)
        and _cross_source_identity(after, current_after)
        and _cross_source_identity(initial, current_after)
        and bytes_read == after.st_size
    )
    if not stable:
        issue = {"code": "artifact_changed_while_hashing"}
        if observed is not None:
            issue["observed_sha256"] = observed
        return None, observed, bytes_read, "unstable", issue
    content = b"".join(chunks) if retain_content else None
    return content, observed, bytes_read, "complete", None


def stat_child(path: Path, parent_fd: int, name: str) -> os.stat_result:
    """Stat a child without following links, relative to a held parent handle."""
    try:
        _verify_parent_handle(Path(path), parent_fd)
        return _path_stat(Path(path), parent_fd, name)
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            raise
        raise FileVerificationError("entry_stat_failed", Path(path), type(exc).__name__, exc.errno)


def read_link(path: Path, parent_fd: Optional[int] = None, name: Optional[str] = None,
              expected: Optional[os.stat_result] = None) -> str:
    path = Path(path)
    _verify_parent_handle(path, parent_fd)
    before = _path_stat(path, parent_fd, name)
    if not _is_link_entry(path, before) or (expected is not None and not _same_file_object(expected, before)):
        raise FileVerificationError("link_identity_changed", path)
    if os.name == "nt" and parent_fd is not None and name is not None:
        fd = _open_windows_relative(parent_fd, name, allow_reparse=True, access=0x00000080)
        try:
            target = _windows_read_link(fd, path)
        finally:
            os.close(fd)
    elif parent_fd is not None and name is not None and os.name != "nt":
        if os.readlink not in getattr(os, "supports_dir_fd", set()):
            raise FileVerificationError("descriptor_relative_readlink_unavailable", path, errno_value=errno.ENOTSUP)
        target = os.readlink(name, dir_fd=parent_fd)
    else:
        target = os.readlink(str(path))
    after = _path_stat(path, parent_fd, name)
    _verify_parent_handle(path, parent_fd)
    if not _same_file_object(before, after):
        raise FileVerificationError("link_identity_changed", path)
    return target


def _windows_read_link(fd: int, path: Path) -> str:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    ioctl = kernel.DeviceIoControl
    ioctl.argtypes = (wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                      wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID)
    ioctl.restype = wintypes.BOOL
    output = ctypes.create_string_buffer(16384)
    returned = wintypes.DWORD()
    if not ioctl(_windows_handle(fd), 0x000900A8, None, 0, output, len(output),
                 ctypes.byref(returned), None):
        error = ctypes.get_last_error()
        raise OSError(error, "FSCTL_GET_REPARSE_POINT failed for {}".format(path.name))
    data = output.raw[:returned.value]
    if len(data) < 16:
        raise OSError(errno.EIO, "truncated Windows reparse data")
    tag = int.from_bytes(data[0:4], "little")
    if tag == 0xA000000C and len(data) >= 20:  # IO_REPARSE_TAG_SYMLINK
        substitute_offset, substitute_length, print_offset, print_length = __import__("struct").unpack_from("<HHHH", data, 8)
        path_buffer_start = 20
    elif tag == WINDOWS_MOUNT_POINT_REPARSE_TAG and len(data) >= 16:
        substitute_offset, substitute_length, print_offset, print_length = __import__("struct").unpack_from("<HHHH", data, 8)
        path_buffer_start = 16
    else:
        raise FileVerificationError("unsupported_reparse_point", path)
    offset, length = (print_offset, print_length) if print_length else (substitute_offset, substitute_length)
    end = path_buffer_start + offset + length
    if length % 2 or end > len(data):
        raise OSError(errno.EIO, "invalid Windows reparse target")
    return data[path_buffer_start + offset:end].decode("utf-16-le")


def sync_file(path: Path) -> None:
    """Synchronize a verified regular file without following its leaf link."""
    path = Path(path)
    with secure_directory(path.parent) as (parent_fd, _names):
        info = stat_child(path, parent_fd, path.name)
        flags = os.O_RDWR if os.name == "nt" else os.O_RDONLY
        fd = open_file_no_follow(path, flags, expected=info, parent_fd=parent_fd, name=path.name)
        try:
            before = os.fstat(fd)
            sync_fd(fd)
            after = os.fstat(fd)
            current = stat_child(path, parent_fd, path.name)
            if not _same_file_state(before, after) or not _cross_source_identity(after, current):
                raise FileVerificationError("file_changed_during_sync", path)
        finally:
            os.close(fd)


def sync_fd(fd: int, error_code: str = "file_sync_failed") -> None:
    try:
        os.fsync(fd)
    except BaseException as exc:
        exc.durability_sync_failed = True
        exc.error_code = error_code
        raise


def sync_parent_directory(path: Path) -> None:
    """Synchronize a publication's parent namespace on POSIX."""
    if os.name == "nt":
        return
    parent = Path(path).parent
    with secure_directory(parent) as (fd, _names):
        sync_fd(fd, "directory_sync_failed")


def atomic_replace(source: Path, destination: Path) -> None:
    """Replace a sibling atomically, then verify/sync its parent namespace."""
    source, destination = Path(source), Path(destination)
    if os.path.abspath(str(source.parent)) != os.path.abspath(str(destination.parent)):
        raise FileVerificationError("atomic_replace_parent_mismatch", destination)
    with secure_directory(destination.parent, verify_names=False) as (directory_fd, _names):
        parent_before = os.fstat(directory_fd)
        if os.name == "nt":
            try:
                os.replace(str(source), str(destination))
            except OSError as exc:
                exc.error_code = "atomic_replace_failed"
                raise
            try:
                parent_after = _path_stat(destination.parent)
            except BaseException as exc:
                exc.namespace_sync_failed = True
                exc.durability_sync_failed = True
                exc.error_code = "parent_directory_changed_after_replace"
                exc.published_path = str(destination)
                raise
            if not _same_file_object(parent_before, parent_after):
                exc = FileVerificationError("parent_directory_changed_after_replace", destination.parent)
                exc.namespace_sync_failed = True
                exc.durability_sync_failed = True
                exc.error_code = "parent_directory_changed_after_replace"
                exc.published_path = str(destination)
                raise exc
        else:
            # CPython omits os.replace from supports_dir_fd even on POSIX
            # builds where it forwards both directory descriptors correctly.
            # os.rename exposes the same renameat capability in that set.
            if os.rename not in getattr(os, "supports_dir_fd", set()):
                raise FileVerificationError("descriptor_relative_replace_unavailable", destination,
                                            errno_value=errno.ENOTSUP)
            try:
                os.replace(
                    source.name, destination.name,
                    src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                )
            except (TypeError, NotImplementedError) as exc:
                raise FileVerificationError(
                    "descriptor_relative_replace_unavailable", destination,
                    type(exc).__name__, errno.ENOTSUP,
                )
            except OSError as exc:
                exc.error_code = "atomic_replace_failed"
                raise
            try:
                sync_fd(directory_fd, "directory_sync_failed_after_replace")
            except BaseException as exc:
                exc.namespace_sync_failed = True
                exc.published_path = str(destination)
                raise


def _sync_tree_files(path: Path, expected: os.stat_result, parent_fd: int, name: str,
                     directories: dict, files: dict) -> None:
    with secure_directory(path, expected, parent_fd, name) as (directory_fd, names):
        before = os.fstat(directory_fd)
        for child_name in names:
            child_path = path / child_name
            try:
                info = stat_child(child_path, directory_fd, child_name)
            except FileVerificationError as exc:
                raise FileVerificationError("evidence_entry_unreadable", child_path, exc.error_type, exc.errno)
            if stat.S_ISLNK(info.st_mode) or _is_reparse_point(info):
                raise FileVerificationError("evidence_link_not_followed", child_path)
            if stat.S_ISDIR(info.st_mode):
                _sync_tree_files(child_path, info, directory_fd, child_name, directories, files)
            elif stat.S_ISREG(info.st_mode):
                fd = open_file_no_follow(
                    child_path, os.O_RDWR if os.name == "nt" else os.O_RDONLY,
                    expected=info, parent_fd=directory_fd, name=child_name,
                )
                try:
                    file_before = os.fstat(fd)
                    sync_fd(fd)
                    file_after = os.fstat(fd)
                    current = _path_stat(child_path, directory_fd, child_name)
                    if not _same_file_state(file_before, file_after) \
                            or not _cross_source_identity(file_after, current):
                        raise FileVerificationError("evidence_file_changed_during_sync", child_path)
                    file_key = os.path.normcase(os.path.abspath(str(child_path)))
                    files[file_key] = file_after
                finally:
                    os.close(fd)
            else:
                raise FileVerificationError("evidence_non_regular_entry", child_path)
        after = os.fstat(directory_fd)
        current = _path_stat(path, parent_fd, name)
        if not _same_file_state(before, after) or not _cross_source_identity(after, current):
            raise FileVerificationError("evidence_directory_changed_during_sync", path)
        key = os.path.normcase(os.path.abspath(str(path)))
        directories[key] = (path, after, names)


def _sync_tree_directories(path: Path, expected: os.stat_result, parent_fd: int, name: str,
                           directories: dict, files: dict) -> None:
    key = os.path.normcase(os.path.abspath(str(path)))
    _recorded_path, recorded_stat, recorded_names = directories[key]
    with secure_directory(path, expected, parent_fd, name) as (directory_fd, names):
        opened = os.fstat(directory_fd)
        if names != recorded_names or not _same_file_state(recorded_stat, opened):
            raise FileVerificationError("evidence_directory_changed_before_sync", path)
        for child_name in names:
            child_path = path / child_name
            info = stat_child(child_path, directory_fd, child_name)
            if stat.S_ISDIR(info.st_mode) and not _is_reparse_point(info):
                child_key = os.path.normcase(os.path.abspath(str(child_path)))
                child_record = directories.get(child_key)
                if child_record is None or not _cross_source_identity(child_record[1], info):
                    raise FileVerificationError("evidence_directory_changed_before_sync", child_path)
                _sync_tree_directories(child_path, child_record[1], directory_fd, child_name, directories, files)
            elif stat.S_ISREG(info.st_mode):
                file_key = os.path.normcase(os.path.abspath(str(child_path)))
                file_record = files.get(file_key)
                if file_record is None or not _cross_source_identity(file_record, info):
                    raise FileVerificationError("evidence_file_changed_before_directory_sync", child_path)
            else:
                raise FileVerificationError("evidence_non_regular_entry", child_path)
        after = os.fstat(directory_fd)
        current = _path_stat(path, parent_fd, name)
        if not _same_file_state(recorded_stat, after) or not _cross_source_identity(after, current):
            raise FileVerificationError("evidence_directory_changed_during_sync", path)
        if os.name != "nt":
            sync_fd(directory_fd, "directory_sync_failed")


def sync_evidence_tree(root: Path) -> None:
    """Sync every file first, then directories bottom-up, without following links."""
    root = Path(root).absolute()
    directories = {}
    files = {}
    with secure_directory(root.parent) as (parent_fd, _parent_names):
        root_info = stat_child(root, parent_fd, root.name)
        if not stat.S_ISDIR(root_info.st_mode) or _is_reparse_point(root_info):
            raise FileVerificationError("evidence_root_not_directory", root)
        _sync_tree_files(root, root_info, parent_fd, root.name, directories, files)
        _sync_tree_directories(root, directories[os.path.normcase(os.path.abspath(str(root)))][1],
                               parent_fd, root.name, directories, files)
        root_after = stat_child(root, parent_fd, root.name)
        if not _same_file_state(root_info, root_after):
            raise FileVerificationError("evidence_root_changed_during_sync", root)
        if not _same_file_object(os.fstat(parent_fd), _path_stat(root.parent)):
            raise FileVerificationError("evidence_parent_changed_during_sync", root.parent)
        if os.name != "nt":
            sync_fd(parent_fd, "directory_sync_failed")


def normalize_link_target(target: str) -> Tuple[Optional[str], str]:
    """Return a deterministic POSIX representation for a safe relative link."""
    normalized = target.replace("\\", "/") if os.name == "nt" else target
    pure = PurePosixPath(normalized)
    windows_path = PureWindowsPath(target) if os.name == "nt" else None
    if (pure.is_absolute() or ".." in pure.parts
            or (windows_path is not None and (windows_path.is_absolute() or bool(windows_path.drive)))):
        return None, "omitted_unsafe"
    return pure.as_posix(), "reported"


def _safe_link_target(path: Path) -> Tuple[Optional[str], str]:
    try:
        target = os.readlink(path)
    except OSError:
        return None, "unavailable"
    return normalize_link_target(target)


def is_junction_entry(path: Path, info: Optional[os.stat_result] = None) -> bool:
    if os.name == "nt" and info is not None:
        return getattr(info, "st_reparse_tag", None) == WINDOWS_MOUNT_POINT_REPARSE_TAG
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        try:
            if is_junction():
                return True
        except OSError:
            pass
    if os.name == "nt":
        try:
            metadata = info if info is not None else path.lstat()
            return getattr(metadata, "st_reparse_tag", None) == WINDOWS_MOUNT_POINT_REPARSE_TAG
        except OSError:
            return False
    return False


def _role_and_producer(relative: str, step_ids: set) -> Tuple[str, str, bool]:
    parts = PurePosixPath(relative).parts
    classification_name = parts[-1]
    if classification_name.endswith(".writing"):
        classification_name = classification_name[:-len(".writing")]
        suffix = classification_name.rsplit(".", 1)
        if len(suffix) == 2 and len(suffix[1]) == 32 and all(c in "0123456789abcdef" for c in suffix[1].lower()):
            classification_name = suffix[0]
    if len(parts) == 1:
        role = ROOT_ROLES.get(classification_name)
        return (role or "unclassified", "runner", role is not None)
    if parts[0] in step_ids:
        role = STEP_ROLES.get(classification_name)
        # Formatter output uses the same explicit diagnostics artifacts; any
        # future parser output remains visible as unclassified.
        return (role or "unclassified", "step:" + parts[0], role is not None)
    return "unclassified", "runner", False


def _file_type(name: str) -> str:
    if name.endswith(".writing"):
        name = name[:-len(".writing")]
        suffix = name.rsplit(".", 1)
        if len(suffix) == 2 and len(suffix[1]) == 32 and all(c in "0123456789abcdef" for c in suffix[1].lower()):
            name = suffix[0]
    suffix = Path(name).suffix.lower()
    return {
        ".json": "json", ".jsonl": "jsonl", ".log": "text",
        ".txt": "text", ".bin": "binary",
    }.get(suffix, "unknown")


def _relative_path(root: Path, path: Path) -> Optional[str]:
    try:
        raw = os.path.relpath(str(path), str(root))
    except ValueError:
        return None
    posix = PurePosixPath(raw.replace("\\", "/"))
    if posix.is_absolute() or not posix.parts or any(part in ("", ".", "..") for part in posix.parts):
        return None
    return posix.as_posix()


def _is_link_entry(path: Path, info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode) or _is_reparse_point(info):
        return True
    return is_junction_entry(path, info)


def is_link_entry(path: Path, info: os.stat_result) -> bool:
    """Public no-follow classification used by provenance and the runner."""
    return _is_link_entry(path, info)


def _inventory_digest_payload(inventory: dict) -> dict:
    payload = {key: value for key, value in inventory.items() if key != "inventory_digest"}
    # See module docstring: the exact summary SHA remains in artifacts, but
    # this one field is normalized in the digest input to break the cycle.
    payload = json.loads(json.dumps(payload))
    for artifact in payload.get("artifacts", []):
        if artifact.get("path") == "summary.json" and artifact.get("role") == "run_summary":
            artifact["sha256"] = "<normalized-summary-self-reference>"
            artifact["digest_sha256_normalized"] = True
    return payload


def calculate_inventory_digest(inventory: dict) -> str:
    return hashlib.sha256(canonical_json_bytes(_inventory_digest_payload(inventory))).hexdigest()


def build_inventory(evidence_dir: Path, step_ids: Iterable[str] = ()) -> dict:
    """Traverse evidence without following links and hash stable regular files."""
    root = evidence_dir.absolute()
    steps = set(step_ids)
    artifacts: List[dict] = []
    issues: List[dict] = []

    def walk(directory: Path, expected: Optional[os.stat_result] = None,
             parent_fd: Optional[int] = None, name: Optional[str] = None) -> None:
        try:
            listing = secure_directory(directory, expected, parent_fd, name)
            with listing as (fd, child_names):
                _walk_children(directory, fd, child_names)
        except OSError as exc:
            relative = _relative_path(root, directory)
            code = getattr(exc, "code", "directory_unreadable")
            issues.append({
                "code": "directory_changed_before_traversal" if code.startswith("directory_changed") else code,
                "path": relative or ".", "severity": "error",
                "error_type": getattr(exc, "error_type", type(exc).__name__),
                "errno": exc.errno,
            })
    def _walk_children(directory: Path, fd: int, child_names: List[str]) -> None:
        for child_name in child_names:
            path = directory / child_name
            relative = _relative_path(root, path)
            if relative is None:
                issues.append({"code": "unsafe_artifact_path", "path": None})
                continue
            try:
                info = stat_child(path, fd, child_name)
            except OSError as exc:
                issues.append({
                    "code": "artifact_stat_failed", "path": relative,
                    "error_type": getattr(exc, "error_type", type(exc).__name__), "errno": exc.errno,
                })
                artifacts.append({
                    "path": relative, "role": "unclassified", "producer": "runner",
                    "file_type": _file_type(path.name), "entry_type": "unknown",
                    "size_bytes": None, "sha256": None, "status": "unreadable",
                    "hashing_status": "unreadable", "verification_status": "not_verified",
                })
                continue
            if _is_link_entry(path, info):
                try:
                    target = read_link(path, fd, child_name, info)
                    target, target_status = normalize_link_target(target)
                except OSError:
                    target, target_status = None, "unavailable"
                if is_junction_entry(path, info) and target_status == "reported":
                    # Junctions are detected without traversal, but the TAR
                    # representation is not guaranteed to preserve their kind.
                    target_status = "junction_unsupported"
                role, producer, _known = _role_and_producer(relative, steps)
                artifacts.append({
                    "path": relative, "role": role, "producer": producer,
                    "file_type": None, "entry_type": "symlink", "size_bytes": None,
                    "sha256": None, "status": "not_followed", "hashing_status": "not_followed",
                    "verification_status": "not_verified", "link_target": target,
                    "link_target_status": target_status,
                })
                issues.append({"code": "symlink_not_followed", "path": relative, "severity": "error"})
                continue
            if relative == INVENTORY_NAME and stat.S_ISREG(info.st_mode):
                continue
            if stat.S_ISDIR(info.st_mode):
                if relative == INVENTORY_NAME:
                    artifacts.append({
                        "path": relative, "role": "unclassified", "producer": "runner",
                        "file_type": None, "entry_type": "unexpected_directory", "size_bytes": None,
                        "sha256": None, "status": "not_followed", "hashing_status": "not_followed",
                        "verification_status": "not_verified",
                    })
                    issues.append({"code": "inventory_path_is_directory", "path": relative, "severity": "error"})
                    continue
                walk(path, info, fd, child_name)
                continue
            role, producer, known = _role_and_producer(relative, steps)
            if not stat.S_ISREG(info.st_mode):
                artifacts.append({
                    "path": relative, "role": role, "producer": producer,
                    "file_type": None, "entry_type": "non_regular", "size_bytes": None,
                    "sha256": None, "status": "not_followed", "hashing_status": "not_followed",
                    "verification_status": "not_verified",
                })
                issues.append({"code": "non_regular_entry_not_followed", "path": relative, "severity": "error"})
                continue
            sha256, size_bytes, status, issue = hash_regular_file(path, info, fd, child_name)
            artifact = {
                "path": relative, "role": role, "producer": producer,
                "file_type": _file_type(path.name), "entry_type": "regular",
                "size_bytes": size_bytes if size_bytes is not None else info.st_size,
                "sha256": sha256, "status": status,
                "hashing_status": status,
                "verification_status": "computed" if sha256 else "not_verified",
            }
            artifacts.append(artifact)
            if issue:
                issue_record = {key: value for key, value in issue.items() if key != "observed_sha256"}
                issues.append(dict(issue_record, path=relative, severity="error"))
            if relative.endswith(".writing"):
                artifact["status"] = "unfinished"
                artifact["unfinished_write"] = True
                issues.append({"code": "unfinished_atomic_write", "path": relative, "severity": "error"})
            if not known:
                issues.append({"code": "unclassified_artifact", "path": relative, "severity": "warning"})

    walk(root)
    artifacts.sort(key=lambda item: item["path"])
    issues.sort(key=lambda item: (item.get("path") or "", item.get("code", ""), item.get("severity", "")))
    incomplete = any(
        item.get("severity") == "error" or item.get("code") in {
            "artifact_unreadable", "artifact_changed_before_hash", "artifact_changed_while_hashing",
            "artifact_stat_failed", "directory_unreadable", "unsafe_artifact_path",
        }
        for item in issues
    ) or any(item.get("status") != "complete" for item in artifacts)
    result = {
        "schema_version": SCHEMA_VERSION,
        "status": "incomplete" if incomplete else "complete",
        "hash_algorithm": "sha256",
        "hash_block_size_bytes": HASH_BLOCK_SIZE,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "issues": issues,
        "self": {
            "path": INVENTORY_NAME,
            "hash_excluded": True,
            "reason": "The inventory excludes itself from artifact entries because its final bytes contain its digest.",
        },
        "digest_scope": {
            "summary_sha256": "normalized in the inventory digest to avoid the summary-to-inventory digest cycle; the artifact record retains the exact file SHA-256."
        },
    }
    result["inventory_digest"] = calculate_inventory_digest(result)
    return result

