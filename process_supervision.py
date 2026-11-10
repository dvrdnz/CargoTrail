#!/usr/bin/env python3
"""Cross-platform process-tree supervision for CargoTrail.

POSIX: one new session per command; terminate and verify the complete process
    group, not just the direct child.
Windows: one Job Object per command with KILL_ON_JOB_CLOSE; create the root
    process suspended, assign it to the Job Object, then resume it so every
    descendant is born inside the same Job Object.

This module deliberately fails closed on Windows if Job Object assignment is
not available. Falling back to terminating only the direct child would make
its process-tree guarantee false.
"""

# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from __future__ import annotations

import logging
import hashlib
import errno
import os
import ntpath
from datetime import datetime, timedelta, timezone
import signal
import subprocess
import sys
import shutil
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from artifact_inventory import open_regular_writer


class ProcessSupervisionError(RuntimeError):
    """The runner could not establish or complete process-tree supervision."""


class CancellationContext:
    """First-signal cancellation token shared by one agent invocation."""

    def __init__(self) -> None:
        self.signal_number: Optional[int] = None

    @property
    def signal_name(self) -> Optional[str]:
        if self.signal_number is None:
            return None
        try:
            return signal.Signals(self.signal_number).name
        except (ValueError, TypeError):
            return "SIGNAL_{}".format(self.signal_number)

    @property
    def cancelled(self) -> bool:
        return self.signal_number is not None

    def request(self, signal_number: int) -> None:
        # Signal handlers only perform this bounded assignment. The first
        # reason remains authoritative throughout cleanup and finalization.
        if self.signal_number is None:
            self.signal_number = signal_number


def _cancellation_reason(cancellation: Any) -> Tuple[Optional[int], Optional[str]]:
    if cancellation is None:
        return None, None
    number = getattr(cancellation, "signal_number", None)
    if number is None and not getattr(cancellation, "cancelled", False):
        return None, None
    if number is None:
        number = getattr(signal, "SIGINT", 2)
    name = getattr(cancellation, "signal_name", None)
    if not name:
        try:
            name = signal.Signals(number).name
        except (ValueError, TypeError):
            name = "SIGNAL_{}".format(number)
    return int(number), str(name)


LOGGER = logging.getLogger("cargotrail.process_supervision")


def _procfs_session_groups(session_id: int) -> Optional[set]:
    """Return live process groups belonging to a Linux session.

    This is stronger than checking only the session leader's process group:
    descendants may call setpgid() and move to another process group while
    remaining in the runner-owned session. Zombies are excluded because they
    cannot execute; ``None`` means procfs was unavailable/incomplete.
    """
    proc = Path("/proc")
    if not sys.platform.startswith("linux") or not proc.is_dir():
        return None
    groups = set()
    saw_stat = False
    try:
        entries = list(proc.iterdir())
    except OSError:
        return None
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "stat").read_text(encoding="utf-8")
            close = raw.rfind(")")
            if close < 0:
                continue
            fields = raw[close + 2 :].split()
            # fields: state, ppid, pgrp, session, ...
            if len(fields) < 4:
                continue
            saw_stat = True
            state = fields[0]
            process_group = int(fields[2])
            session = int(fields[3])
            if session == session_id and state not in {"Z", "X"}:
                groups.add(process_group)
        except (OSError, ValueError, IndexError):
            continue
    if saw_stat:
        return groups
    return None


def _ps_session_groups(session_id: int) -> Optional[set]:
    """Enumerate live process groups in a POSIX session without procfs.

    macOS's ``ps`` accepts the ``sess`` keyword but reports zero for it; it
    therefore cannot be used to identify POSIX sessions there. Enumerate PIDs
    and process groups owned by the current real UID, then obtain each session
    ID via ``getsid(2)`` (exposed by :func:`os.getsid`). Restricting the query
    avoids unrelated system and other-user processes whose session metadata
    the runner is not permitted to inspect. A process that exits during the
    scan is a normal race and is ignored. Any other lookup failure makes the
    snapshot incomplete: silently omitting a process would turn an unverified
    cleanup into a false success.
    """
    ps = shutil.which("ps")
    get_session_id = getattr(os, "getsid", None)
    if not ps or get_session_id is None:
        return None
    try:
        completed = subprocess.run(
            [ps, "-U", str(os.getuid()), "-o", "pid=,pgid=,stat="],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="ascii",
            errors="replace",
            timeout=2.0,
            check=False,
            close_fds=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None

    groups = set()
    saw_process_row = False
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) < 3:
            # A malformed process row means the inventory is not complete.
            return None
        saw_process_row = True
        try:
            pid = int(fields[0])
            process_group = int(fields[1])
        except ValueError:
            return None
        state = fields[2]
        if state.startswith(("Z", "X")):
            continue
        try:
            process_session = get_session_id(pid)
        except ProcessLookupError:
            # The process exited after ps took its snapshot.
            continue
        except OSError as exc:
            if exc.errno == errno.ESRCH:
                continue
            # EPERM and all other errors prevent proving the session is empty.
            return None
        if process_session == session_id:
            groups.add(process_group)
    # `ps` returning an empty list is not evidence that a process table was
    # successfully inventoried. Keep the snapshot unverified in that case.
    return groups if saw_process_row else None


def _posix_session_snapshot(session_id: int) -> Tuple[set, bool]:
    """Return (live process groups, complete_enumeration).

    Linux procfs and the macOS/BSD `ps` path provide a session-wide view.
    If both mechanisms fail, probe and supervise the initial process group as
    a best effort, but mark the snapshot incomplete. Callers must never turn
    that reduced visibility into a verified-success result.
    """
    groups = _procfs_session_groups(session_id)
    if groups is not None:
        return groups, True
    groups = _ps_session_groups(session_id)
    if groups is not None:
        return groups, True
    try:
        os.killpg(session_id, 0)
        return {session_id}, False
    except ProcessLookupError:
        return set(), False
    except PermissionError:
        return {session_id}, False
    except OSError:
        return {session_id}, False


def _posix_session_groups(session_id: int) -> set:
    # Convenience view retained for diagnostics and focused tests. Safety
    # decisions use the completeness bit from _posix_session_snapshot().
    return _posix_session_snapshot(session_id)[0]


def _send_posix_session_signal(session_id: int, sig: int) -> List[str]:
    errors = []
    groups = _posix_session_groups(session_id)
    # Always probe the initial group too: a process may have appeared between
    # the /proc snapshot and the signal pass.
    groups.add(session_id)
    for pgid in sorted(groups):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            pass
        except OSError as exc:
            errors.append("pgid {}: {}: {}".format(pgid, type(exc).__name__, exc))
    return errors


def _wait_posix_session_empty(session_id: int, process: subprocess.Popen, timeout: float) -> bool:
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        try:
            process.poll()
        except OSError:
            pass
        groups, enumeration_complete = _posix_session_snapshot(session_id)
        if not groups and enumeration_complete:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.05, remaining))


def _run_cleanup_uninterruptibly(function, *args):
    """Finish process-tree cleanup even if the user repeats a stop signal."""
    previous_handlers = {}
    try:
        for name in ("SIGINT", "SIGTERM", "SIGHUP"):
            sig = getattr(signal, name, None)
            if sig is None:
                continue
            try:
                previous_handlers[sig] = signal.signal(sig, signal.SIG_IGN)
            except (ValueError, OSError):
                # signal.signal is restricted to the main thread. A library
                # caller on another thread still gets the normal cleanup try.
                continue
        return function(*args)
    except KeyboardInterrupt:
        # Covers the narrow race where Ctrl+C arrived immediately before the
        # temporary ignore handler was installed.
        if signal.SIGINT not in previous_handlers:
            try:
                previous_handlers[signal.SIGINT] = signal.signal(signal.SIGINT, signal.SIG_IGN)
            except ValueError:
                raise
        return function(*args)
    finally:
        for sig, previous_handler in reversed(list(previous_handlers.items())):
            try:
                signal.signal(sig, previous_handler)
            except (ValueError, OSError):
                pass


def _posix_cleanup(
    process: subprocess.Popen,
    session_id: int,
    grace_seconds: float,
    reason: str,
) -> Dict[str, Any]:
    """Terminate every process group in the owned session and verify exit."""
    result: Dict[str, Any] = {
        "supervision": "posix-session-process-groups",
        "trigger": reason,
        "descendants_detected": reason == "orphaned-descendants",
        "term_signal_sent": False,
        "kill_signal_sent": False,
        "cleanup_complete": True,
        "active_members_after_cleanup": 0,
        "process_groups_signalled": [],
        "errors": [],
    }
    current_groups, enumeration_complete = _posix_session_snapshot(session_id)
    LOGGER.warning(
        "POSIX process-tree cleanup started: session_id=%s trigger=%s process_pid=%s groups=%s enumeration_complete=%s",
        session_id, reason, process.pid, sorted(current_groups), enumeration_complete,
    )
    if not enumeration_complete:
        LOGGER.error("POSIX session enumeration incomplete: session_id=%s", session_id)
        result["errors"].append(
            "session-wide process enumeration unavailable; only the initial process group can be supervised"
        )
    if not current_groups:
        try:
            process.wait(timeout=max(0.1, grace_seconds))
        except subprocess.TimeoutExpired:
            result["cleanup_complete"] = False
            result["errors"].append("direct child did not exit after its session disappeared")
        result["cleanup_complete"] = bool(result["cleanup_complete"] and enumeration_complete)
        result["active_members_after_cleanup"] = 0 if result["cleanup_complete"] else None
        return result

    result["process_groups_signalled"] = sorted(current_groups | {session_id})
    term_errors = _send_posix_session_signal(session_id, signal.SIGTERM)
    result["term_signal_sent"] = not term_errors
    LOGGER.info(
        "POSIX SIGTERM sent: session_id=%s groups=%s errors=%d",
        session_id, result["process_groups_signalled"], len(term_errors),
    )
    result["errors"].extend("SIGTERM " + item for item in term_errors)

    if not _wait_posix_session_empty(session_id, process, grace_seconds):
        LOGGER.warning(
            "POSIX grace period expired; escalating to SIGKILL: session_id=%s grace_seconds=%s",
            session_id, grace_seconds,
        )
        # Re-scan and re-send SIGKILL until the whole session is empty. This
        # closes the race where a process forks or changes process group while
        # the initial signal snapshot is being delivered.
        forced_deadline = time.monotonic() + max(2.0, min(5.0, grace_seconds))
        kill_errors = []
        while True:
            current_groups, current_enumeration_complete = _posix_session_snapshot(session_id)
            if not current_groups and current_enumeration_complete:
                break
            # Even with an incomplete snapshot, keep trying the original
            # process group. This is best effort only; the final result remains
            # unverified and therefore cannot be reported as success.
            result["process_groups_signalled"] = sorted(
                set(result["process_groups_signalled"]) | current_groups | {session_id}
            )
            current_errors = _send_posix_session_signal(session_id, signal.SIGKILL)
            result["kill_signal_sent"] = result["kill_signal_sent"] or not current_errors
            kill_errors.extend(current_errors)
            process.poll()
            remaining = forced_deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(0.05, remaining))
        result["errors"].extend("SIGKILL " + item for item in kill_errors)
        LOGGER.info(
            "POSIX SIGKILL phase finished: session_id=%s groups=%s signal_errors=%d",
            session_id, result["process_groups_signalled"], len(kill_errors),
        )
        if _posix_session_groups(session_id):
            result["cleanup_complete"] = False
            result["errors"].append("owned session still has live members after SIGKILL")

    try:
        process.wait(timeout=max(1.0, min(5.0, grace_seconds + 1.0)))
    except subprocess.TimeoutExpired:
        result["cleanup_complete"] = False
        result["errors"].append("direct child could not be reaped after termination")
    except OSError as exc:
        result["cleanup_complete"] = False
        result["errors"].append("wait: {}: {}".format(type(exc).__name__, exc))

    final_groups, final_enumeration_complete = _posix_session_snapshot(session_id)
    still_live = bool(final_groups)
    result["active_members_after_cleanup"] = None if (still_live or not final_enumeration_complete) else 0
    if still_live or not final_enumeration_complete:
        result["cleanup_complete"] = False
        if not final_enumeration_complete:
            result["errors"].append("final process-tree state could not be fully verified")
    LOGGER.log(
        logging.INFO if result["cleanup_complete"] else logging.ERROR,
        "POSIX process-tree cleanup finished: session_id=%s cleanup_complete=%s active_members=%s errors=%s",
        session_id, result["cleanup_complete"], result["active_members_after_cleanup"], result["errors"],
    )
    return result


class _WindowsNativeApi:
    """Typed Win32 API and structures used by the owned-handle backend."""

    CREATE_SUSPENDED = 0x00000004
    CREATE_NEW_PROCESS_GROUP = 0x00000200
    CREATE_UNICODE_ENVIRONMENT = 0x00000400
    EXTENDED_STARTUPINFO_PRESENT = 0x00080000
    STARTF_USESTDHANDLES = 0x00000100
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
    DUPLICATE_SAME_ACCESS = 0x00000002
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
    JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION = 1
    JOB_OBJECT_BASIC_PROCESS_ID_LIST = 3
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    SYNCHRONIZE = 0x00100000
    WAIT_OBJECT_0 = 0
    WAIT_TIMEOUT = 258
    WAIT_FAILED = 0xFFFFFFFF
    INFINITE = 0xFFFFFFFF
    STILL_ACTIVE = 259
    ERROR_INSUFFICIENT_BUFFER = 122
    ERROR_MORE_DATA = 234
    TH32CS_SNAPPROCESS = 0x00000002

    def __init__(self) -> None:
        if os.name != "nt":
            raise ProcessSupervisionError("Windows process supervision is only available on Windows")
        import ctypes
        from ctypes import wintypes

        self.ctypes = ctypes
        self.wintypes = wintypes
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._define_structures()
        self._declare_api()

    def _define_structures(self) -> None:
        ctypes, wintypes = self.ctypes, self.wintypes

        class BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )]

        class EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        class BASIC_ACCOUNTING_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("TotalUserTime", ctypes.c_longlong),
                ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wintypes.DWORD),
                ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD),
                ("TotalTerminatedProcesses", wintypes.DWORD),
            ]

        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        class STARTUPINFOW(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
                ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE),
            ]

        class STARTUPINFOEXW(ctypes.Structure):
            _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
            ]

        self.EXTENDED_LIMIT_INFORMATION = EXTENDED_LIMIT_INFORMATION
        self.BASIC_ACCOUNTING_INFORMATION = BASIC_ACCOUNTING_INFORMATION
        self.FILETIME = FILETIME
        self.PROCESSENTRY32W = PROCESSENTRY32W
        self.STARTUPINFOEXW = STARTUPINFOEXW
        self.PROCESS_INFORMATION = PROCESS_INFORMATION

    def _declare_api(self) -> None:
        c, w, k = self.ctypes, self.wintypes, self.kernel32
        k.CreateJobObjectW.argtypes = [c.c_void_p, w.LPCWSTR]
        k.CreateJobObjectW.restype = w.HANDLE
        k.SetInformationJobObject.argtypes = [w.HANDLE, w.INT, c.c_void_p, w.DWORD]
        k.SetInformationJobObject.restype = w.BOOL
        k.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        k.AssignProcessToJobObject.restype = w.BOOL
        k.ResumeThread.argtypes = [w.HANDLE]
        k.ResumeThread.restype = w.DWORD
        k.QueryInformationJobObject.argtypes = [w.HANDLE, w.INT, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
        k.QueryInformationJobObject.restype = w.BOOL
        k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        k.OpenProcess.restype = w.HANDLE
        k.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
        k.QueryFullProcessImageNameW.restype = w.BOOL
        k.GetProcessTimes.argtypes = [
            w.HANDLE, c.POINTER(self.FILETIME), c.POINTER(self.FILETIME),
            c.POINTER(self.FILETIME), c.POINTER(self.FILETIME),
        ]
        k.GetProcessTimes.restype = w.BOOL
        k.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
        k.CreateToolhelp32Snapshot.restype = w.HANDLE
        k.Process32FirstW.argtypes = [w.HANDLE, c.POINTER(self.PROCESSENTRY32W)]
        k.Process32FirstW.restype = w.BOOL
        k.Process32NextW.argtypes = [w.HANDLE, c.POINTER(self.PROCESSENTRY32W)]
        k.Process32NextW.restype = w.BOOL
        k.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
        k.TerminateJobObject.restype = w.BOOL
        k.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
        k.TerminateProcess.restype = w.BOOL
        k.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        k.WaitForSingleObject.restype = w.DWORD
        k.GetExitCodeProcess.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
        k.GetExitCodeProcess.restype = w.BOOL
        k.CloseHandle.argtypes = [w.HANDLE]
        k.CloseHandle.restype = w.BOOL
        k.GetCurrentProcess.argtypes = []
        k.GetCurrentProcess.restype = w.HANDLE
        k.DuplicateHandle.argtypes = [w.HANDLE, w.HANDLE, w.HANDLE, c.POINTER(w.HANDLE), w.DWORD, w.BOOL, w.DWORD]
        k.DuplicateHandle.restype = w.BOOL
        k.InitializeProcThreadAttributeList.argtypes = [c.c_void_p, w.DWORD, w.DWORD, c.POINTER(c.c_size_t)]
        k.InitializeProcThreadAttributeList.restype = w.BOOL
        k.UpdateProcThreadAttribute.argtypes = [c.c_void_p, w.DWORD, c.c_size_t, c.c_void_p,
                                                c.c_size_t, c.c_void_p, c.c_void_p]
        k.UpdateProcThreadAttribute.restype = w.BOOL
        k.DeleteProcThreadAttributeList.argtypes = [c.c_void_p]
        k.DeleteProcThreadAttributeList.restype = None
        k.CreateProcessW.argtypes = [w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL,
                                     w.DWORD, c.c_void_p, w.LPCWSTR,
                                     c.POINTER(self.STARTUPINFOEXW), c.POINTER(self.PROCESS_INFORMATION)]
        k.CreateProcessW.restype = w.BOOL
        k.GenerateConsoleCtrlEvent.argtypes = [w.DWORD, w.DWORD]
        k.GenerateConsoleCtrlEvent.restype = w.BOOL

    def error(self, operation: str, code: Optional[int] = None) -> "_WindowsApiError":
        if code is None:
            code = self.ctypes.get_last_error()
        return _WindowsApiError(operation, int(code), str(self.ctypes.WinError(code)))


class _WindowsApiError(ProcessSupervisionError):
    def __init__(self, operation: str, code: int, detail: str):
        self.operation = operation
        self.code = code
        super().__init__("{} failed (Windows error {}): {}".format(operation, code, detail))


class _WindowsProcess:
    """Owns the process and primary-thread handles returned by CreateProcessW."""

    def __init__(self, api: _WindowsNativeApi, process_handle: Any, thread_handle: Any,
                 pid: int, command: List[str]):
        self.api = api
        self.process_handle = process_handle
        self.thread_handle = thread_handle
        self.pid = int(pid)
        self.process_group_id = int(pid)
        self.command = list(command)
        self.returncode = None

    def wait(self, timeout: Optional[float] = None) -> int:
        milliseconds = self.api.INFINITE if timeout is None else max(0, min(0xFFFFFFFE, int(timeout * 1000)))
        status = int(self.api.kernel32.WaitForSingleObject(self.process_handle, milliseconds))
        if status == self.api.WAIT_TIMEOUT:
            raise subprocess.TimeoutExpired(self.command, timeout)
        if status == self.api.WAIT_FAILED:
            raise self.api.error("WaitForSingleObject(process)")
        if status != self.api.WAIT_OBJECT_0:
            raise ProcessSupervisionError("Unexpected process wait status: {}".format(status))
        code = self.api.wintypes.DWORD()
        if not self.api.kernel32.GetExitCodeProcess(self.process_handle, self.api.ctypes.byref(code)):
            raise self.api.error("GetExitCodeProcess")
        if int(code.value) == self.api.STILL_ACTIVE:
            raise ProcessSupervisionError("Process wait signaled while GetExitCodeProcess reports STILL_ACTIVE")
        self.returncode = int(code.value)
        return self.returncode

    def poll(self) -> Optional[int]:
        if self.returncode is not None:
            return self.returncode
        try:
            return self.wait(timeout=0)
        except subprocess.TimeoutExpired:
            return None

    def terminate(self, exit_code: int = 1) -> bool:
        return bool(self.api.kernel32.TerminateProcess(self.process_handle, exit_code))

    def send_ctrl_break(self) -> bool:
        return bool(self.api.kernel32.GenerateConsoleCtrlEvent(1, self.process_group_id))

    def close(self) -> List[str]:
        errors = []
        # Clear ownership before each call so no outer cleanup path can close
        # the same native handle a second time.
        for attr, name in (("thread_handle", "primary thread"), ("process_handle", "process")):
            handle = getattr(self, attr)
            if not handle:
                continue
            setattr(self, attr, None)
            try:
                if not self.api.kernel32.CloseHandle(handle):
                    errors.append(str(self.api.error("CloseHandle({})".format(name))))
            except Exception as exc:
                errors.append("CloseHandle({}) raised {}: {}".format(name, type(exc).__name__, exc))
        return errors


class _WindowsJob:
    """Owns one kill-on-close Job Object and verifies its active process count."""

    def __init__(self, api: Optional[_WindowsNativeApi] = None) -> None:
        self.api = api or _WindowsNativeApi()
        self.handle = None
        handle = self.api.kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise self.api.error("CreateJobObjectW")
        self.handle = handle
        try:
            limits = self.api.EXTENDED_LIMIT_INFORMATION()
            limits.BasicLimitInformation.LimitFlags = self.api.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not self.api.kernel32.SetInformationJobObject(
                self.handle, self.api.JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                self.api.ctypes.byref(limits), self.api.ctypes.sizeof(limits),
            ):
                raise self.api.error("SetInformationJobObject(KILL_ON_JOB_CLOSE)")
        except BaseException as error:
            close_errors = self.close()
            try:
                error.job_created = True
                error.job_cleanup_verified = not close_errors
            except Exception:
                pass
            if close_errors:
                failure = ProcessSupervisionError("{}; {}".format(error, "; ".join(close_errors)))
                failure.job_created = True
                failure.job_cleanup_verified = False
                raise failure from error
            raise
        LOGGER.debug("Windows Job Object created and configured with KILL_ON_JOB_CLOSE")

    def assign(self, process: _WindowsProcess) -> None:
        if not self.api.kernel32.AssignProcessToJobObject(self.handle, process.process_handle):
            raise self.api.error("AssignProcessToJobObject")

    def resume(self, process: _WindowsProcess) -> None:
        previous_count = int(self.api.kernel32.ResumeThread(process.thread_handle))
        if previous_count == self.api.WAIT_FAILED:
            raise self.api.error("ResumeThread")
        if previous_count != 1:
            raise ProcessSupervisionError(
                "ResumeThread returned unexpected previous suspend count {}; expected 1".format(previous_count)
            )

    def terminate(self, exit_code: int = 1) -> bool:
        return bool(self.api.kernel32.TerminateJobObject(self.handle, exit_code))

    def active_processes(self) -> int:
        info = self.api.BASIC_ACCOUNTING_INFORMATION()
        returned = self.api.wintypes.DWORD(0)
        ok = self.api.kernel32.QueryInformationJobObject(
            self.handle, self.api.JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION,
            self.api.ctypes.byref(info), self.api.ctypes.sizeof(info), self.api.ctypes.byref(returned),
        )
        if not ok:
            raise self.api.error("QueryInformationJobObject(BasicAccountingInformation)")
        return int(info.ActiveProcesses)

    def active_process_details(self) -> List[Dict[str, Any]]:
        ctypes, wintypes = self.api.ctypes, self.api.wintypes
        header_size = ctypes.sizeof(wintypes.DWORD) * 2
        pointer_size = ctypes.sizeof(ctypes.c_size_t)
        capacity = max(1, self.active_processes())
        for _attempt in range(4):
            buffer = ctypes.create_string_buffer(header_size + capacity * pointer_size)
            returned = wintypes.DWORD(0)
            ok = self.api.kernel32.QueryInformationJobObject(
                self.handle, self.api.JOB_OBJECT_BASIC_PROCESS_ID_LIST,
                buffer, ctypes.sizeof(buffer), ctypes.byref(returned),
            )
            assigned = wintypes.DWORD.from_buffer(buffer, 0).value
            count = wintypes.DWORD.from_buffer(buffer, ctypes.sizeof(wintypes.DWORD)).value
            if not ok:
                error = ctypes.get_last_error()
                if error == self.api.ERROR_MORE_DATA:
                    capacity = max(assigned, capacity * 2)
                    continue
                raise self.api.error("QueryInformationJobObject(BasicProcessIdList)", error)
            process_ids = [
                int(ctypes.c_size_t.from_buffer(buffer, header_size + index * pointer_size).value)
                for index in range(min(count, capacity))
            ]
            parent_ids = self._process_parent_ids()
            observed_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            return [
                self._process_name(process_id, parent_ids.get(process_id), observed_at)
                for process_id in process_ids
            ]
        raise ProcessSupervisionError("Job Object process list changed during repeated queries")

    def _process_parent_ids(self) -> Dict[int, int]:
        """Take a best-effort Toolhelp snapshot for parent-PID diagnostics.

        This metadata is diagnostic only: a Toolhelp failure must never change
        the authoritative Job Object membership or cleanup result.
        """
        ctypes = self.api.ctypes
        snapshot = None
        try:
            snapshot = self.api.kernel32.CreateToolhelp32Snapshot(self.api.TH32CS_SNAPPROCESS, 0)
            invalid_handle = ctypes.c_void_p(-1).value
            if not snapshot or snapshot == invalid_handle:
                snapshot = None
                return {}
            entry = self.api.PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(entry)
            if not self.api.kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
                return {}
            parents = {}
            while True:
                parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
                if not self.api.kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    break
            return parents
        except Exception:
            return {}
        finally:
            if snapshot:
                try:
                    self.api.kernel32.CloseHandle(snapshot)
                except Exception:
                    pass

    def _process_name(
        self, process_id: int, parent_process_id: Optional[int] = None,
        observed_at_utc: Optional[str] = None,
    ) -> Dict[str, Any]:
        ctypes, wintypes = self.api.ctypes, self.api.wintypes
        details: Dict[str, Any] = {
            "pid": process_id,
            "parent_pid": parent_process_id,
            "name": "<unavailable>",
            "image_path": None,
            "process_created_at_utc": None,
            "observed_at_utc": observed_at_utc,
            "process_handle_state": "unavailable",
            # QueryInformationJobObject's active PID list is authoritative here;
            # this does not claim to expose the scheduler's run/wait state.
            "job_membership": "active",
        }
        query_access = self.api.PROCESS_QUERY_LIMITED_INFORMATION
        handle = self.api.kernel32.OpenProcess(
            query_access | self.api.SYNCHRONIZE, False, process_id,
        )
        wait_capable = bool(handle)
        if not handle:
            # Keep image/start-time diagnostics even where the process DACL
            # permits querying but denies SYNCHRONIZE access.
            handle = self.api.kernel32.OpenProcess(query_access, False, process_id)
        if not handle:
            return details
        try:
            if wait_capable:
                wait_result = self.api.kernel32.WaitForSingleObject(handle, 0)
                if wait_result == self.api.WAIT_TIMEOUT:
                    details["process_handle_state"] = "active"
                elif wait_result == self.api.WAIT_OBJECT_0:
                    details["process_handle_state"] = "signaled"
                else:
                    details["process_handle_state"] = "unknown"

            capacity = 32768
            image = ctypes.create_unicode_buffer(capacity)
            length = wintypes.DWORD(capacity)
            if self.api.kernel32.QueryFullProcessImageNameW(
                handle, 0, image, ctypes.byref(length),
            ):
                details["image_path"] = image.value
                details["name"] = ntpath.basename(image.value)

            created = self.api.FILETIME()
            exited = self.api.FILETIME()
            kernel = self.api.FILETIME()
            user = self.api.FILETIME()
            if self.api.kernel32.GetProcessTimes(
                handle, ctypes.byref(created), ctypes.byref(exited),
                ctypes.byref(kernel), ctypes.byref(user),
            ):
                ticks = (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)
                created_at = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
                details["process_created_at_utc"] = created_at.isoformat(timespec="milliseconds").replace(
                    "+00:00", "Z",
                )
            return details
        finally:
            self.api.kernel32.CloseHandle(handle)

    def wait_empty(self, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            if self.active_processes() == 0:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.05, remaining))

    def terminate_tree(self, process: _WindowsProcess, grace_seconds: float, reason: str) -> Dict[str, Any]:
        LOGGER.warning("Windows Job Object cleanup started: pid=%s trigger=%s", process.pid, reason)
        result: Dict[str, Any] = {
            "supervision": "windows-job-object", "trigger": reason,
            "descendants_detected": reason == "orphaned-descendants",
            "term_signal_sent": False, "kill_signal_sent": False,
            "cleanup_complete": False, "active_members_after_cleanup": None,
            "root_process_exited": False, "job_empty": False, "cleanup_verified": False,
            "errors": [],
        }
        try:
            result["term_signal_sent"] = process.send_ctrl_break()
            if not result["term_signal_sent"]:
                result["errors"].append(
                    "CTRL_BREAK: {}".format(self.api.error("GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT)"))
                )
        except Exception as exc:
            result["errors"].append("CTRL_BREAK: {}: {}".format(type(exc).__name__, exc))

        try:
            empty = self.wait_empty(grace_seconds)
        except Exception as exc:
            result["errors"].append("grace-period job verification: {}: {}".format(type(exc).__name__, exc))
            empty = False
        if not empty:
            LOGGER.warning("Windows Job Object grace period expired; terminating job: pid=%s", process.pid)
            try:
                result["kill_signal_sent"] = self.terminate(1)
                if not result["kill_signal_sent"]:
                    result["errors"].append(
                        "TerminateJobObject failed: {}".format(self.api.error("TerminateJobObject"))
                    )
            except Exception as exc:
                result["errors"].append("TerminateJobObject: {}: {}".format(type(exc).__name__, exc))
            try:
                self.wait_empty(5.0)
            except Exception as exc:
                result["errors"].append("post-termination job verification: {}: {}".format(type(exc).__name__, exc))

        try:
            process.wait(timeout=5.0)
            result["root_process_exited"] = True
        except Exception as exc:
            result["errors"].append("root process exit verification: {}: {}".format(type(exc).__name__, exc))
        try:
            active = self.active_processes()
            result["active_members_after_cleanup"] = active
            result["job_empty"] = active == 0
        except Exception as exc:
            result["errors"].append("final job verification: {}: {}".format(type(exc).__name__, exc))
        result["cleanup_verified"] = bool(result["root_process_exited"] and result["job_empty"])
        result["cleanup_complete"] = result["cleanup_verified"]
        if not result["job_empty"]:
            result["errors"].append("Job Object still reports active processes after termination")
        if not result["root_process_exited"]:
            result["errors"].append("root process exit could not be verified")
        fatal_errors = [error for error in result["errors"] if not error.startswith("CTRL_BREAK:")]
        if fatal_errors:
            result["supervision_error"] = "; ".join(fatal_errors)
        LOGGER.log(
            logging.INFO if result["cleanup_complete"] else logging.ERROR,
            "Windows Job Object cleanup checked: pid=%s cleanup_complete=%s active_members=%s errors=%s",
            process.pid, result["cleanup_complete"], result["active_members_after_cleanup"], result["errors"],
        )
        return result

    def after_leader_exit(self, process: _WindowsProcess, grace_seconds: float) -> Dict[str, Any]:
        try:
            active = self.active_processes()
        except Exception as exc:
            return {
                "supervision": "windows-job-object", "trigger": "verification-error",
                "descendants_detected": None, "term_signal_sent": False, "kill_signal_sent": False,
                "cleanup_complete": False, "active_members_after_cleanup": None,
                "root_process_exited": process.returncode is not None, "job_empty": False,
                "cleanup_verified": False, "errors": [str(exc)],
            }
        if active:
            try:
                if self.wait_empty(grace_seconds):
                    active = 0
            except Exception as exc:
                LOGGER.warning(
                    "Windows Job Object drain check failed after leader exit: pid=%s error=%s",
                    process.pid, exc,
                )
        if active:
            try:
                members = self.active_process_details()
                LOGGER.warning(
                    "Windows Job Object still has processes after leader exit: pid=%s members=%s",
                    process.pid, members,
                )
            except Exception as exc:
                LOGGER.warning(
                    "Windows Job Object process enumeration failed after leader exit: pid=%s error=%s",
                    process.pid, exc,
                )
        if active == 0:
            return {
                "supervision": "windows-job-object", "trigger": None,
                "descendants_detected": False, "term_signal_sent": False, "kill_signal_sent": False,
                "cleanup_complete": process.returncode is not None, "active_members_after_cleanup": 0,
                "root_process_exited": process.returncode is not None, "job_empty": True,
                "cleanup_verified": process.returncode is not None, "errors": [],
            }
        return self.terminate_tree(process, grace_seconds, "orphaned-descendants")

    def close(self) -> List[str]:
        if not self.handle:
            return []
        handle = self.handle
        try:
            if self.api.kernel32.CloseHandle(handle):
                self.handle = None
                return []
            errors = [str(self.api.error("CloseHandle(Job Object)"))]
        except Exception as exc:
            errors = ["CloseHandle(Job Object) raised {}: {}".format(type(exc).__name__, exc)]
        # CloseHandle failed, so keep using the still-owned Job Object handle
        # for one final termination and state check. Do not retry CloseHandle:
        # every owned handle has one release attempt and the failure is surfaced.
        try:
            if not self.terminate(1):
                errors.append(str(self.api.error("TerminateJobObject(after close failure)")))
        except Exception as exc:
            errors.append("TerminateJobObject(after close failure): {}: {}".format(type(exc).__name__, exc))
        try:
            if not self.wait_empty(5.0):
                errors.append("Job Object remained active after CloseHandle failure")
        except Exception as exc:
            errors.append("job state verification after CloseHandle failure: {}: {}".format(
                type(exc).__name__, exc,
            ))
        self.handle = None
        return errors


class _WindowsSpawnFailure(ProcessSupervisionError):
    def __init__(self, stage: str, error: BaseException, startup: Dict[str, Any],
                 process_tree: Dict[str, Any], launch_failure: bool = False):
        self.stage = stage
        self.error = error
        self.startup = dict(startup)
        self.process_tree = process_tree
        self.launch_failure = launch_failure
        super().__init__("{}: {}: {}".format(stage, type(error).__name__, error))


def _resolve_windows_executable(command: List[str], cwd: Path, env: dict) -> str:
    if not command or not command[0]:
        raise FileNotFoundError("empty executable name")
    executable = str(command[0])
    import ntpath
    has_path = bool(ntpath.splitdrive(executable)[0] or "/" in executable or "\\" in executable)
    if has_path:
        path = Path(executable)
        if not path.is_absolute():
            path = cwd / path
        resolved = path.resolve(strict=True)
        if not resolved.is_file():
            raise FileNotFoundError("executable is not a file: {}".format(resolved))
        return str(resolved)
    resolved = shutil.which(executable, path=env.get("PATH", os.defpath))
    if not resolved:
        raise FileNotFoundError("executable not found on PATH: {}".format(executable))
    return str(Path(resolved).resolve(strict=True))


def _windows_environment_block(env: dict, ctypes: Any) -> Any:
    entries = []
    seen = set()
    for key, value in env.items():
        key, value = str(key), str(value)
        if "\0" in key or "\0" in value or ("=" in key and not key.startswith("=")):
            raise ValueError("invalid Windows environment entry: {!r}".format(key))
        folded = key.casefold()
        if folded in seen:
            raise ValueError("duplicate case-insensitive Windows environment key: {!r}".format(key))
        seen.add(folded)
        entries.append((folded, "{}={}".format(key, value)))
    block = "\0".join(item[1] for item in sorted(entries, key=lambda item: item[0])) + "\0\0"
    return ctypes.create_unicode_buffer(block)


def _windows_create_process(api: _WindowsNativeApi, command: List[str], cwd: Path, env: dict,
                            stdout: Any, stderr: Any) -> _WindowsProcess:
    """Create the root suspended, passing only duplicated standard handles."""
    import msvcrt
    c, w, k = api.ctypes, api.wintypes, api.kernel32
    duplicate_handles = []
    attribute_list = None
    attribute_list_initialized = False
    process = None
    errors = []
    try:
        with open(os.devnull, "rb", buffering=0) as stdin_file:
            source_handles = [
                msvcrt.get_osfhandle(stdin_file.fileno()),
                msvcrt.get_osfhandle(stdout.fileno()),
                msvcrt.get_osfhandle(stderr.fileno()),
            ]
            child_handles = (w.HANDLE * 3)()
            current = k.GetCurrentProcess()
            for index, source in enumerate(source_handles):
                target = w.HANDLE()
                if not k.DuplicateHandle(current, w.HANDLE(source), current, c.byref(target),
                                         0, True, api.DUPLICATE_SAME_ACCESS):
                    raise api.error("DuplicateHandle(standard handle {})".format(index))
                duplicate_handles.append(target)
                child_handles[index] = target

            size = c.c_size_t(0)
            k.InitializeProcThreadAttributeList(None, 1, 0, c.byref(size))
            first_error = c.get_last_error()
            if not size.value or first_error != api.ERROR_INSUFFICIENT_BUFFER:
                raise api.error("InitializeProcThreadAttributeList(size query)", first_error)
            attribute_storage = c.create_string_buffer(size.value)
            attribute_list = c.cast(attribute_storage, c.c_void_p)
            if not k.InitializeProcThreadAttributeList(attribute_list, 1, 0, c.byref(size)):
                raise api.error("InitializeProcThreadAttributeList")
            attribute_list_initialized = True
            if not k.UpdateProcThreadAttribute(
                attribute_list, 0, api.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                c.cast(child_handles, c.c_void_p), c.sizeof(child_handles), None, None,
            ):
                raise api.error("UpdateProcThreadAttribute(HANDLE_LIST)")

            executable = _resolve_windows_executable(command, cwd, env)
            mutable_command = c.create_unicode_buffer(subprocess.list2cmdline([str(arg) for arg in command]))
            environment = _windows_environment_block(env, c)
            startup = api.STARTUPINFOEXW()
            startup.StartupInfo.cb = c.sizeof(api.STARTUPINFOEXW)
            startup.StartupInfo.dwFlags = api.STARTF_USESTDHANDLES
            startup.StartupInfo.hStdInput = child_handles[0]
            startup.StartupInfo.hStdOutput = child_handles[1]
            startup.StartupInfo.hStdError = child_handles[2]
            startup.lpAttributeList = attribute_list
            information = api.PROCESS_INFORMATION()
            flags = (api.CREATE_SUSPENDED | api.CREATE_NEW_PROCESS_GROUP |
                     api.EXTENDED_STARTUPINFO_PRESENT | api.CREATE_UNICODE_ENVIRONMENT)
            if not k.CreateProcessW(
                executable, mutable_command, None, None, True, flags, environment,
                str(cwd), c.byref(startup), c.byref(information),
            ):
                raise api.error("CreateProcessW")
            process_handle = information.hProcess
            thread_handle = information.hThread
            if not process_handle or not thread_handle or not information.dwProcessId:
                for handle, label in ((thread_handle, "primary thread"), (process_handle, "process")):
                    if handle and not k.CloseHandle(handle):
                        errors.append(str(api.error("CloseHandle(invalid PROCESS_INFORMATION {})".format(label))))
                raise ProcessSupervisionError("CreateProcessW succeeded with invalid PROCESS_INFORMATION handles")
            process = _WindowsProcess(api, process_handle, thread_handle,
                                      int(information.dwProcessId), command)
    except BaseException as exc:
        primary_error = exc
    else:
        primary_error = None
    finally:
        if attribute_list_initialized:
            try:
                k.DeleteProcThreadAttributeList(attribute_list)
            except Exception as exc:
                errors.append("DeleteProcThreadAttributeList raised {}: {}".format(type(exc).__name__, exc))
        for index, handle in enumerate(reversed(duplicate_handles)):
            try:
                if not k.CloseHandle(handle):
                    errors.append(str(api.error("CloseHandle(temporary standard handle {})".format(index))))
            except Exception as exc:
                errors.append("CloseHandle(temporary standard handle {}) raised {}: {}".format(
                    index, type(exc).__name__, exc,
                ))

    if primary_error is not None:
        if errors:
            failure = ProcessSupervisionError(
                "{}; resource cleanup failed: {}".format(primary_error, "; ".join(errors))
            )
            failure.process = process
            failure.resource_cleanup_failed = True
            failure.launch_failure = (
                isinstance(primary_error, FileNotFoundError)
                or isinstance(primary_error, _WindowsApiError) and primary_error.operation == "CreateProcessW"
            )
            raise failure from primary_error
        if isinstance(primary_error, _WindowsApiError) and primary_error.operation == "CreateProcessW":
            setattr(primary_error, "process", None)
        else:
            try:
                setattr(primary_error, "process", process)
                if process is not None:
                    setattr(primary_error, "resource_cleanup_failed", True)
            except Exception:
                failure = ProcessSupervisionError(
                    "{}; process handle could not be transferred for cleanup".format(primary_error)
                )
                failure.process = process
                failure.resource_cleanup_failed = process is None
                raise failure from primary_error
        raise primary_error
    if errors:
        failure = ProcessSupervisionError("; ".join(errors))
        failure.process = process
        failure.resource_cleanup_failed = True
        raise failure
    return process


def _cleanup_failed_windows_start(job: Optional[_WindowsJob], process: Optional[_WindowsProcess],
                                  startup: Dict[str, Any], exc: BaseException) -> Dict[str, Any]:
    """Terminate and verify a failed, possibly still-suspended startup."""
    tree: Dict[str, Any] = {
        "supervision": "windows-job-object", "trigger": "launch-failed",
        "descendants_detected": None, "term_signal_sent": False,
        "kill_signal_sent": False, "cleanup_complete": False,
        "active_members_after_cleanup": None, "root_process_exited": False,
        "job_empty": False, "cleanup_verified": False, "errors": [startup["error"]],
    }
    if process is not None:
        if startup.get("job_assigned"):
            try:
                tree["kill_signal_sent"] = bool(job.terminate(1))
                if not tree["kill_signal_sent"]:
                    tree["errors"].append(str(job.api.error("TerminateJobObject(startup failure)")))
            except Exception as cleanup_exc:
                tree["errors"].append("TerminateJobObject: {}: {}".format(type(cleanup_exc).__name__, cleanup_exc))
        else:
            try:
                tree["kill_signal_sent"] = process.terminate(1)
                if not tree["kill_signal_sent"]:
                    tree["errors"].append(str(job.api.error("TerminateProcess(suspended root)")))
            except Exception as cleanup_exc:
                tree["errors"].append("TerminateProcess: {}: {}".format(type(cleanup_exc).__name__, cleanup_exc))
        try:
            process.wait(timeout=5.0)
            tree["root_process_exited"] = True
        except Exception as cleanup_exc:
            tree["errors"].append("root process exit verification: {}: {}".format(type(cleanup_exc).__name__, cleanup_exc))
    if job is not None:
        try:
            active = job.active_processes()
            tree["active_members_after_cleanup"] = active
            tree["job_empty"] = active == 0
        except Exception as cleanup_exc:
            tree["errors"].append("job state verification: {}: {}".format(type(cleanup_exc).__name__, cleanup_exc))
    elif startup.get("job_created"):
        tree["job_empty"] = bool(getattr(exc, "job_cleanup_verified", False))
    else:
        tree["job_empty"] = None

    tree["cleanup_verified"] = bool(
        (not startup["process_created"] or tree["root_process_exited"])
        and (tree["job_empty"] is True or tree["job_empty"] is None and not startup.get("job_created"))
    )
    if getattr(exc, "resource_cleanup_failed", False):
        tree["errors"].append("temporary native handle or attribute-list cleanup failed")
        tree["cleanup_verified"] = False
    tree["cleanup_complete"] = tree["cleanup_verified"]
    startup["root_process_exited"] = tree["root_process_exited"]
    startup["job_empty"] = tree["job_empty"]
    startup["cleanup_verified"] = tree["cleanup_verified"]
    if not tree["cleanup_complete"]:
        tree["errors"].append("startup failure cleanup could not be verified")

    if process is not None:
        try:
            close_errors = process.close()
            tree["errors"].extend(close_errors)
            if close_errors:
                tree["cleanup_complete"] = tree["cleanup_verified"] = False
        except Exception as cleanup_exc:
            tree["errors"].append("process handle cleanup: {}: {}".format(type(cleanup_exc).__name__, cleanup_exc))
            tree["cleanup_complete"] = tree["cleanup_verified"] = False
    if job is not None:
        try:
            close_errors = job.close()
            tree["errors"].extend(close_errors)
            if close_errors:
                tree["cleanup_complete"] = tree["cleanup_verified"] = False
        except Exception as cleanup_exc:
            tree["errors"].append("Job Object handle cleanup: {}: {}".format(type(cleanup_exc).__name__, cleanup_exc))
            tree["cleanup_complete"] = tree["cleanup_verified"] = False
    startup["cleanup_verified"] = tree["cleanup_verified"]
    tree["startup"] = dict(startup)
    return tree


def _spawn_windows(command: List[str], cwd: Path, env: dict, stdout: Any, stderr: Any
                   ) -> Tuple[_WindowsProcess, _WindowsJob, Dict[str, Any]]:
    startup: Dict[str, Any] = {
        "stage": "job_object_creation", "job_created": False, "job_configured": False,
        "process_created": False,
        "process_pid": None,
        "job_assignment_attempted": False, "job_assigned": False,
        "resume_attempted": False, "thread_resumed": False,
        "root_process_exited": None, "job_empty": None,
        "cleanup_verified": False, "error": None,
    }
    job = None
    process = None
    try:
        job = _WindowsJob()
        startup["job_created"] = True
        startup["job_configured"] = True
        startup["stage"] = "create_process"
        process = _windows_create_process(job.api, command, cwd, env, stdout, stderr)
        startup["process_created"] = True
        startup["process_pid"] = process.pid
        startup["stage"] = "job_assignment"
        startup["job_assignment_attempted"] = True
        job.assign(process)
        startup["job_assigned"] = True
        startup["stage"] = "thread_resume"
        startup["resume_attempted"] = True
        job.resume(process)
        startup["thread_resumed"] = True
        startup["stage"] = "running"
        return process, job, startup
    except BaseException as exc:
        if job is None and getattr(exc, "job_created", False):
            startup["job_created"] = True
            startup["job_configured"] = False
            startup["job_empty"] = bool(getattr(exc, "job_cleanup_verified", False))
        if process is None:
            process = getattr(exc, "process", None)
            if process is not None:
                startup["process_created"] = True
                startup["process_pid"] = getattr(process, "pid", None)
        stage = startup["stage"]
        if isinstance(exc, _WindowsApiError) and exc.operation == "CreateProcessW":
            stage = startup["stage"] = "create_process"
        elif isinstance(exc, FileNotFoundError):
            stage = startup["stage"] = "executable_resolution"
        startup["error"] = "{}: {}".format(type(exc).__name__, exc)
        tree = _run_cleanup_uninterruptibly(
            _cleanup_failed_windows_start, job, process, startup, exc,
        )
        raise _WindowsSpawnFailure(
            stage, exc, startup, tree,
            launch_failure=(bool(getattr(exc, "launch_failure", False)) or
                            isinstance(exc, OSError) or
                            isinstance(exc, _WindowsApiError) and exc.operation == "CreateProcessW"),
        ) from exc


class _CancellationRequested(Exception):
    pass


def _cancellation_requested(cancellation: Any) -> bool:
    return cancellation is not None and bool(getattr(cancellation, "cancelled", False))


def _wait_with_cancellation(process: Any, command: List[str], timeout: Optional[float], cancellation: Any) -> int:
    deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
    while True:
        if _cancellation_requested(cancellation):
            raise _CancellationRequested()
        return_code = process.poll()
        if return_code is not None:
            if _cancellation_requested(cancellation):
                raise _CancellationRequested()
            return return_code
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            time.sleep(min(0.1, remaining))
        else:
            time.sleep(0.1)


def _capture_stream(stream: Any, destination: Any, limit: int, metrics: Dict[str, Any]) -> None:
    digest = hashlib.sha256()
    total = 0
    retained = 0
    errors = []
    write_failed = False
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
            remaining = max(0, limit - retained)
            if remaining and not write_failed:
                try:
                    output = chunk[:remaining]
                    written = destination.write(output)
                    retained += int(written or 0)
                    if written != len(output):
                        errors.append("capture write retained {} of {} bytes".format(written or 0, len(output)))
                        write_failed = True
                except Exception as exc:
                    errors.append("capture write failed: {}: {}".format(type(exc).__name__, exc))
                    write_failed = True
    except Exception as exc:
        errors.append("capture read failed: {}: {}".format(type(exc).__name__, exc))
    finally:
        try:
            stream.close()
        except Exception as exc:
            errors.append("capture pipe close failed: {}: {}".format(type(exc).__name__, exc))
        metrics.update({
            "bytes": total,
            "sha256": digest.hexdigest(),
            "truncated": total > limit,
            "capture_limit_bytes": limit,
            "retained_bytes": retained,
            "errors": errors,
        })


def _windows_capture_pipes() -> Tuple[Any, Any, Any, Any]:
    """Create two parent-reader/child-writer pipes with partial-failure cleanup."""
    open_fds = []
    streams = []
    try:
        stdout_read_fd, stdout_write_fd = os.pipe()
        open_fds.extend((stdout_read_fd, stdout_write_fd))
        stderr_read_fd, stderr_write_fd = os.pipe()
        open_fds.extend((stderr_read_fd, stderr_write_fd))

        stdout_reader = os.fdopen(stdout_read_fd, "rb", buffering=0)
        open_fds.remove(stdout_read_fd)
        streams.append(stdout_reader)
        stdout_child = os.fdopen(stdout_write_fd, "wb", buffering=0)
        open_fds.remove(stdout_write_fd)
        streams.append(stdout_child)
        stderr_reader = os.fdopen(stderr_read_fd, "rb", buffering=0)
        open_fds.remove(stderr_read_fd)
        streams.append(stderr_reader)
        stderr_child = os.fdopen(stderr_write_fd, "wb", buffering=0)
        open_fds.remove(stderr_write_fd)
        streams.append(stderr_child)
        return stdout_reader, stdout_child, stderr_reader, stderr_child
    except BaseException:
        for stream in reversed(streams):
            try:
                stream.close()
            except Exception:
                pass
        for fd in reversed(open_fds):
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def _cleanup_started_process(process: Any, supervisor: Any, grace_seconds: float, reason: str) -> Dict[str, Any]:
    if os.name == "nt":
        if supervisor is None:
            raise ProcessSupervisionError("Windows Job Object is unavailable for started-process cleanup")
        return _run_cleanup_uninterruptibly(supervisor.terminate_tree, process, grace_seconds, reason)
    return _run_cleanup_uninterruptibly(_posix_cleanup, process, process.pid, grace_seconds, reason)


def run_supervised_process(
    command: List[str],
    cwd: Path,
    env: dict,
    stdout_path: Path,
    stderr_path: Path,
    timeout: Optional[float],
    grace_seconds: float,
    cancellation: Any = None,
    capture_limits: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Run command and supervise the whole process group/tree.

    The direct child's exit code is retained as ``native_exit_code``. Runner
    control results use 124 for timeout and 130 for Ctrl+C. A command that exits
    while leaving descendants behind is cleaned up and reported as failed by
    the caller, even if its direct exit code was zero.
    """
    started = time.monotonic()
    capture_enabled = capture_limits is not None
    capture_limits = capture_limits or {}
    if capture_enabled:
        capture_limits = {
            "stdout": int(capture_limits.get("stdout", 8192)),
            "stderr": int(capture_limits.get("stderr", 8192)),
        }
        if any(value < 0 for value in capture_limits.values()):
            raise ValueError("capture limits must be non-negative")
    result: Dict[str, Any] = {
        "exit_code": None,
        "native_exit_code": None,
        "interrupted": False,
        "timed_out": False,
        "duration_ms": None,
        "spawn_error": None,
        "supervision_error": None,
        "orphan_processes_detected": False,
        "process_tree": None,
        "startup": None,
        "signal_number": None,
        "signal_name": None,
        "capture": None,
    }
    supervisor = None
    process = None
    readers = []
    reader_metrics = {
        key: {
            "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest(), "truncated": False,
            "capture_limit_bytes": capture_limits.get(key, 0), "retained_bytes": 0, "errors": [],
        }
        for key in ("stdout", "stderr")
    }
    capture_streams = {}
    child_pipe_writers = []
    with open_regular_writer(stdout_path) as stdout, open_regular_writer(stderr_path) as stderr:
        try:
            if _cancellation_requested(cancellation):
                raise _CancellationRequested()
            LOGGER.debug("Starting supervised Python subprocess: platform=%s cwd=%s", os.name, cwd)
            if capture_enabled:
                if os.name == "nt":
                    stdout_reader, stdout_child, stderr_reader, stderr_child = _windows_capture_pipes()
                    child_pipe_writers.extend([stdout_child, stderr_child])
                    capture_streams.update({"stdout": stdout_reader, "stderr": stderr_reader})
                else:
                    stdout_reader = stderr_reader = None
                    stdout_child = stderr_child = None
            if os.name == "nt":
                process, supervisor, result["startup"] = _spawn_windows(
                    command, cwd, env,
                    stdout_child if capture_enabled else stdout,
                    stderr_child if capture_enabled else stderr,
                )
            else:
                process = subprocess.Popen(
                    command,
                    cwd=str(cwd),
                    env=env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE if capture_enabled else stdout,
                    stderr=subprocess.PIPE if capture_enabled else stderr,
                    shell=False,
                    close_fds=True,
                    start_new_session=True,
                )
                if capture_enabled:
                    stdout_reader = process.stdout
                    stderr_reader = process.stderr
                    capture_streams.update({"stdout": stdout_reader, "stderr": stderr_reader})
            if capture_enabled:
                for writer in child_pipe_writers:
                    writer.close()
                child_pipe_writers = []
                for label, stream, destination in (
                    ("stdout", stdout_reader, stdout), ("stderr", stderr_reader, stderr),
                ):
                    thread = threading.Thread(
                        target=_capture_stream,
                        args=(stream, destination, capture_limits[label], reader_metrics[label]),
                        name="probe-{}-capture".format(label), daemon=True,
                    )
                    thread.start()
                    readers.append(thread)
            LOGGER.info(
                "Supervised subprocess started: pid=%s supervision=%s",
                process.pid, "windows-job-object" if os.name == "nt" else "posix-session-process-groups",
            )
        except _WindowsSpawnFailure as exc:
            LOGGER.exception("Windows process startup failed during %s", exc.stage)
            message = "Windows process startup failed during {}: {}\n".format(exc.stage, exc)
            if not capture_enabled:
                stderr.write(message.encode("utf-8", errors="replace"))
            result["exit_code"] = 127 if exc.launch_failure else 126
            result["native_exit_code"] = result["exit_code"]
            result["startup"] = exc.startup
            result["process_tree"] = exc.process_tree
            if exc.launch_failure:
                result["spawn_error"] = str(exc)
            else:
                result["supervision_error"] = str(exc)
        except _CancellationRequested:
            number, name = _cancellation_reason(cancellation)
            result.update({
                "interrupted": True,
                "signal_number": number,
                "signal_name": name,
                "exit_code": 128 + number if number is not None else 130,
                "native_exit_code": None,
                "startup": {"stage": "cancelled_before_launch", "process_created": False},
                "process_tree": {
                    "supervision": "not_started", "trigger": "cancelled-before-launch",
                    "cleanup_complete": True, "active_members_after_cleanup": 0, "errors": [],
                },
            })
        except KeyboardInterrupt:
            number = getattr(signal, "SIGINT", 2)
            if cancellation is not None:
                try:
                    cancellation.request(number)
                except Exception:
                    pass
            reason_number, reason_name = _cancellation_reason(cancellation)
            reason_number = reason_number if reason_number is not None else number
            reason_name = reason_name or "SIGINT"
            result.update({
                "interrupted": True, "signal_number": reason_number, "signal_name": reason_name,
                "exit_code": 128 + reason_number,
            })
            if process is not None:
                try:
                    result["process_tree"] = _cleanup_started_process(
                        process, supervisor, grace_seconds, "signal-{}".format(reason_name),
                    )
                    result["native_exit_code"] = process.returncode
                except Exception as cleanup_exc:
                    result["supervision_error"] = "cleanup after startup interruption failed: {}: {}".format(
                        type(cleanup_exc).__name__, cleanup_exc,
                    )
                    result["process_tree"] = {
                        "supervision": "windows-job-object" if os.name == "nt" else "posix-session-process-groups",
                        "trigger": "startup-interruption", "cleanup_complete": False,
                        "active_members_after_cleanup": None, "errors": [result["supervision_error"]],
                    }
            else:
                result["process_tree"] = {
                    "supervision": "not_started", "trigger": "interrupted-before-launch",
                    "cleanup_complete": True, "active_members_after_cleanup": 0, "errors": [],
                }
        except OSError as exc:
            LOGGER.exception("Failed to start supervised subprocess")
            message = "{}: {}\n".format(type(exc).__name__, exc)
            if not capture_enabled:
                stderr.write(message.encode("utf-8", errors="replace"))
            if process is None:
                result["exit_code"] = 127
                result["native_exit_code"] = 127
                result["spawn_error"] = "{}: {}".format(type(exc).__name__, exc)
            else:
                result["exit_code"] = 126
                result["supervision_error"] = "{}: {}".format(type(exc).__name__, exc)
                try:
                    result["process_tree"] = _cleanup_started_process(
                        process, supervisor, grace_seconds, "capture-setup-error",
                    )
                    result["native_exit_code"] = process.returncode
                except Exception as cleanup_exc:
                    result["process_tree"] = {
                        "supervision": "windows-job-object" if os.name == "nt" else "posix-session-process-groups",
                        "trigger": "capture-setup-error", "cleanup_complete": False,
                        "active_members_after_cleanup": None,
                        "errors": [result["supervision_error"], "cleanup failed: {}: {}".format(
                            type(cleanup_exc).__name__, cleanup_exc,
                        )],
                    }
        except ProcessSupervisionError as exc:
            LOGGER.exception("Could not establish process supervision")
            message = "Process supervision error: {}\n".format(exc)
            if not capture_enabled:
                stderr.write(message.encode("utf-8", errors="replace"))
            result["exit_code"] = 126
            result["native_exit_code"] = 126
            result["supervision_error"] = str(exc)
            result["process_tree"] = {
                "supervision": "windows-job-object", "trigger": "launch-failed",
                "descendants_detected": None, "term_signal_sent": False, "kill_signal_sent": False,
                "cleanup_complete": False, "active_members_after_cleanup": None,
                "errors": [str(exc)],
            }
        except Exception as exc:
            LOGGER.exception("Supervised process setup failed")
            result["exit_code"] = 126
            result["supervision_error"] = "{}: {}".format(type(exc).__name__, exc)
            if process is not None:
                try:
                    result["process_tree"] = _cleanup_started_process(
                        process, supervisor, grace_seconds, "capture-setup-error",
                    )
                    result["native_exit_code"] = process.returncode
                except Exception as cleanup_exc:
                    result["process_tree"] = {
                        "supervision": "windows-job-object" if os.name == "nt" else "posix-session-process-groups",
                        "trigger": "capture-setup-error", "cleanup_complete": False,
                        "active_members_after_cleanup": None,
                        "errors": [result["supervision_error"], "cleanup failed: {}: {}".format(
                            type(cleanup_exc).__name__, cleanup_exc,
                        )],
                    }
            else:
                result["process_tree"] = {
                    "supervision": "not_started", "trigger": "launch-setup-error",
                    "cleanup_complete": False, "active_members_after_cleanup": None,
                    "errors": [result["supervision_error"]],
                }
        else:
            try:
                try:
                    if cancellation is not None:
                        result["native_exit_code"] = _wait_with_cancellation(process, command, timeout, cancellation)
                    else:
                        result["native_exit_code"] = process.wait(timeout=timeout)
                    if _cancellation_requested(cancellation):
                        raise _CancellationRequested()
                    result["exit_code"] = result["native_exit_code"]
                    if os.name == "nt":
                        tree = supervisor.after_leader_exit(process, grace_seconds)
                    else:
                        pgid = process.pid
                        groups, enumeration_complete = _posix_session_snapshot(pgid)
                        if groups or not enumeration_complete:
                            reason = "orphaned-descendants" if groups else "verification-error"
                            tree = _run_cleanup_uninterruptibly(_posix_cleanup, process, pgid, grace_seconds, reason)
                        else:
                            tree = {
                                "supervision": "posix-session-process-groups", "trigger": None,
                                "descendants_detected": False, "term_signal_sent": False,
                                "kill_signal_sent": False, "cleanup_complete": True,
                                "active_members_after_cleanup": 0, "errors": [],
                            }
                    result["process_tree"] = tree
                    if os.name == "nt":
                        result["startup"].update({
                            "root_process_exited": tree.get("root_process_exited"),
                            "job_empty": tree.get("job_empty"),
                            "cleanup_verified": tree.get("cleanup_verified", tree.get("cleanup_complete", False)),
                        })
                        tree["startup"] = dict(result["startup"] or {})
                    result["orphan_processes_detected"] = bool(tree.get("descendants_detected"))
                except subprocess.TimeoutExpired:
                    LOGGER.warning("Supervised subprocess timeout: pid=%s timeout_seconds=%s", process.pid, timeout)
                    result["timed_out"] = True
                    result["exit_code"] = 124
                    if os.name == "nt":
                        tree = _run_cleanup_uninterruptibly(supervisor.terminate_tree, process, grace_seconds, "timeout")
                    else:
                        tree = _run_cleanup_uninterruptibly(_posix_cleanup, process, process.pid, grace_seconds, "timeout")
                    result["native_exit_code"] = process.returncode
                    result["process_tree"] = tree
                    if os.name == "nt":
                        result["startup"].update({
                            "root_process_exited": tree.get("root_process_exited"),
                            "job_empty": tree.get("job_empty"),
                            "cleanup_verified": tree.get("cleanup_verified", tree.get("cleanup_complete", False)),
                        })
                        tree["startup"] = dict(result["startup"] or {})
                except _CancellationRequested:
                    number, name = _cancellation_reason(cancellation)
                    LOGGER.warning("Supervised subprocess cancelled: pid=%s signal=%s", process.pid, name)
                    result.update({
                        "interrupted": True,
                        "signal_number": number,
                        "signal_name": name,
                        "exit_code": 128 + number if number is not None else 130,
                    })
                    reason = "signal-{}".format(name or "unknown")
                    if os.name == "nt":
                        tree = _run_cleanup_uninterruptibly(supervisor.terminate_tree, process, grace_seconds, reason)
                    else:
                        tree = _run_cleanup_uninterruptibly(_posix_cleanup, process, process.pid, grace_seconds, reason)
                    result["native_exit_code"] = process.returncode
                    result["process_tree"] = tree
                    if os.name == "nt":
                        result["startup"].update({
                            "root_process_exited": tree.get("root_process_exited"),
                            "job_empty": tree.get("job_empty"),
                            "cleanup_verified": tree.get("cleanup_verified", tree.get("cleanup_complete", False)),
                        })
                        tree["startup"] = dict(result["startup"] or {})
                except KeyboardInterrupt:
                    LOGGER.warning("Supervised subprocess interrupted: pid=%s", process.pid)
                    if cancellation is not None:
                        try:
                            cancellation.request(getattr(signal, "SIGINT", 2))
                        except Exception:
                            pass
                    result["interrupted"] = True
                    number, name = _cancellation_reason(cancellation)
                    number = number if number is not None else getattr(signal, "SIGINT", 2)
                    name = name or "SIGINT"
                    result["signal_number"] = number
                    result["signal_name"] = name
                    result["exit_code"] = 128 + number
                    if os.name == "nt":
                        tree = _run_cleanup_uninterruptibly(supervisor.terminate_tree, process, grace_seconds, "interrupt")
                    else:
                        tree = _run_cleanup_uninterruptibly(_posix_cleanup, process, process.pid, grace_seconds, "interrupt")
                    result["native_exit_code"] = process.returncode
                    result["process_tree"] = tree
                    if os.name == "nt":
                        result["startup"].update({
                            "root_process_exited": tree.get("root_process_exited"),
                            "job_empty": tree.get("job_empty"),
                            "cleanup_verified": tree.get("cleanup_verified", tree.get("cleanup_complete", False)),
                        })
                        tree["startup"] = dict(result["startup"] or {})
            except Exception as exc:
                LOGGER.exception("Unexpected exception in process supervision: pid=%s", getattr(process, "pid", None))
                # Never abandon a started Cargo process because of an error in
                # the supervising code itself. Attempt process-tree cleanup and
                # record an explicit non-success result.
                result["supervision_error"] = "{}: {}".format(type(exc).__name__, exc)
                result["exit_code"] = 126
                try:
                    if os.name == "nt" and supervisor is not None:
                        tree = _run_cleanup_uninterruptibly(supervisor.terminate_tree, process, grace_seconds, "supervisor-error")
                    else:
                        tree = _run_cleanup_uninterruptibly(_posix_cleanup, process, process.pid, grace_seconds, "supervisor-error")
                    result["process_tree"] = tree
                    if os.name == "nt":
                        result["startup"].update({
                            "root_process_exited": tree.get("root_process_exited"),
                            "job_empty": tree.get("job_empty"),
                            "cleanup_verified": tree.get("cleanup_verified", tree.get("cleanup_complete", False)),
                        })
                        tree["startup"] = dict(result["startup"] or {})
                except Exception as cleanup_exc:
                    result["process_tree"] = {
                        "supervision": "windows-job-object" if os.name == "nt" else "posix-session-process-groups",
                        "trigger": "supervisor-error", "descendants_detected": None,
                        "term_signal_sent": False, "kill_signal_sent": False,
                        "cleanup_complete": False, "active_members_after_cleanup": None,
                        "errors": [
                            result["supervision_error"],
                            "cleanup failure: {}: {}".format(type(cleanup_exc).__name__, cleanup_exc),
                        ],
                    }
        finally:
            for writer in child_pipe_writers:
                try:
                    writer.close()
                except Exception:
                    pass
            for thread in readers:
                thread.join(timeout=max(1.0, grace_seconds + 1.0))
            if capture_enabled:
                for label, stream in capture_streams.items():
                    associated_thread = next((
                        thread for thread in readers if label in thread.name
                    ), None)
                    if stream is not None and associated_thread is not None and associated_thread.is_alive():
                        try:
                            stream.close()
                        except Exception:
                            pass
                for thread in readers:
                    if thread.is_alive():
                        thread.join(timeout=0.5)
                    if thread.is_alive():
                        reader_metrics["stdout" if "stdout" in thread.name else "stderr"]["errors"].append(
                            "capture reader did not stop after process cleanup"
                        )
                for stream in capture_streams.values():
                    try:
                        stream.close()
                    except Exception:
                        pass
            if supervisor is not None:
                try:
                    close_errors = _run_cleanup_uninterruptibly(supervisor.close)
                except Exception as close_exc:
                    close_errors = ["Job Object close failed: {}: {}".format(type(close_exc).__name__, close_exc)]
                if close_errors:
                    LOGGER.error("Windows Job Object close failed: %s", close_errors)
                    message = "; ".join(close_errors)
                    existing = result.get("supervision_error")
                    result["supervision_error"] = (existing + "; " + message) if existing else message
                    tree = result.get("process_tree")
                    if tree is None:
                        tree = {
                            "supervision": "windows-job-object", "trigger": "job-close-error",
                            "descendants_detected": None, "term_signal_sent": False,
                            "kill_signal_sent": False, "cleanup_complete": False,
                            "active_members_after_cleanup": None, "errors": [],
                        }
                        result["process_tree"] = tree
                    tree["cleanup_complete"] = False
                    tree["cleanup_verified"] = False
                    tree.setdefault("errors", []).extend(close_errors)
                    if result.get("startup") is not None:
                        result["startup"]["cleanup_verified"] = False
                    if tree.get("startup") is not None:
                        tree["startup"]["cleanup_verified"] = False

            if os.name == "nt" and process is not None:
                try:
                    close_errors = process.close()
                except Exception as close_exc:
                    close_errors = ["process handle cleanup: {}: {}".format(type(close_exc).__name__, close_exc)]
                if close_errors:
                    LOGGER.error("Windows process handle cleanup failed: %s", close_errors)
                    message = "; ".join(close_errors)
                    existing = result.get("supervision_error")
                    result["supervision_error"] = (existing + "; " + message) if existing else message
                    tree = result.get("process_tree")
                    if tree is None:
                        tree = {
                            "supervision": "windows-job-object", "trigger": "process-handle-close-error",
                            "cleanup_complete": False, "cleanup_verified": False,
                            "active_members_after_cleanup": None, "errors": [],
                        }
                        result["process_tree"] = tree
                    tree["cleanup_complete"] = False
                    tree["cleanup_verified"] = False
                    tree.setdefault("errors", []).extend(close_errors)
                    if result.get("startup") is not None:
                        result["startup"]["cleanup_verified"] = False
                    if tree.get("startup") is not None:
                        tree["startup"]["cleanup_verified"] = False

            if capture_enabled:
                result["capture"] = reader_metrics
                capture_errors = [
                    error for info in reader_metrics.values() for error in info.get("errors", [])
                ]
                if capture_errors:
                    message = "; ".join(capture_errors)
                    existing = result.get("supervision_error")
                    result["supervision_error"] = (existing + "; " + message) if existing else message

    tree = result.get("process_tree")
    if os.name == "nt" and result.get("startup") is not None and tree is not None:
        result["startup"].update({
            "root_process_exited": tree.get("root_process_exited"),
            "job_empty": tree.get("job_empty"),
            "cleanup_verified": tree.get("cleanup_verified", tree.get("cleanup_complete", False)),
        })
        if tree.get("startup") is not None:
            tree["startup"].update(result["startup"])
    if os.name == "nt" and tree and tree.get("supervision_error"):
        existing = result.get("supervision_error")
        detail = tree["supervision_error"]
        result["supervision_error"] = (existing + "; " + detail) if existing else detail
    if tree is None and os.name != "nt" and process is not None:
        # Covers unusual exceptions after POSIX spawn.
        tree = {
            "supervision": "posix-session-process-groups", "trigger": "unexpected-error",
            "descendants_detected": None, "term_signal_sent": False, "kill_signal_sent": False,
            "cleanup_complete": False, "active_members_after_cleanup": None,
            "errors": ["process supervision did not reach a verified final state"],
        }
        result["process_tree"] = tree
    result["duration_ms"] = round((time.monotonic() - started) * 1000)
    LOGGER.debug(
        "Supervised subprocess completed: pid=%s exit_code=%s native_exit_code=%s duration_ms=%s timed_out=%s interrupted=%s supervision_error=%s",
        getattr(process, "pid", None), result.get("exit_code"), result.get("native_exit_code"),
        result["duration_ms"], result["timed_out"], result["interrupted"], result.get("supervision_error"),
    )
    return result
