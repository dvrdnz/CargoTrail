"""Focused Windows supervisor unit tests and native Windows integration tests."""

# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import ctypes
import hashlib
import importlib.util
import inspect
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import artifact_inventory
import process_supervision as supervision
AGENT_SCRIPT = Path(__file__).resolve().parents[1] / "cargotrail.py"
AGENT_SPEC = importlib.util.spec_from_file_location("windows_test_cargotrail", AGENT_SCRIPT)
agent = importlib.util.module_from_spec(AGENT_SPEC)
AGENT_SPEC.loader.exec_module(agent)


class FakeProcess:
    def __init__(self, pid=4242):
        self.pid = pid
        self.process_handle = object()
        self.thread_handle = object()
        self.returncode = None
        self.terminated = False
        self.close_calls = 0

    def terminate(self, exit_code=1):
        self.terminated = True
        return True

    def wait(self, timeout=None):
        self.returncode = 1
        return self.returncode

    def poll(self):
        return self.returncode

    def send_ctrl_break(self):
        return False

    def close(self):
        self.close_calls += 1
        return []


class FakeJob:
    def __init__(self, events, assign_error=None, resume_error=None, terminate_error=None):
        self.events = events
        self.assign_error = assign_error
        self.resume_error = resume_error
        self.terminate_error = terminate_error
        self.active = 0
        self.close_calls = 0
        self.api = SimpleNamespace(error=lambda operation: "fake Windows error in " + operation)

    def assign(self, process):
        self.events.append("assign")
        if self.assign_error:
            raise self.assign_error
        self.active = 1

    def resume(self, process):
        self.events.append("resume")
        if self.resume_error:
            raise self.resume_error

    def terminate(self, exit_code=1):
        self.events.append("terminate_job")
        if self.terminate_error:
            return False
        self.active = 0
        return True

    def active_processes(self):
        return self.active

    def close(self):
        self.close_calls += 1
        return []


class WindowsSupervisorUnitTests(unittest.TestCase):
    def test_windows_backend_does_not_use_private_popen_attributes(self):
        source = inspect.getsource(supervision)
        self.assertNotIn("._thread", source)
        self.assertNotIn("._handle", source)

    def test_capture_pipe_setup_closes_partial_descriptors(self):
        real_pipe = os.pipe
        opened = []
        calls = []

        def fail_second_pipe():
            calls.append(True)
            if len(calls) == 2:
                raise OSError("injected second-pipe failure")
            descriptors = real_pipe()
            opened.extend(descriptors)
            return descriptors

        with mock.patch.object(supervision.os, "pipe", side_effect=fail_second_pipe):
            with self.assertRaisesRegex(OSError, "second-pipe"):
                supervision._windows_capture_pipes()
        self.assertEqual(len(opened), 2)
        for descriptor in opened:
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_create_assign_resume_order(self):
        events = []
        job = FakeJob(events)
        process = FakeProcess()

        def create(*_args):
            events.append("create_process")
            return process

        with mock.patch.object(supervision, "_WindowsJob", return_value=job), \
                mock.patch.object(supervision, "_windows_create_process", side_effect=create):
            _proc, _job, startup = supervision._spawn_windows(
                ["cargo.exe", "check"], Path("."), {}, None, None,
            )

        self.assertEqual(events, ["create_process", "assign", "resume"])
        self.assertTrue(startup["process_created"])
        self.assertTrue(startup["job_assigned"])
        self.assertTrue(startup["thread_resumed"])

    def test_after_leader_exit_allows_job_children_to_finish_naturally(self):
        job = object.__new__(supervision._WindowsJob)
        job.active_processes = mock.Mock(return_value=1)
        job.wait_empty = mock.Mock(return_value=True)
        job.terminate_tree = mock.Mock()
        process = FakeProcess()
        process.returncode = 0

        tree = job.after_leader_exit(process, 2.0)

        self.assertFalse(tree["descendants_detected"])
        self.assertTrue(tree["cleanup_complete"])
        self.assertTrue(tree["job_empty"])
        job.wait_empty.assert_called_once_with(2.0)
        job.terminate_tree.assert_not_called()

    def test_createprocess_failure_is_structured_without_process_handles(self):
        events = []
        job = FakeJob(events)
        error = supervision._WindowsApiError("CreateProcessW", 2, "file not found")
        with mock.patch.object(supervision, "_WindowsJob", return_value=job), \
                mock.patch.object(supervision, "_windows_create_process", side_effect=error):
            with self.assertRaises(supervision._WindowsSpawnFailure) as caught:
                supervision._spawn_windows(["missing.exe"], Path("."), {}, None, None)

        failure = caught.exception
        self.assertTrue(failure.launch_failure)
        self.assertFalse(failure.startup["process_created"])
        self.assertIsNone(failure.startup["process_pid"])
        self.assertFalse(failure.startup["job_assigned"])
        self.assertFalse(failure.startup["thread_resumed"])
        self.assertTrue(failure.process_tree["job_empty"])
        self.assertTrue(failure.process_tree["cleanup_complete"])
        self.assertEqual(job.close_calls, 1)

    def test_assign_failure_terminates_and_verifies_suspended_root(self):
        events = []
        process = FakeProcess()
        job = FakeJob(events, assign_error=RuntimeError("assign denied"))

        with mock.patch.object(supervision, "_WindowsJob", return_value=job), \
                mock.patch.object(supervision, "_windows_create_process", return_value=process):
            with self.assertRaises(supervision._WindowsSpawnFailure) as caught:
                supervision._spawn_windows(["cargo.exe"], Path("."), {}, None, None)

        failure = caught.exception
        self.assertEqual(events, ["assign"])
        self.assertTrue(process.terminated)
        self.assertTrue(failure.process_tree["root_process_exited"])
        self.assertTrue(failure.process_tree["job_empty"])
        self.assertTrue(failure.process_tree["cleanup_complete"])
        self.assertEqual(process.close_calls, 1)
        self.assertEqual(job.close_calls, 1)

    def test_resume_failure_terminates_job_and_verifies_both_states(self):
        events = []
        process = FakeProcess()
        job = FakeJob(events, resume_error=RuntimeError("resume failed"))

        with mock.patch.object(supervision, "_WindowsJob", return_value=job), \
                mock.patch.object(supervision, "_windows_create_process", return_value=process):
            with self.assertRaises(supervision._WindowsSpawnFailure) as caught:
                supervision._spawn_windows(["cargo.exe"], Path("."), {}, None, None)

        failure = caught.exception
        self.assertEqual(events, ["assign", "resume", "terminate_job"])
        self.assertTrue(failure.process_tree["root_process_exited"])
        self.assertTrue(failure.process_tree["job_empty"])
        self.assertTrue(failure.process_tree["cleanup_verified"])
        self.assertEqual(process.close_calls, 1)
        self.assertEqual(job.close_calls, 1)

    def test_terminate_job_error_is_kept_and_final_state_is_verified(self):
        events = []
        job = object.__new__(supervision._WindowsJob)
        job.handle = object()
        job.api = SimpleNamespace(
            error=lambda operation: "simulated error: " + operation,
            kernel32=SimpleNamespace(TerminateJobObject=lambda *_args: 0),
        )
        job.wait_empty = mock.Mock(side_effect=[False, False])
        job.active_processes = mock.Mock(return_value=0)
        process = FakeProcess()
        tree = job.terminate_tree(process, 0, "timeout")

        self.assertTrue(any("TerminateJobObject failed" in error for error in tree["errors"]))
        self.assertTrue(tree["root_process_exited"])
        self.assertTrue(tree["job_empty"])
        self.assertTrue(tree["cleanup_verified"])
        self.assertIn("TerminateJobObject failed", tree["supervision_error"])

    def test_process_verification_failure_cannot_report_cleanup_complete(self):
        job = object.__new__(supervision._WindowsJob)
        job.handle = object()
        job.api = SimpleNamespace(
            error=lambda operation: "simulated error: " + operation,
            kernel32=SimpleNamespace(TerminateJobObject=lambda *_args: 1),
        )
        job.wait_empty = mock.Mock(side_effect=[RuntimeError("query failed"), False])
        job.active_processes = mock.Mock(side_effect=RuntimeError("final query failed"))
        process = FakeProcess()
        process.wait = mock.Mock(side_effect=RuntimeError("wait failed"))
        tree = job.terminate_tree(process, 0, "timeout")

        self.assertFalse(tree["cleanup_complete"])
        self.assertFalse(tree["cleanup_verified"])
        self.assertTrue(any("final job verification" in error for error in tree["errors"]))
        self.assertTrue(any("root process exit verification" in error for error in tree["errors"]))

    def test_resume_thread_rejects_failure_and_unexpected_suspend_counts(self):
        class Kernel:
            def __init__(self, result):
                self.result = result
                self.handle = None

            def ResumeThread(self, handle):
                self.handle = handle
                return self.result

        for result in (0xFFFFFFFF, 0, 2):
            with self.subTest(result=result):
                kernel = Kernel(result)
                api = SimpleNamespace(
                    WAIT_FAILED=0xFFFFFFFF, kernel32=kernel,
                    error=lambda operation: supervision._WindowsApiError(operation, 5, "access denied"),
                )
                job = object.__new__(supervision._WindowsJob)
                job.api = api
                process = FakeProcess()
                if result == 0xFFFFFFFF:
                    with self.assertRaises(supervision._WindowsApiError) as caught:
                        job.resume(process)
                    self.assertEqual(caught.exception.operation, "ResumeThread")
                else:
                    with self.assertRaisesRegex(supervision.ProcessSupervisionError, "expected 1"):
                        job.resume(process)
                self.assertIs(kernel.handle, process.thread_handle)

    def test_process_handle_close_attempts_each_handle_once_and_reports_errors(self):
        closed = []

        def close(handle):
            closed.append(handle)
            return False

        api = SimpleNamespace(
            kernel32=SimpleNamespace(CloseHandle=close),
            error=lambda operation: "simulated close failure: " + operation,
        )
        process = supervision._WindowsProcess(api, "process-handle", "thread-handle", 1, ["x"])
        first = process.close()
        second = process.close()

        self.assertEqual(closed, ["thread-handle", "process-handle"])
        self.assertEqual(len(first), 2)
        self.assertEqual(second, [])

    def test_job_close_failure_is_reported_after_emergency_termination_check(self):
        calls = []
        kernel = SimpleNamespace(
            CloseHandle=lambda handle: calls.append(("close", handle)) or 0,
            TerminateJobObject=lambda handle, code: calls.append(("terminate", handle, code)) or 1,
        )
        job = object.__new__(supervision._WindowsJob)
        job.handle = "job-handle"
        job.api = SimpleNamespace(
            kernel32=kernel, error=lambda operation: "simulated error: " + operation,
        )
        job.wait_empty = mock.Mock(return_value=True)
        errors = job.close()

        self.assertTrue(any("CloseHandle(Job Object)" in error for error in errors))
        self.assertEqual(calls, [("close", "job-handle"), ("terminate", "job-handle", 1)])
        job.wait_empty.assert_called_once_with(5.0)
        self.assertIsNone(job.handle)


def _windows_console_available():
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.kernel32.GetConsoleCP())
    except Exception:
        return False


@unittest.skipUnless(os.name == "nt", "requires native Windows process APIs")
class NativeWindowsSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self._native_cleanup_callbacks = []

    def tearDown(self):
        for cleanup in reversed(self._native_cleanup_callbacks):
            cleanup()
        self.temp.cleanup()

    def test_safe_file_handle_flushes_regular_file(self):
        path = self.root / "safe-flush.bin"
        path.write_bytes(b"windows handle verification")
        digest, size = artifact_inventory.sha256_file(path)
        self.assertEqual(size, len(b"windows handle verification"))
        self.assertEqual(digest, hashlib.sha256(b"windows handle verification").hexdigest())
        artifact_inventory.sync_file(path)

    def test_relative_directory_scan_ignores_swapped_path_and_hashes_held_subtree(self):
        original = self.root / "nested"
        decoy = self.root / "nested-decoy"
        held_name = self.root / "nested-held"
        original.mkdir()
        decoy.mkdir()
        original_bytes = b"content from the directory handle"
        decoy_bytes = b"content from the swapped path"
        (original / "item.bin").write_bytes(original_bytes)
        (decoy / "item.bin").write_bytes(decoy_bytes)
        (decoy / "decoy-only.bin").write_bytes(b"must not be enumerated from the held handle")
        root_fd = artifact_inventory._open_windows_handle(self.root, os.O_RDONLY, 0, directory=True)
        original_info = artifact_inventory._path_stat(original)
        state = {"preopen_swapped": False, "swapped": False, "restored": False}

        try:
            original.rename(held_name)
            decoy.rename(original)
            state["preopen_swapped"] = True
            with self.assertRaises(artifact_inventory.FileVerificationError) as changed:
                with artifact_inventory.secure_directory(
                        original, original_info, root_fd, original.name):
                    self.fail("an exchanged directory must not be opened as the recorded subtree")
            self.assertEqual(changed.exception.code, "directory_changed_before_open")
            original.rename(decoy)
            held_name.rename(original)
            state["preopen_swapped"] = False

            with artifact_inventory.secure_directory(
                    original, original_info, root_fd, original.name, verify_names=False) as (directory_fd, names):
                self.assertEqual(names, ["item.bin"])
                original.rename(held_name)
                decoy.rename(original)
                state["swapped"] = True
                try:
                    self.assertEqual(artifact_inventory._windows_listdir(directory_fd), ["item.bin"])
                    _content, digest, _size = artifact_inventory.read_regular_file(
                        original / "item.bin", parent_fd=directory_fd, name="item.bin",
                    )
                    self.assertEqual(_content, original_bytes)
                    self.assertEqual(digest, hashlib.sha256(original_bytes).hexdigest())
                    self.assertNotEqual(digest, hashlib.sha256(decoy_bytes).hexdigest())
                finally:
                    original.rename(decoy)
                    held_name.rename(original)
                    state["restored"] = True
        finally:
            if state["swapped"] and not state["restored"]:
                if original.exists() and held_name.exists():
                    original.rename(decoy)
                    held_name.rename(original)
            elif state["preopen_swapped"] and held_name.exists() and original.exists():
                original.rename(decoy)
                held_name.rename(original)
            os.close(root_fd)
        self.assertTrue(state["swapped"])
        self.assertTrue(state["restored"])

    def test_handle_open_rejects_windows_reparse_leaf(self):
        path = self.root / "safe-flush.bin"
        path.write_bytes(b"windows handle verification")
        link = self.root / "reparse-leaf.bin"
        try:
            link.symlink_to(path)
        except (OSError, NotImplementedError):
            self.skipTest("Windows symlink creation is unavailable without the required privilege")
        with self.assertRaises(OSError):
            artifact_inventory.sha256_file(link)

    def test_junction_is_detected_as_a_reparse_point_without_traversal(self):
        target = self.root / "junction-target"
        junction = self.root / "junction-leaf"
        target.mkdir()
        (target / "secret.bin").write_bytes(b"external target")
        completed = subprocess.run(
            ["cmd.exe", "/c", "mklink", "/J", str(junction), str(target)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if completed.returncode != 0:
            self.skipTest("Windows junction creation is unavailable in this workspace")
        info = os.stat(str(junction), follow_symlinks=False)
        self.assertTrue(artifact_inventory.is_link_entry(junction, info))
        with self.assertRaises(OSError):
            artifact_inventory.sha256_file(junction)
        inventory = artifact_inventory.build_inventory(self.root)
        record = next(item for item in inventory["artifacts"] if item["path"] == junction.name)
        self.assertEqual(record["status"], "not_followed")
        self.assertIsNone(record["sha256"])

    def run_python(self, code, timeout=10, grace=0.2, cwd=None, env=None):
        return supervision.run_supervised_process(
            [sys.executable, "-c", code], Path(cwd or Path.cwd()), env or os.environ.copy(),
            self.root / "stdout.bin", self.root / "stderr.bin", timeout, grace,
        )

    def spawn_ready_python(self, code, ready_file):
        stdout = (self.root / "interactive-stdout.bin").open("wb")
        stderr = (self.root / "interactive-stderr.bin").open("wb")
        process, job, startup = supervision._spawn_windows(
            [sys.executable, "-c", code], self.root, os.environ.copy(), stdout, stderr,
        )

        cleaned = {"value": False}

        def cleanup_native_process():
            if cleaned["value"]:
                return
            try:
                if process.poll() is None:
                    try:
                        job.terminate(1)
                    finally:
                        process.wait(timeout=5)
            finally:
                job.close()
                process.close()
                stdout.close()
                stderr.close()
                cleaned["value"] = True

        self._native_cleanup_callbacks.append(cleanup_native_process)
        self.addCleanup(cleanup_native_process)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not ready_file.exists():
            if process.poll() is not None:
                break
            time.sleep(0.02)
        self.assertTrue(ready_file.exists(), "child did not report that its signal handler was ready")
        return process, job, startup

    def pipeline_runner(self, root):
        workspace = root / "workspace"
        workspace.mkdir()
        output = root / "evidence"
        output.mkdir()
        slow_command = ["-c", "import time; time.sleep(60)"]
        steps = [
            {"id": "first", "enabled": True, "args": slow_command, "parser": "text",
             "cwd": ".", "timeout_seconds": 10, "environment": {},
             "unset_environment": [], "redact_arg_indexes": []},
            {"id": "second", "enabled": True, "args": ["-c", "pass"], "parser": "text",
             "cwd": ".", "timeout_seconds": 10, "environment": {},
             "unset_environment": [], "redact_arg_indexes": []},
        ]
        config = {
            "schema_version": 1,
            "workspace_root": str(workspace),
            "execution": {
                "cargo_executable": sys.executable,
                "continue_on_error": True,
                "default_timeout_seconds": 10,
                "termination_grace_seconds": 0.2,
                "environment": {},
                "unset_environment": [],
            },
            "steps": steps,
            "_config_path": str(root / "pipeline.json"),
            "_config_sha256": "native-windows-test",
        }
        cargo_version = {"parsed": {"release": "1.91.1", "channel": "stable"}}
        environment = {"CARGO_HOME": str(root / "cargo-home")}
        fake_process_analysis = agent.analyze_cargo_invocation(
            ["supervision-test-command"], workspace, environment, cargo_version,
            agent.BUILD_PRODUCING_SUBCOMMANDS,
        )
        invocation_context = {
            step["id"]: {"analysis": fake_process_analysis}
            for step in steps
        }
        return agent.Runner(config, workspace, output, False, invocation_context=invocation_context)

    def assert_pid_exited(self, pid):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        kernel.WaitForSingleObject.restype = ctypes.c_ulong
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        handle = kernel.OpenProcess(0x00100000 | 0x00100000, False, int(pid))
        if not handle:
            self.assertIn(ctypes.get_last_error(), (87, 1168),
                          "OpenProcess failed for a reason other than an absent process")
            return
        try:
            self.assertEqual(kernel.WaitForSingleObject(handle, 0), 0,
                             "process {} remained alive after cleanup".format(pid))
        finally:
            kernel.CloseHandle(handle)

    def test_normal_exit_zero_and_regular_nonzero_exit(self):
        success = self.run_python("pass")
        self.assertEqual(success["native_exit_code"], 0)
        self.assertTrue(success["process_tree"]["cleanup_complete"])
        self.assertTrue(success["startup"]["cleanup_verified"])
        failure = self.run_python("raise SystemExit(7)")
        self.assertEqual(failure["native_exit_code"], 7)
        self.assertTrue(failure["process_tree"]["cleanup_complete"])

    def test_environment_working_directory_and_separate_output_files(self):
        env = os.environ.copy()
        env["CARGO_EVIDENCE_TEST_VALUE"] = "native-windows-value"
        result = self.run_python(
            "import os,sys; print(os.getcwd()); print(os.environ['CARGO_EVIDENCE_TEST_VALUE']); "
            "print('stderr-marker',file=sys.stderr)",
            cwd=self.root, env=env,
        )
        self.assertEqual(result["native_exit_code"], 0)
        self.assertIn(str(self.root).encode(), (self.root / "stdout.bin").read_bytes())
        self.assertIn(b"native-windows-value", (self.root / "stdout.bin").read_bytes())
        self.assertIn(b"stderr-marker", (self.root / "stderr.bin").read_bytes())

    def test_nonexistent_executable_reports_launch_failure(self):
        missing = self.root / "cargo-evidence-agent-no-such-program.exe"
        result = supervision.run_supervised_process(
            [str(missing)], Path.cwd(), os.environ.copy(),
            self.root / "stdout.bin", self.root / "stderr.bin", 2, 0.1,
        )
        self.assertIsNotNone(result["spawn_error"])
        self.assertEqual(result["startup"]["stage"], "executable_resolution")
        self.assertFalse(result["startup"]["process_created"])
        self.assertTrue(result["process_tree"]["cleanup_complete"])

    def test_createprocess_rejects_invalid_executable(self):
        invalid_program = self.root / "not-a-windows-executable.exe"
        invalid_program.write_bytes(b"not a PE image")
        result = supervision.run_supervised_process(
            [str(invalid_program)], Path.cwd(), os.environ.copy(),
            self.root / "stdout.bin", self.root / "stderr.bin", 2, 0.1,
        )
        self.assertIsNotNone(result["spawn_error"])
        self.assertEqual(result["startup"]["stage"], "create_process")
        self.assertFalse(result["startup"]["process_created"])
        self.assertTrue(result["process_tree"]["cleanup_complete"])

    def test_repeated_runs_release_process_job_and_duplicate_handles(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.argtypes = []
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.GetProcessHandleCount.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        kernel.GetProcessHandleCount.restype = ctypes.c_int

        def handle_count():
            count = ctypes.c_ulong(0)
            self.assertTrue(kernel.GetProcessHandleCount(kernel.GetCurrentProcess(), ctypes.byref(count)))
            return count.value

        warmup = self.run_python("pass")
        self.assertEqual(warmup["native_exit_code"], 0)
        before = handle_count()
        observed = [before]
        for _ in range(3):
            result = self.run_python("pass")
            self.assertEqual(result["native_exit_code"], 0)
            self.assertTrue(result["process_tree"]["cleanup_complete"])
            observed.append(handle_count())
        after = handle_count()
        self.assertEqual(after, before, observed)

    def test_timeout_terminates_and_verifies_job(self):
        result = self.run_python("import time; time.sleep(60)", timeout=0.2)
        self.assertTrue(result["timed_out"])
        self.assertTrue(result["process_tree"]["cleanup_complete"], result["process_tree"])
        self.assertTrue(result["process_tree"]["job_empty"])
        self.assert_pid_exited(result["startup"]["process_pid"])

    def test_interrupt_terminates_and_verifies_job(self):
        real_wait = supervision._WindowsProcess.wait
        first = {"value": True}

        def interrupt_once(process, timeout=None):
            if first["value"]:
                first["value"] = False
                raise KeyboardInterrupt()
            return real_wait(process, timeout)

        with mock.patch.object(supervision._WindowsProcess, "wait", new=interrupt_once):
            result = self.run_python("import time; time.sleep(60)", timeout=None)
        self.assertTrue(result["interrupted"])
        self.assertTrue(result["process_tree"]["cleanup_complete"], result["process_tree"])
        self.assert_pid_exited(result["startup"]["process_pid"])

    def test_root_exit_with_live_child_is_detected_and_cleaned(self):
        pid_file = self.root / "child.pid"
        child_code = "import time; time.sleep(60)"
        code = "import subprocess,sys; p=subprocess.Popen([sys.executable,'-c',{}]); open({},'w').write(str(p.pid))".format(
            repr(child_code), repr(str(pid_file)),
        )
        result = self.run_python(code, timeout=10, grace=0.1)
        self.assertEqual(result["native_exit_code"], 0)
        self.assertTrue(result["process_tree"]["descendants_detected"])
        self.assertTrue(result["process_tree"]["cleanup_complete"], result["process_tree"])
        self.assertTrue(pid_file.exists())
        self.assert_pid_exited(int(pid_file.read_text()))

    def test_multistage_process_tree_is_killed_after_timeout(self):
        child_pid = self.root / "child.pid"
        grandchild_pid = self.root / "grandchild.pid"
        child_script = self.root / "child.py"
        parent_script = self.root / "parent.py"
        child_script.write_text(
            "import subprocess,sys,time\n"
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
            "open(sys.argv[1],'w').write(str(p.pid))\n"
            "time.sleep(60)\n", encoding="utf-8",
        )
        parent_script.write_text(
            "import subprocess,sys,time\n"
            "p=subprocess.Popen([sys.executable,sys.argv[1],sys.argv[2]])\n"
            "open(sys.argv[3],'w').write(str(p.pid))\n"
            "time.sleep(60)\n", encoding="utf-8",
        )
        result = supervision.run_supervised_process(
            [sys.executable, str(parent_script), str(child_script), str(grandchild_pid), str(child_pid)],
            self.root, os.environ.copy(), self.root / "stdout.bin", self.root / "stderr.bin", 0.5, 0.1,
        )
        self.assertTrue(result["timed_out"])
        self.assertTrue(result["process_tree"]["cleanup_complete"], result["process_tree"])
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and (not child_pid.exists() or not grandchild_pid.exists()):
            time.sleep(0.02)
        self.assertTrue(child_pid.exists())
        self.assertTrue(grandchild_pid.exists())
        self.assert_pid_exited(int(child_pid.read_text()))
        self.assert_pid_exited(int(grandchild_pid.read_text()))

    @unittest.skipUnless(_windows_console_available(), "requires a shared Windows console")
    def test_ctrl_break_cooperative_handler_exits_without_job_fallback(self):
        ready_file = self.root / "cooperative-ready.txt"
        handled_file = self.root / "cooperative-handled.txt"
        code = (
            "import signal,time\n"
            "def handler(*_):\n"
            "    open({handled!r}, 'w').write('handled')\n"
            "    raise SystemExit(0)\n"
            "signal.signal(signal.SIGBREAK, handler)\n"
            "open({ready!r}, 'w').write('ready')\n"
            "while True: time.sleep(0.05)\n"
        ).format(handled=str(handled_file), ready=str(ready_file))
        process, job, _startup = self.spawn_ready_python(code, ready_file)

        started = time.monotonic()
        tree = job.terminate_tree(process, grace_seconds=3.0, reason="ctrl-break-cooperative-test")
        elapsed = time.monotonic() - started

        self.assertTrue(tree["term_signal_sent"], tree)
        self.assertTrue(handled_file.exists(), "signal-send success alone does not prove handler execution")
        self.assertFalse(tree["kill_signal_sent"], "cooperative exit must not use TerminateJobObject")
        self.assertTrue(tree["root_process_exited"], tree)
        self.assertTrue(tree["job_empty"], tree)
        self.assertTrue(tree["cleanup_verified"], tree)
        self.assertLess(elapsed, 3.0, "cooperative process did not exit within the grace period")
        self.assert_pid_exited(process.pid)

    @unittest.skipUnless(_windows_console_available(), "requires a shared Windows console")
    def test_ctrl_break_noncooperative_process_uses_job_fallback(self):
        ready_file = self.root / "noncooperative-ready.txt"
        child_ready = self.root / "noncooperative-child-ready.txt"
        child_pid_file = self.root / "noncooperative-child.pid"
        child_code = (
            "import signal,time\n"
            "signal.signal(signal.SIGBREAK, signal.SIG_IGN)\n"
            "open({ready!r}, 'w').write('ready')\n"
            "time.sleep(60)\n"
        ).format(ready=str(child_ready))
        code = (
            "import os,signal,subprocess,sys,time\n"
            "signal.signal(signal.SIGBREAK, signal.SIG_IGN)\n"
            "child=subprocess.Popen([sys.executable, '-c', {child!r}])\n"
            "open({pid!r}, 'w').write(str(child.pid))\n"
            "deadline=time.monotonic()+5\n"
            "while not os.path.exists({child_ready!r}) and time.monotonic()<deadline: time.sleep(0.01)\n"
            "open({ready!r}, 'w').write('ready')\n"
            "time.sleep(60)\n"
        ).format(child=child_code, pid=str(child_pid_file), child_ready=str(child_ready), ready=str(ready_file))
        process, job, _startup = self.spawn_ready_python(code, ready_file)

        tree = job.terminate_tree(process, grace_seconds=0.3, reason="ctrl-break-noncooperative-test")

        self.assertTrue(tree["term_signal_sent"], tree)
        self.assertTrue(tree["kill_signal_sent"], "noncooperative job must use TerminateJobObject")
        self.assertTrue(tree["root_process_exited"], tree)
        self.assertTrue(tree["job_empty"], tree)
        self.assertEqual(tree["active_members_after_cleanup"], 0)
        self.assertTrue(tree["cleanup_verified"], tree)
        self.assertTrue(child_pid_file.exists())
        self.assert_pid_exited(process.pid)
        self.assert_pid_exited(int(child_pid_file.read_text()))

    def test_native_job_assignment_failure_kills_unassigned_suspended_root(self):
        original_declare = supervision._WindowsNativeApi._declare_api

        def fail_assignment(api):
            original_declare(api)

            def fail(*_args):
                ctypes.set_last_error(5)
                return 0

            api.kernel32.AssignProcessToJobObject = fail

        with mock.patch.object(supervision._WindowsNativeApi, "_declare_api", new=fail_assignment):
            result = self.run_python("import time; time.sleep(60)")
        self.assertIsNotNone(result["supervision_error"])
        self.assertTrue(result["process_tree"]["cleanup_complete"], result["process_tree"])
        self.assertTrue(result["startup"]["root_process_exited"])
        self.assert_pid_exited(result["startup"]["process_pid"])

    def test_native_resume_failure_terminates_assigned_job(self):
        original_declare = supervision._WindowsNativeApi._declare_api

        def fail_resume(api):
            original_declare(api)

            def fail(_thread_handle):
                ctypes.set_last_error(5)
                return 0xFFFFFFFF

            api.kernel32.ResumeThread = fail

        with mock.patch.object(supervision._WindowsNativeApi, "_declare_api", new=fail_resume):
            result = self.run_python("import time; time.sleep(60)")
        self.assertIsNotNone(result["supervision_error"])
        self.assertTrue(result["process_tree"]["cleanup_complete"], result["process_tree"])
        self.assertTrue(result["startup"]["job_assigned"])
        self.assertFalse(result["startup"]["thread_resumed"])
        self.assert_pid_exited(result["startup"]["process_pid"])

    def test_pipeline_reports_verified_job_assignment_failure_as_supervision_error(self):
        original_declare = supervision._WindowsNativeApi._declare_api

        def fail_assignment(api):
            original_declare(api)

            def fail(*_args):
                ctypes.set_last_error(5)
                return 0

            api.kernel32.AssignProcessToJobObject = fail

        with tempfile.TemporaryDirectory() as temp:
            runner = self.pipeline_runner(Path(temp))
            with mock.patch.object(supervision._WindowsNativeApi, "_declare_api", new=fail_assignment):
                runner.execute()

        first, second = runner.steps
        self.assertEqual(first["status"], "supervision_error")
        self.assertTrue(first["process_tree"]["cleanup_verified"], first["process_tree"])
        self.assertTrue(first["process_tree"]["root_process_exited"], first["process_tree"])
        self.assertTrue(first["process_tree"]["job_empty"], first["process_tree"])
        self.assertTrue(first["process_tree"]["kill_signal_sent"], first["process_tree"])
        self.assertIn("AssignProcessToJobObject", first["supervision_error"])
        self.assertEqual(second["status"], "not_run_fail_fast")
        summary = runner.make_summary()
        self.assertEqual(summary["status"], "error")
        self.assertEqual(summary["supervision_error_steps"], 1)
        self.assertEqual(summary["not_run_steps"], 1)

    def test_pipeline_reports_verified_resume_failure_as_supervision_error(self):
        original_declare = supervision._WindowsNativeApi._declare_api

        def fail_resume(api):
            original_declare(api)

            def fail(_thread_handle):
                ctypes.set_last_error(5)
                return 0xFFFFFFFF

            api.kernel32.ResumeThread = fail

        with tempfile.TemporaryDirectory() as temp:
            runner = self.pipeline_runner(Path(temp))
            with mock.patch.object(supervision._WindowsNativeApi, "_declare_api", new=fail_resume):
                runner.execute()

        first, second = runner.steps
        self.assertEqual(first["status"], "supervision_error")
        self.assertTrue(first["process_tree"]["cleanup_verified"], first["process_tree"])
        self.assertTrue(first["process_tree"]["job_empty"], first["process_tree"])
        self.assertTrue(first["process_tree"]["kill_signal_sent"], first["process_tree"])
        self.assertTrue(first["process_startup"]["job_assigned"])
        self.assertFalse(first["process_startup"]["thread_resumed"])
        self.assertEqual(second["status"], "not_run_fail_fast")
        self.assertEqual(runner.make_summary()["supervision_error_steps"], 1)

    def test_pipeline_stops_when_final_process_verification_fails(self):
        def fail_final_verification(_job):
            raise supervision.ProcessSupervisionError("simulated final Job Object query failure")

        with tempfile.TemporaryDirectory() as temp:
            runner = self.pipeline_runner(Path(temp))
            runner.config["steps"][0]["args"] = ["-c", "pass"]
            with mock.patch.object(supervision._WindowsJob, "active_processes", new=fail_final_verification):
                runner.execute()

        first, second = runner.steps
        self.assertEqual(first["status"], "process_cleanup_failed")
        self.assertFalse(first["process_tree"]["cleanup_verified"], first["process_tree"])
        self.assertFalse(first["process_tree"]["cleanup_complete"], first["process_tree"])
        self.assertIn("simulated final Job Object query failure", first["process_tree"]["errors"][0])
        self.assertEqual(second["status"], "not_run_fail_fast")
        summary = runner.make_summary()
        self.assertEqual(summary["status"], "error")
        self.assertEqual(summary["process_cleanup_failed_steps"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
