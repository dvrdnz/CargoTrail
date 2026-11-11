# Process supervision

Each configured Cargo command runs under a dedicated process-tree supervisor. A step cannot be reported as `passed` unless its direct process completed successfully and cleanup of the supervised process tree was verified.

## POSIX systems

Each command starts in a new session. The supervisor discovers and signals process groups inside that session. On Linux, it additionally inspects `/proc/<pid>/stat`, which detects descendants that create a separate process group with `setpgid()` while remaining in the original session. Zombies are not counted as live executable processes.

On timeout, interruption, termination signal, or supervisor error, the agent sends `SIGTERM`, waits through the configured grace period, then sends `SIGKILL` to remaining groups. It rediscovers members during forced cleanup, reaps the direct child, and verifies that no live session members remain.

On macOS and POSIX systems without Linux `/proc`, the local `ps` command enumerates processes owned by the current real UID, including processes without a controlling terminal (`-x`); the supervisor obtains each listed process's session ID separately with `getsid(2)`. The terminal-less selection is required for CI-launched descendants, which commonly have no controlling terminal. The implementation does not use `ps`'s `sess` field as a session identifier or query session metadata for unrelated users. A process that exits during the scan is ignored as a normal race. Permission or parsing failures make the inventory incomplete. An empty process snapshot does not by itself prove that the direct child exited: cleanup still signals the known initial process group and requires both the child to be reaped and a complete empty session inventory before reporting success.

A descendant that deliberately calls `setsid()` leaves the session controlled by the runner. This is a documented boundary, not a sandbox guarantee.

## Windows

Each command receives its own Windows Job Object configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.

1. The Job Object is created and configured.
2. Cargo is created suspended with a restricted inherited-handle list.
3. The process is assigned to the Job Object before its primary thread resumes.
4. Descendants inherit Job membership by default; breakaway flags are not enabled.
5. Normal completion checks for remaining Job members. Orphaned descendants are recorded and terminated.
6. Timeout or interruption first requests graceful console termination, then uses `TerminateJobObject()` if active processes remain.
7. Closing the Job Object handle is an additional kill-on-close safeguard.

If Job assignment is unavailable, the runner refuses to start an unsupervised process. It does not fall back to supervising only the Cargo parent.

The ordinary Windows real-Cargo test suite selects LLVM `lld-link` explicitly as its control linker through Cargo's target-specific linker environment variable. A separate `windows-linker-diagnostics` CI matrix runs the three previously affected real-Cargo tests with both the native MSVC default linker and `lld-link`. The MSVC lane remains non-gating while its known ancillary-process handling is verified; its result and diagnostic artifact remain visible. The LLD lane is gating. Both variants use the same tests and Job Object containment.

Microsoft's BuildXL source documents `VCTIP.EXE` as a surviving child process that MSVC compiler tooling (`cl.exe`) may create. CargoTrail recognizes only the executable at the canonical Visual Studio x64 MSVC toolset path (`Microsoft Visual Studio\<instance>\<edition>\VC\Tools\MSVC\<version>\bin\Hostx64\x64\vctip.exe`). If, after the leader exits, every remaining Job Object member matches that exact image layout, CargoTrail classifies them as expected ancillary processes, terminates the Job Object, and still requires the root process to be reaped and the Job Object to be empty. These processes do not break away or survive cleanup. Any additional, unrecognized, or unverifiable member remains an unexpected orphan and causes the command to fail.

When a Job Object remains non-empty after the Cargo leader exits and the drain window expires, the supervisor logs every active member with its PID, parent PID when available, executable basename and full image path, process creation timestamp in UTC when available, observation timestamp, and active Job Object membership. Parent PID and process creation time are best-effort diagnostic metadata only. A zero-time process-handle wait reports whether the process handle is still active or signaled when `SYNCHRONIZE` access is granted; otherwise the state is recorded as unavailable. This is not a scheduler run/wait state. None of these fields affects the authoritative Job Object process list or cleanup decision. The Windows CI diagnostic job also archives toolchain discovery and before/after `vctip.exe` process snapshots. None of this exempts a process from Job Object supervision or changes the production linker selection.

## Status model

| Situation | Step status |
|---|---|
| Exit code is zero and no descendants remain | `passed`, subject to evidence requirements |
| Exit code is zero and only canonical MSVC VCTIP ancillary processes remain; they are terminated and Job Object emptiness is verified | `passed`, subject to evidence requirements |
| Command exits but leaves other or unverifiable descendants that are then cleaned up | `failed` |
| Timeout and cleanup is verified | `timed_out` |
| User interruption and cleanup is verified | `interrupted` |
| Process could not be started | `launch_error` |
| Supervision failed but cleanup was verified | `supervision_error` |
| Process-tree termination or reaping cannot be verified | `process_cleanup_failed` |

Technical launch/supervision errors and unverified cleanup stop the pipeline regardless of `continue_on_error`. Ordinary Cargo failures follow the configured continuation policy.

## Scope and limitations

The agent is not a sandbox. It does not isolate filesystem, network, credentials, kernel interfaces, or native build tools. POSIX descendants can deliberately escape by creating a new session. Run untrusted source trees in an appropriately restricted container, sandbox, or virtual machine.
