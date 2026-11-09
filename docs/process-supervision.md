# Process supervision

Each configured Cargo command runs under a dedicated process-tree supervisor. A step cannot be reported as `passed` unless its direct process completed successfully and cleanup of the supervised process tree was verified.

## POSIX systems

Each command starts in a new session. The supervisor discovers and signals process groups inside that session. On Linux, it additionally inspects `/proc/<pid>/stat`, which detects descendants that create a separate process group with `setpgid()` while remaining in the original session. Zombies are not counted as live executable processes.

On timeout, interruption, termination signal, or supervisor error, the agent sends `SIGTERM`, waits through the configured grace period, then sends `SIGKILL` to remaining groups. It rediscovers members during forced cleanup, reaps the direct child, and verifies that no live session members remain.

On macOS and POSIX systems without Linux `/proc`, session members are enumerated with the local `ps` command. If enumeration is unavailable, the agent may attempt the original process group as a best-effort cleanup, but marks enumeration incomplete. Incomplete visibility cannot be reported as successful cleanup.

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

## Status model

| Situation | Step status |
|---|---|
| Exit code is zero and no descendants remain | `passed`, subject to evidence requirements |
| Command exits but leaves descendants that are then cleaned up | `failed` |
| Timeout and cleanup is verified | `timed_out` |
| User interruption and cleanup is verified | `interrupted` |
| Process could not be started | `launch_error` |
| Supervision failed but cleanup was verified | `supervision_error` |
| Process-tree termination or reaping cannot be verified | `process_cleanup_failed` |

Technical launch/supervision errors and unverified cleanup stop the pipeline regardless of `continue_on_error`. Ordinary Cargo failures follow the configured continuation policy.

## Scope and limitations

The agent is not a sandbox. It does not isolate filesystem, network, credentials, kernel interfaces, or native build tools. POSIX descendants can deliberately escape by creating a new session. Run untrusted source trees in an appropriately restricted container, sandbox, or virtual machine.
