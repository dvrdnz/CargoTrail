# Changelog

This changelog records user-visible changes.

## [1.5.1] - 2026-11-08

### Changed

- Renamed the project and command-line application to CargoTrail.
- Matched workspace-inventory exclusions case-insensitively on Windows and macOS and case-sensitively on other systems. This is a platform default, not a probe of the actual file system, so case-sensitive macOS volumes and case-insensitive mounts on Linux are not detected.
- Canonicalized Cargo configuration file paths by expanding Windows short (8.3) names and resolving aliased parent directories on POSIX systems (for example `/var` on macOS). A symlinked configuration file is still detected as a symlink.

### Fixed

- Recognize `cargo fmt` and `cargo clippy` as known Rustup external subcommands independently of the reviewed Cargo built-in command inventory window.
- Close an already-open file descriptor when parent-directory revalidation fails after a leaf has been opened.
- Close writer descriptors when a post-open operation or parent-directory revalidation fails.
- Centralize directory-handle cleanup to avoid closing the same descriptor twice on verification failures.
- Identify POSIX session members on macOS and other systems without procfs by listing the current user's processes, including those without a controlling terminal, and reading each session ID with `getsid(2)`. macOS `ps` reports zero for its `sess` field, which therefore could not identify a session.
- Stop treating an empty or incomplete POSIX process snapshot as proof of cleanup: the known initial process group is always signalled, and cleanup succeeds only after the direct child is reaped and a complete session inventory is empty.
- Wait for a Windows Job Object to drain after the leader exits before treating remaining members as orphaned descendants.
- Do not fail an otherwise successful Windows command when the only remaining Job Object member is `vctip.exe`, the telemetry uploader of the installed Visual Studio x64 MSVC toolset. It is terminated and Job Object emptiness is still verified; any other or unverifiable member is still reported as an orphan.

### Added

- Adopted the Mozilla Public License 2.0 (MPL-2.0) for original project files and added SPDX/Exhibit A source notices.
- Added a third-party dependency and licensing inventory.
- Added a security policy (`SECURITY.md`).
- Included license documents, the license of the bundled Python runtime (`PYTHON-LICENSE.txt`), and an exact source-tag pointer in platform release archives. Packaging fails if the Python license file cannot be found.
- Regression coverage for Cargo `fmt` and `clippy` classification on newer Cargo versions.
- Fault-injection coverage for file and writer descriptor cleanup and directory-handle close behavior.
- A `--version` command-line option.
- GitHub Actions release automation for native standalone binaries and SHA-256 checksums.
- Logging of the members (PID, parent PID, image path, and creation time) of a Windows Job Object that outlives its leader, in the runner log.
- Regression coverage for macOS terminal-less process discovery, MSVC `vctip.exe` handling, platform-dependent exclusion matching, and release-archive contents.
- Release gating in CI: the documented minimum Python version (3.8) and the real-Cargo tests on Windows with both the MSVC and LLD linkers must pass before release binaries are built.

## [1.5.0]

- Added optional versioned execution profiles and a deterministic fingerprint of the normalized, redacted execution definition.
- Added execution provenance for Cargo/Rust toolchains, workspace state, runtime source files, configuration, and observed probe output.
- Added verified artifact inventories and archive-integrity sidecars.
- Hardened file identity checks, no-follow reads, directory traversal, evidence finalization, and archive verification.
- Improved Cargo invocation analysis, alias resolution, evidence-policy enforcement, and interruption handling.
- Added structured Python-agent logging and process-tree supervision on POSIX and Windows.

## [1.4.0]

- Added a dedicated per-run `runner.log` with UTC timestamps, process IDs, log levels, redaction, and lifecycle details.
- Added deterministic logging-handler cleanup and archive inclusion for the Python-agent log.

## [1.3.0]

- Added POSIX session/process-group supervision and Windows Job Object supervision.
- Added process-tree cleanup verification and a `process_cleanup_failed` status.
- Added real offline Cargo integration tests for successful builds, compiler errors, and test failures.
- Added cross-platform CI coverage for Linux, Windows, and macOS.
