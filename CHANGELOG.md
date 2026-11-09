# Changelog

This changelog records user-visible changes.

## [1.5.1] - 2026-11-08

### Changed

- Renamed the project and command-line application to CargoTrail.

### Fixed

- Recognize `cargo fmt` and `cargo clippy` as known Rustup external subcommands independently of the reviewed Cargo built-in command inventory window.
- Close an already-open file descriptor when parent-directory revalidation fails after a leaf has been opened.
- Close writer descriptors when a post-open operation or parent-directory revalidation fails.
- Centralize directory-handle cleanup to avoid closing the same descriptor twice on verification failures.

### Added

- Adopted the Mozilla Public License 2.0 (MPL-2.0) for original project files and added SPDX/Exhibit A source notices.
- Added a third-party dependency and licensing inventory.
- Included license documents and an exact source-tag pointer in platform release archives.
- Regression coverage for Cargo `fmt` and `clippy` classification on newer Cargo versions.
- Fault-injection coverage for file and writer descriptor cleanup and directory-handle close behavior.
- A `--version` command-line option.
- GitHub Actions release automation for native standalone binaries and SHA-256 checksums.

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
