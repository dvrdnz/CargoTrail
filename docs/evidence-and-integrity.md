# Evidence, provenance, and integrity

The agent separates process execution, Cargo build outcomes, test outcomes, workspace observations, and evidence completeness. These are related signals, not interchangeable claims.

## Cargo evidence

Cargo JSON is line-oriented. The agent records structured compiler messages and Cargo build-finished events. For `cargo test`, the test process may continue after the build event, so a successful build event is not proof that tests passed. The libtest parser requires a complete final test summary; individual `test ... ok` lines are not enough.

The configuration's parser and evidence requirements determine which signals are mandatory. Invalid or contradictory structured evidence is not silently downgraded to a passing result. `continue_on_error` controls later steps after ordinary failed or incomplete results; it cannot convert incomplete evidence into a passing pipeline.

## Provenance

`provenance.json` and the `provenance` object in `manifest.json` record:

- Agent version, runtime source files, Python runtime, and platform.
- Original configuration byte digest and normalized redacted configuration digest.
- Per-step Cargo and Rustc probes, selected toolchain, manifest, target, and output directories.
- Relevant Cargo configuration files and effective build settings.
- Cargo metadata probe observations and lockfile state.
- Workspace inventories before and after execution.

Environment values are not copied into evidence as plain values. Sensitive argument positions are redacted. Environment names suggesting tokens, passwords, secrets, keys, credentials, or authentication are redacted; registry URL credentials and sensitive query values are also redacted. The PATH value is represented by a digest and entry count.

Process output (the stdout and stderr of Cargo, build scripts, and tests) is stored verbatim in the step folders and is not redacted. A build script that prints a secret leaves it in the evidence, so handle evidence directories, archives, and uploaded CI artifacts as potentially sensitive.

## Workspace inventory

The before/after inventories record observed files and directories in the configured workspace. Regular files are hashed in fixed-size blocks, with file identity and metadata checked before and after reading. Symlinks, reparse points, special files, unreadable entries, and unstable entries are not followed as regular files. Cargo target/build directories and evidence output are excluded explicitly. Exclusions are matched case-insensitively on Windows and macOS, where volumes are case-insensitive by default, and case-sensitively on other systems, so an exclusion never hides a differently cased directory there. This is a platform default, not a probe of the actual file system: a case-sensitive macOS volume or a case-insensitive mount on Linux is not detected.

The inventory is an observation, not an atomic snapshot or filesystem lock. It covers the configured workspace only. Registry and Git sources, external path dependencies, Cargo caches, native tools, operating-system inputs, and network services are outside its scope.

## Artifact inventory and archive verification

`artifact-inventory.json` lists evidence files with relative paths, roles, producers, byte sizes, SHA-256 hashes, and verification status. Reads use held file and directory handles where supported. Files that change while being hashed do not receive a trusted digest.

When archive creation is requested, the agent verifies the archive against the finalized evidence snapshot. It rejects unsafe paths, duplicate names, unexpected entries, hard links, unsupported TAR types, changed symlink targets, and directory identity changes. A failed verification removes the archive and does not publish a success sidecar. The sidecar contains the archive hash and size, inventory hash and digest, and manifest hash.

## Digest scope and limitations

SHA-256 values in the evidence identify bytes or canonicalized observations within a defined scope. They are consistency and integrity values; they are not signatures, authenticated attestations, or proof that external tools and the host operating system are trustworthy.

In particular:

- The configuration byte digest changes with whitespace and key order; the semantic digest covers normalized redacted configuration.
- Redacted values are intentionally not compared by semantic digests.
- The execution-profile definition digest excludes workspace contents and runtime observations.
- The workspace digest covers only the configured workspace inventory and is not an atomic snapshot.
- Runtime source digests cover the four explicitly listed local source files; they do not identify the distribution archive or attest the Python interpreter, Cargo, Rustc, native tools, or OS.
- The evidence inventory digest is not an archive hash or signature. Archive and sidecar hashes are checked separately.
