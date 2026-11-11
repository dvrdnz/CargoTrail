# CargoTrail

**Verifiable build provenance for Rust.**

**Version 1.5.1** · A cross-platform evidence and provenance tool for Cargo builds.

CargoTrail runs explicitly configured Cargo pipelines and records structured evidence about execution, build results, workspace changes, toolchain selection, and generated artifacts. It gives CI pipelines a verifiable record beyond a process exit code.

The agent executes only the arguments declared in the JSON configuration. It does not add Cargo flags, invent a default pipeline, invoke a shell, or claim to sandbox the build.

## Features

- **Explicit pipelines:** ordered Cargo commands, working directories, timeouts, environment overrides, and evidence requirements are configuration-controlled.
- **Process-tree supervision:** POSIX session/process-group supervision and Windows Job Objects; cleanup is verified before a step can pass.
- **Cargo-aware evidence:** parses Cargo JSON events and libtest summaries, and distinguishes process success from build and test evidence.
- **Execution provenance:** records Cargo/Rust versions, selected manifests and targets, relevant Cargo configuration, and runtime-source fingerprints.
- **Workspace and artifact inventories:** SHA-256 fingerprints, file-identity checks, and explicit reporting of unstable or unsupported entries.
- **Verified archives:** creates a TAR.GZ evidence archive and integrity sidecar after checking the archive against the finalized evidence tree.
- **No runtime Python dependencies:** the source version uses only the Python standard library.
- **Standalone release binaries:** tagged GitHub releases build native binaries for supported platforms (see [Releases](#release-binaries)).

## Requirements

For the source version:

- CPython 3.8 or newer.
- Rust stable with `cargo` and `rustc` available on `PATH`.
- Linux, macOS, or Windows 10/11 or a supported Windows Server release.

The included example also uses `cargo fmt` and `cargo clippy`. Install those Rust components if they are not already available:

```bash
rustup component add rustfmt clippy
```

The real Cargo integration tests require Rust. Unit and process-supervision tests can be run without it, but CI sets `CARGO_INTEGRATION_REQUIRED=1` so missing Cargo or Rustc fails the job instead of silently skipping integration tests.

## Quick start

1. Clone or download this repository.
2. Copy `examples/rust-workspace.json` into your Rust workspace and adjust the configured steps as needed. The example uses `workspace_root: "."`, so place the file at the workspace root or pass `--root` explicitly.
3. Validate the configuration without executing the configured build steps:

```bash
python cargotrail.py \
  --config /path/to/rust-workspace.json \
  --root /path/to/rust-workspace \
  --validate-config
```

4. Run the pipeline and create a verified evidence archive:

```bash
python cargotrail.py \
  --config /path/to/rust-workspace.json \
  --root /path/to/rust-workspace \
  --output-dir /path/to/evidence/run-001 \
  --archive
```

The output directory must not already contain files. A run creates structured JSON evidence, per-step process output, and `runner.log`. With `--archive`, it also creates a TAR.GZ and a separate `.integrity.json` sidecar.

## Command-line options

```text
--config PATH        Required JSON pipeline configuration
--root PATH          Override workspace_root; must contain Cargo.toml
--output-dir PATH    Evidence directory; must be empty if it already exists
--archive            Create a verified POSIX-PAX TAR.GZ beside the evidence directory
--dry-run            Print the redacted command plan without executing configured steps
--validate-config    Validate configuration and Cargo invocation policy without running steps
--log-level LEVEL    DEBUG, INFO, WARNING, or ERROR (default: INFO)
--version            Print the agent version
--help               Show command-line help
```

The `--dry-run` and `--validate-config` modes still perform Cargo version preflight for each enabled step. They do not execute configured build, test, formatter, alias-target, or custom subcommands.

## Configuration

A pipeline is a JSON object with a required `schema_version`, `workspace_root`, and non-empty `steps` array. Each step declares its own ID, exact Cargo argument array, parser, working directory, and optional timeout and evidence requirements. `execution` controls the Cargo executable, timeouts, environment, and whether ordinary failed steps allow later steps to continue. An optional `profile` identifies a versioned execution definition; it does not introduce inheritance or a second pipeline format.

Start with [`examples/rust-workspace.json`](examples/rust-workspace.json). The full field reference, command-classification rules, and evidence-policy semantics are documented in [Configuration](docs/configuration.md).

**Important:** arguments are passed directly to Cargo with `shell=False`. Shell operators, variable expansion, pipes, and shell scripts are not interpreted. Configure every command explicitly.

## Evidence outputs

A regular run produces these primary files:

| File | Purpose |
|---|---|
| `manifest.json` | Run identity, configuration fingerprint, status, and references to evidence and provenance |
| `summary.json` | Overall result and per-status counters |
| `provenance.json` | Agent/runtime identity and per-step Cargo/Rust toolchain and configuration observations |
| `workspace-inventory.json` | Before/after workspace observations and digests |
| `artifact-inventory.json` | Inventory, sizes, hashes, roles, and verification status of evidence files |
| `config.redacted.json` | Normalized configuration with environment values and configured sensitive arguments redacted |
| `runner.log` | Python-agent lifecycle and process-supervision log |
| `<step-id>/` | One folder per configured step, named after its `id` and located directly in the evidence directory: process output, Cargo events, diagnostics, and test summaries |

When archive creation is requested, the archive is verified against the finalized evidence tree. The sidecar records archive and inventory hashes. These are integrity checks, not signatures or authenticated attestations.

## Process supervision and security model

Each configured command is supervised as a process tree. On POSIX, the agent uses a dedicated session and discovers/signals process groups; Linux additionally inspects `/proc`. On Windows, each command is assigned to a Job Object configured to terminate members when the job handle closes. The agent fails closed when supervision cannot be established or cleanup cannot be verified.

This is **not a sandbox**. A POSIX descendant that deliberately creates a new session can leave the supervised session. Build scripts and native tools execute with the permissions of the user running the agent. Run untrusted projects inside an OS sandbox, container with appropriate restrictions, or virtual machine.

More detail is available in [Process supervision](docs/process-supervision.md) and [Evidence, provenance, and integrity](docs/evidence-and-integrity.md).

## Run tests

```bash
python -m compileall -q .
python -m unittest discover -s tests -v
```

To require the real Cargo integration tests:

```bash
CARGO_INTEGRATION_REQUIRED=1 CARGO_NET_OFFLINE=true \
  python -m unittest discover -s tests -v
```

On Windows PowerShell:

```powershell
$env:CARGO_INTEGRATION_REQUIRED = '1'
$env:CARGO_NET_OFFLINE = 'true'
python -m unittest discover -s tests -v
```

See [Contributing](CONTRIBUTING.md) for development and CI details.

## Release binaries

Tagged releases build native, single-file binaries on GitHub Actions for:

- Linux x86-64 and ARM64.
- Windows x86-64.
- macOS Intel x86-64 and Apple Silicon ARM64.

The binaries include the Python runtime and the agent's four source modules needed for runtime provenance. They do **not** include Cargo or Rust; install Rust separately and ensure `cargo` and `rustc` are available when running a pipeline. The Linux builds are produced on Ubuntu 24.04, so older distributions with an older GNU C Library (glibc) may not be compatible.

On Linux and macOS, extract the `.tar.gz` asset and run:

```bash
chmod +x cargotrail
./cargotrail --version
```

On Windows, run the downloaded `.exe` from PowerShell or Command Prompt:

```powershell
.\cargotrail.exe --version
```

Each binary archive includes `LICENSE`, `README.md`, `THIRD_PARTY_NOTICES.md`, `PYTHON-LICENSE.txt` (license of the bundled Python runtime), and `SOURCE-CODE.txt` pointing to the exact source tag. The release workflow also publishes `SHA256SUMS.txt`. Verify downloaded assets before use. Binaries are not code-signed or notarized by the default workflow. See [Building and releasing](docs/releasing.md) for local build instructions and the tag-based release process.

## License

Unless a file states otherwise, the original source code, documentation, examples, and project configuration in this repository are licensed under the **Mozilla Public License 2.0 (MPL-2.0)**. See [`LICENSE`](LICENSE) for the complete license text. The SPDX identifier is `MPL-2.0`.

Third-party components remain under their own licenses. The application has no third-party Python runtime dependencies; build-time and bundled-runtime licensing notes are documented in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
