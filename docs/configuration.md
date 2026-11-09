# Configuration reference

The configuration is a UTF-8 JSON object. The supported schema version is currently `1`. Unknown keys are rejected so that misspelled or unsupported settings cannot be silently ignored.

## Top-level fields

| Field | Required | Description |
|---|---:|---|
| `schema_version` | Yes | Must be the integer `1`. |
| `workspace_root` | Yes | Workspace directory containing `Cargo.toml`; relative paths are resolved from the configuration file. |
| `execution` | No | Cargo executable, error continuation, timeouts, environment overrides, and environment variables to unset. |
| `steps` | Yes | Non-empty ordered array of explicitly declared Cargo commands. |
| `profile` | No | Optional logical profile ID, positive revision, and description. |

## Execution settings

| Field | Default | Description |
|---|---|---|
| `cargo_executable` | `cargo` | Executable invoked directly; no shell is involved. |
| `continue_on_error` | `true` | Continue after ordinary command failures. Technical supervision errors and invalid evidence always stop the pipeline. |
| `default_timeout_seconds` | `null` | Default timeout for steps without an override. |
| `termination_grace_seconds` | `5` | Grace period between graceful and forced process-tree termination. |
| `environment` | `{}` | Additional environment values. Values are redacted in evidence. |
| `unset_environment` | `[]` | Environment names removed before each command. |

An environment variable cannot be present in both `environment` and `unset_environment` at the same scope.

## Step settings

Each step is an object with these fields:

| Field | Required | Description |
|---|---:|---|
| `id` | Yes | Unique stable identifier matching `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`. |
| `args` | Yes | Non-empty array of strings passed to Cargo exactly as configured. |
| `enabled` | No | Defaults to `true`. Disabled steps are retained in the execution definition but are not run. |
| `parser` | No | `text`, `cargo-json`, or `cargo-json+libtest`; defaults to `text`. |
| `cwd` | No | Directory relative to `workspace_root`; defaults to `.`. It cannot escape the workspace root. |
| `timeout_seconds` | No | Positive timeout or `null` to use the execution default. |
| `environment` | No | Step-specific environment values. |
| `unset_environment` | No | Step-specific environment names to remove. |
| `redact_arg_indexes` | No | Argument indexes masked in logs and redacted configuration output. |
| `evidence_requirements` | No | Explicit requirements for Cargo JSON events, `build-finished`, and test summaries. |

### Parser behavior

- `text` stores command output as text. Cargo build evidence is not inferred from arbitrary text.
- `cargo-json` requires valid Cargo JSON events. Build-producing Cargo commands require a successful `build-finished` event unless the validated configuration explicitly defines a non-build evidence contract for a resolved custom command.
- `cargo-json+libtest` requires valid Cargo JSON events, a successful build-finished event, and a complete libtest summary by default.

A zero-test result is not a positive test result unless `allow_zero_tests` is explicitly enabled in a test-summary contract. A process exit code of zero alone does not establish successful build or test evidence.

## Example

The repository includes [`../examples/rust-workspace.json`](../examples/rust-workspace.json), which declares formatting, Clippy, tests, and a release build. Adapt it to the target workspace and remove or add steps explicitly. No command is inserted implicitly.

## Cargo command resolution

The agent parses Cargo global options, toolchain selectors, command-local options, and configured aliases for preflight, policy enforcement, and provenance. Alias expansion is used for analysis only; the executed argument vector remains the configured one. The agent does not execute alias targets, external commands, scripts, or shell fragments during preflight.

Known Rustup external subcommands `fmt` and `clippy` are identified independently of the version-reviewed Cargo built-in inventory. Other unrecognized names remain subject to the conservative command-classification rules in the provenance report.
