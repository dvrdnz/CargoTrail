# Contributing

## Development setup

- CPython 3.8 or newer.
- Rust stable (`cargo` and `rustc`) for the real Cargo integration tests.
- No third-party Python dependencies for running the application or tests.

Run the checks before opening a pull request:

```bash
python -m compileall -q .
CARGO_INTEGRATION_REQUIRED=1 CARGO_NET_OFFLINE=true python -m unittest discover -s tests -v
```

On Windows PowerShell:

```powershell
$env:CARGO_INTEGRATION_REQUIRED = '1'
$env:CARGO_NET_OFFLINE = 'true'
python -m unittest discover -s tests -v
```

## Change guidelines

- Keep all source code, comments, documentation, examples, and user-facing messages in English.
- Preserve the explicit-config model: do not add implicit Cargo commands or inject unrequested arguments.
- Treat evidence schemas and digest contracts as compatibility surfaces. Document and test intentional changes.
- Add regression tests for security-sensitive filesystem and process-supervision behavior. Prefer deterministic fault injection over timing-dependent tests.
- Keep runtime dependencies in the Python standard library. Build-only dependencies belong in `requirements-build.txt`.
- Do not describe the runner as a sandbox or claim that hashes are authenticated attestations.

## Pull requests

Describe the behavior change, the regression it addresses, the tests run, and any platform-specific limitations. Include native test evidence for changes to POSIX or Windows APIs; mocks on another operating system do not replace native validation.


## Licensing

By submitting a contribution, you agree that your contribution is provided under the Mozilla Public License 2.0 (MPL-2.0). Preserve existing license notices and add the MPL-2.0 Exhibit A notice to new source files. Do not submit third-party code unless its license and provenance have been reviewed and documented.
