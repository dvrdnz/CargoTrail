#!/usr/bin/env python3
"""Smoke-test a built CargoTrail executable against a minimal real Cargo crate."""

# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_SOURCES = frozenset(
    {"cargotrail.py", "process_supervision.py", "provenance.py", "artifact_inventory.py"}
)
LIB_RS = (
    "pub fn add(a: u32, b: u32) -> u32 { a + b }\n"
    "#[cfg(test)]\n"
    "mod tests {\n"
    "    use super::*;\n"
    "    #[test]\n"
    "    fn adds() { assert_eq!(add(1, 2), 3); }\n"
    "}\n"
)


class SmokeFailure(Exception):
    """Raised when an expectation about the executable is not met."""


def run(command, cwd, env, timeout=600):
    """Run a command without a shell and return its combined output."""
    completed = subprocess.run(
        [str(part) for part in command],
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
        universal_newlines=True,
        encoding="utf-8",
        errors="replace",
    )
    return completed.returncode, completed.stdout


def expect(condition, message):
    if not condition:
        raise SmokeFailure(message)


def pipeline_config():
    steps = [
        {
            "id": "build",
            "args": ["build", "--locked", "--offline", "--message-format=json"],
            "parser": "cargo-json",
            "cwd": ".",
            "evidence_requirements": {
                "require_valid_json_events": True,
                "require_build_finished": True,
            },
        },
        {
            "id": "test",
            "args": ["test", "--locked", "--offline", "--message-format=json"],
            "parser": "cargo-json+libtest",
            "cwd": ".",
            "evidence_requirements": {
                "require_valid_json_events": True,
                "require_build_finished": True,
                "require_test_summary": True,
                "allow_zero_tests": False,
            },
        },
    ]
    return {
        "schema_version": 1,
        "workspace_root": ".",
        "execution": {"cargo_executable": "cargo", "continue_on_error": False},
        "steps": steps,
    }


def smoke_test(executable):
    env = dict(os.environ, CARGO_NET_OFFLINE="true")
    with tempfile.TemporaryDirectory(prefix="cargotrail-smoke-") as scratch_name:
        scratch = Path(scratch_name).resolve()
        workspace = scratch / "workspace"
        workspace.mkdir()
        (workspace / "Cargo.toml").write_text(
            '[package]\nname = "cargotrail_smoke"\nversion = "0.1.0"\nedition = "2021"\n',
            encoding="utf-8",
        )
        (workspace / "src").mkdir()
        (workspace / "src" / "lib.rs").write_text(LIB_RS, encoding="utf-8")
        code, output = run(["cargo", "generate-lockfile", "--offline"], workspace, env)
        expect(code == 0, "cargo generate-lockfile failed:\n" + output)

        config = scratch / "pipeline.json"
        config.write_text(json.dumps(pipeline_config(), indent=2), encoding="utf-8")

        code, output = run([executable, "--version"], scratch, env)
        expect(code == 0 and output.strip().startswith("CargoTrail "), "--version failed:\n" + output)

        code, output = run(
            [executable, "--config", config, "--root", workspace, "--validate-config"], scratch, env
        )
        expect(code == 0, "--validate-config failed:\n" + output)

        evidence = scratch / "evidence"
        code, output = run(
            [executable, "--config", config, "--root", workspace, "--output-dir", evidence, "--archive"],
            scratch,
            env,
        )
        expect(code == 0, "pipeline run failed (exit {}):\n{}".format(code, output))

        manifest = json.loads((evidence / "manifest.json").read_text(encoding="utf-8"))
        expect(manifest.get("status") == "passed", "manifest status is {!r}, expected 'passed'".format(manifest.get("status")))

        provenance = json.loads((evidence / "provenance.json").read_text(encoding="utf-8"))
        sources = provenance.get("agent", {}).get("runtime_source_files", [])
        found = {item.get("path"): item.get("status") for item in sources}
        expect(
            set(found) == RUNTIME_SOURCES,
            "runtime source files differ from expectation: {}".format(sorted(found)),
        )
        not_hashed = sorted(path for path, status in found.items() if status != "hashed")
        expect(
            not not_hashed,
            "runtime sources not bundled or not hashable in the executable: {}".format(not_hashed),
        )

        archive = Path(str(evidence) + ".tar.gz")
        sidecar = Path(str(archive) + ".integrity.json")
        expect(archive.is_file(), "evidence archive was not created: {}".format(archive))
        expect(sidecar.is_file(), "integrity sidecar was not created: {}".format(sidecar))
    return manifest.get("status")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    default = ROOT / "dist" / ("cargotrail.exe" if sys.platform == "win32" else "cargotrail")
    parser.add_argument("--executable", type=Path, default=default, help="Executable to test (default: dist/cargotrail)")
    args = parser.parse_args()
    executable = args.executable.resolve()
    if not executable.is_file():
        parser.error("Executable not found: {}".format(executable))
    try:
        status = smoke_test(executable)
    except SmokeFailure as exc:
        print("SMOKE TEST FAILED: {}".format(exc), file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print("SMOKE TEST ERROR: {}: {}".format(type(exc).__name__, exc), file=sys.stderr)
        return 1
    print("Smoke test passed: {} (run status: {})".format(executable.name, status))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
