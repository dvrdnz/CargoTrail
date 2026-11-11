"""Real Cargo integration tests (no fake executable, no external dependencies).

Run with: python -m unittest discover -s tests -v
Set CARGO_INTEGRATION_REQUIRED=1 in CI so missing Cargo is a hard failure,
not a silently skipped integration job.
"""

# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tarfile
import time
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "cargotrail.py"
sys.path.insert(0, str(ROOT))
import importlib.util
import artifact_inventory

SPEC = importlib.util.spec_from_file_location("cargotrail_integration", RUNNER)
agent = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(agent)

CARGO = shutil.which("cargo")


def _windows_cargo_target_linker_variable(rustc_path: str) -> str:
    """Return Cargo's target-specific linker environment variable for rustc's host."""
    rustc_info = subprocess.run(
        [rustc_path, "-vV"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=15, check=False,
    )
    if rustc_info.returncode != 0:
        raise RuntimeError("rustc -vV failed while selecting the Windows Cargo test linker")
    host = next((line.split(":", 1)[1].strip() for line in rustc_info.stdout.splitlines()
                 if line.startswith("host: ")), None)
    if not host:
        raise RuntimeError("rustc -vV did not report its host target")
    return "CARGO_TARGET_{}_LINKER".format(host.upper().replace("-", "_"))


def _windows_cargo_lld_configuration(rustc_path: str) -> tuple[str, str]:
    """Return Cargo's target-linker variable and an installed MSVC-compatible lld-link.

    This is an explicit test-only control variant. It does not change the
    production linker selection or relax Job Object process-tree verification.
    """
    linker = shutil.which("lld-link.exe") or shutil.which("lld-link")
    if not linker:
        roots = []
        for variable in ("ProgramFiles", "ProgramFiles(x86)"):
            root_value = os.environ.get(variable)
            if root_value:
                root_path = Path(root_value)
                if root_path not in roots:
                    roots.append(root_path)
        if not roots:
            roots.append(Path(r"C:\Program Files"))

        candidates = []
        for root_path in roots:
            candidates.append(root_path / "LLVM" / "bin" / "lld-link.exe")
            visual_studio = root_path / "Microsoft Visual Studio"
            if visual_studio.is_dir():
                candidates.extend(visual_studio.glob("*/*/VC/Tools/Llvm/bin/lld-link.exe"))
                candidates.extend(visual_studio.glob("*/*/VC/Tools/Llvm/x64/bin/lld-link.exe"))
        linker = next((str(path) for path in candidates if path.is_file()), None)
    if not linker:
        raise RuntimeError("Windows real Cargo LLD diagnostic requires LLVM lld-link.exe")

    linker_variable = _windows_cargo_target_linker_variable(rustc_path)
    if not linker_variable.endswith("_WINDOWS_MSVC_LINKER"):
        raise RuntimeError(
            "lld-link requires a Windows MSVC rustc host target; got linker variable {}".format(
                linker_variable,
            )
        )
    return linker_variable, str(linker)


class WindowsCargoLinkerConfigurationTests(unittest.TestCase):
    def test_uses_lld_link_and_rustc_host_target_environment_key(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temp:
            llvm = Path(temp) / "LLVM" / "bin"
            llvm.mkdir(parents=True)
            linker = llvm / "lld-link.exe"
            linker.write_bytes(b"test linker placeholder")
            with mock.patch.object(shutil, "which", return_value=None), \
                    mock.patch.dict(os.environ, {"ProgramFiles": temp}, clear=False), \
                    mock.patch.object(subprocess, "run", return_value=SimpleNamespace(
                        returncode=0, stdout="rustc 1.90.0\nhost: x86_64-pc-windows-msvc\n",
                        stderr="",
                    )) as rustc_run:
                variable, selected = _windows_cargo_lld_configuration("rustc.exe")
        self.assertEqual(variable, "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER")
        self.assertEqual(selected, str(linker))
        rustc_run.assert_called_once()
        self.assertEqual(rustc_run.call_args.args[0], ["rustc.exe", "-vV"])

    def test_finds_lld_link_in_visual_studio_llvm_bin_directory(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temp:
            linker = Path(temp) / "Microsoft Visual Studio" / "2022" / "Enterprise" / "VC" / "Tools" / "Llvm" / "bin" / "lld-link.exe"
            linker.parent.mkdir(parents=True)
            linker.write_bytes(b"test linker placeholder")
            with mock.patch.object(shutil, "which", return_value=None), \
                    mock.patch.dict(os.environ, {"ProgramFiles": temp}, clear=False), \
                    mock.patch.object(subprocess, "run", return_value=SimpleNamespace(
                        returncode=0, stdout="rustc 1.90.0\nhost: x86_64-pc-windows-msvc\n", stderr="",
                    )):
                variable, selected = _windows_cargo_lld_configuration("rustc.exe")
        self.assertEqual(variable, "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER")
        self.assertEqual(selected, str(linker))

    def test_rejects_non_msvc_rustc_host_for_lld_link(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temp:
            llvm = Path(temp) / "LLVM" / "bin"
            llvm.mkdir(parents=True)
            linker = llvm / "lld-link.exe"
            linker.write_bytes(b"test linker placeholder")
            with mock.patch.object(shutil, "which", return_value=None), \
                    mock.patch.dict(os.environ, {"ProgramFiles": temp}, clear=False), \
                    mock.patch.object(subprocess, "run", return_value=SimpleNamespace(
                        returncode=0, stdout="rustc 1.90.0\nhost: x86_64-pc-windows-gnu\n", stderr="",
                    )):
                with self.assertRaisesRegex(RuntimeError, "Windows MSVC rustc host target"):
                    _windows_cargo_lld_configuration("rustc.exe")

    def test_msvc_mode_uses_target_linker_variable_for_explicit_unset(self):
        from types import SimpleNamespace
        with mock.patch.object(subprocess, "run", return_value=SimpleNamespace(
            returncode=0, stdout="rustc 1.90.0\nhost: x86_64-pc-windows-msvc\n", stderr="",
        )) as rustc_run:
            variable = _windows_cargo_target_linker_variable("rustc.exe")
        self.assertEqual(variable, "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER")
        rustc_run.assert_called_once_with(
            ["rustc.exe", "-vV"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=15, check=False,
        )

    def test_msvc_mode_unsets_cargo_linker_override_in_real_test_setup(self):
        from types import SimpleNamespace
        with mock.patch.object(os, "name", "nt"), \
                mock.patch.object(shutil, "which", return_value="rustc.exe"), \
                mock.patch.object(subprocess, "run", return_value=SimpleNamespace(
                    returncode=0, stdout="rustc 1.90.0\nhost: x86_64-pc-windows-msvc\n", stderr="",
                )), \
                mock.patch.object(sys.modules[__name__], "CARGO", "cargo.exe"), \
                mock.patch.dict(os.environ, {"CARGOTRAIL_WINDOWS_LINKER": "msvc"}, clear=False):
            RealCargoIntegrationTests.setUpClass()

        self.assertEqual(
            RealCargoIntegrationTests.cargo_test_unset_environment,
            ["CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER"],
        )
        self.assertEqual(RealCargoIntegrationTests.cargo_test_environment, {"CARGO_NET_OFFLINE": "true"})

    def test_unconfigured_windows_setup_preserves_lld_control_default(self):
        with mock.patch.object(os, "name", "nt"), \
                mock.patch.object(shutil, "which", return_value="rustc.exe"), \
                mock.patch.object(sys.modules[__name__], "CARGO", "cargo.exe"), \
                mock.patch.object(
                    sys.modules[__name__], "_windows_cargo_lld_configuration",
                    return_value=("CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER", r"C:\LLVM\bin\lld-link.exe"),
                ), \
                mock.patch.dict(os.environ, {}, clear=True):
            RealCargoIntegrationTests.setUpClass()

        self.assertEqual(RealCargoIntegrationTests.cargo_test_unset_environment, [])
        self.assertEqual(
            RealCargoIntegrationTests.cargo_test_environment,
            {
                "CARGO_NET_OFFLINE": "true",
                "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER": r"C:\LLVM\bin\lld-link.exe",
            },
        )

    def test_lld_mode_injects_only_the_test_linker_override(self):
        from types import SimpleNamespace
        with mock.patch.object(os, "name", "nt"), \
                mock.patch.object(shutil, "which", return_value="rustc.exe"), \
                mock.patch.object(subprocess, "run", return_value=SimpleNamespace(
                    returncode=0, stdout="rustc 1.90.0\nhost: x86_64-pc-windows-msvc\n", stderr="",
                )), \
                mock.patch.object(sys.modules[__name__], "CARGO", "cargo.exe"), \
                mock.patch.object(
                    sys.modules[__name__], "_windows_cargo_lld_configuration",
                    return_value=("CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER", r"C:\LLVM\bin\lld-link.exe"),
                ), \
                mock.patch.dict(os.environ, {"CARGOTRAIL_WINDOWS_LINKER": "lld"}, clear=False):
            RealCargoIntegrationTests.setUpClass()

        self.assertEqual(RealCargoIntegrationTests.cargo_test_unset_environment, [])
        self.assertEqual(
            RealCargoIntegrationTests.cargo_test_environment,
            {
                "CARGO_NET_OFFLINE": "true",
                "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER": r"C:\LLVM\bin\lld-link.exe",
            },
        )


class RealCargoIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CARGO:
            reason = "real Cargo integration tests require cargo and rustc on PATH"
            if os.environ.get("CARGO_INTEGRATION_REQUIRED") == "1":
                raise RuntimeError(reason + " (CARGO_INTEGRATION_REQUIRED=1)")
            raise unittest.SkipTest(reason)
        # A real rustc toolchain is required, not merely a cargo shim.
        rustc = shutil.which("rustc")
        if not rustc:
            reason = "cargo is present but rustc is missing"
            if os.environ.get("CARGO_INTEGRATION_REQUIRED") == "1":
                raise RuntimeError(reason)
            raise unittest.SkipTest(reason)

        cls.cargo_test_environment = {"CARGO_NET_OFFLINE": "true"}
        cls.cargo_test_unset_environment = []
        if os.name == "nt":
            # Preserve the previous LLD control default. The diagnostic matrix
            # selects the native MSVC linker explicitly for its comparison lane.
            linker_mode = os.environ.get("CARGOTRAIL_WINDOWS_LINKER", "lld").strip().lower()
            if linker_mode == "msvc":
                linker_variable = _windows_cargo_target_linker_variable(rustc)
                cls.cargo_test_unset_environment.append(linker_variable)
                print(
                    "Windows Cargo integration linker: MSVC default ({} unset)".format(
                        linker_variable,
                    )
                )
            elif linker_mode == "lld":
                try:
                    linker_variable, linker = _windows_cargo_lld_configuration(rustc)
                except RuntimeError as exc:
                    if os.environ.get("CARGO_INTEGRATION_REQUIRED") == "1":
                        raise
                    raise unittest.SkipTest(str(exc))
                cls.cargo_test_environment[linker_variable] = linker
                print("Windows Cargo integration linker: lld-link ({})".format(linker))
            else:
                raise RuntimeError(
                    "CARGOTRAIL_WINDOWS_LINKER must be either 'msvc' or 'lld', got {!r}".format(
                        linker_mode,
                    )
                )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cargo-evidence-real-")
        self.base = Path(self.temp.name)

    def tearDown(self):
        for attempt in range(5):
            try:
                self.temp.cleanup()
                return
            except OSError as exc:
                # Windows may briefly report a non-empty directory while Cargo
                # closes its final build output handles after the child exits.
                if getattr(exc, "winerror", None) != 145:
                    raise
                if attempt == 4:
                    # The restricted Windows temp mount can expose stale
                    # Cargo directory entries that cannot be unlinked by the
                    # current test process. Do not turn a successful Cargo
                    # integration into a false test failure for that cleanup.
                    self.temp._ignore_cleanup_errors = True
                    self.temp.cleanup()
                    return
                time.sleep(0.1)

    def make_crate(self, name: str, source: str) -> Path:
        workspace = self.base / name
        (workspace / "src").mkdir(parents=True)
        (workspace / "Cargo.toml").write_text(
            '[package]\nname = "{}"\nversion = "0.1.0"\nedition = "2021"\n'.format(name),
            encoding="utf-8",
        )
        (workspace / "src" / "lib.rs").write_text(source, encoding="utf-8")
        return workspace

    def test_real_cargo_alias_precedence_matches_invocation_resolver_contract(self):
        workspace = self.make_crate("real_alias_precedence", "pub fn alias_test() {}\n")
        cargo_home = self.base / "isolated-cargo-home"
        cargo_home.mkdir()
        config_path = cargo_home / "config.toml"
        env = os.environ.copy()
        env.update({
            "CARGO_HOME": str(cargo_home),
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TERM_COLOR": "never",
            "NO_COLOR": "1",
        })

        def cargo_help(args, call_env=env):
            return subprocess.run(
                [CARGO] + args, cwd=str(workspace), env=call_env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=30, check=False,
            )

        builtin_alias = cargo_help(["b", "--help"])
        self.assertEqual(builtin_alias.returncode, 0, builtin_alias.stderr)
        self.assertIn("Compile a local package", builtin_alias.stdout)

        config_path.write_text(
            '[alias]\nb = "check"\nbuild = "test"\nmerge = ["check"]\n', encoding="utf-8",
        )
        project_config = workspace / ".cargo" / "config.toml"
        project_config.parent.mkdir()
        project_config.write_text('[alias]\nmerge = ["--message-format=json"]\nci = "test"\n', encoding="utf-8")
        project_alias = cargo_help(["ci", "--help"])
        self.assertEqual(project_alias.returncode, 0, project_alias.stderr)
        self.assertIn("Execute all unit and integration tests", project_alias.stdout)
        merged_array_alias = cargo_help(["merge", "--help"])
        self.assertEqual(merged_array_alias.returncode, 0, merged_array_alias.stderr)
        self.assertIn("Check a local package", merged_array_alias.stdout)
        user_override = cargo_help(["b", "--help"])
        self.assertEqual(user_override.returncode, 0, user_override.stderr)
        self.assertIn("Check a local package", user_override.stdout)
        built_in_wins = cargo_help(["build", "--help"])
        self.assertEqual(built_in_wins.returncode, 0, built_in_wins.stderr)
        self.assertIn("Compile a local package", built_in_wins.stdout)

        environment = dict(env, CARGO_ALIAS_B="test")
        environment_override = cargo_help(["b", "--help"], environment)
        self.assertEqual(environment_override.returncode, 0, environment_override.stderr)
        self.assertIn("Execute all unit and integration tests", environment_override.stdout)
        cli_override = cargo_help(["--config", "alias.b='build'", "b", "--help"])
        self.assertEqual(cli_override.returncode, 0, cli_override.stderr)
        self.assertIn("Check a local package", cli_override.stdout)
        cli_alias_file = self.base / "cli-aliases.toml"
        cli_alias_file.write_text('[alias]\nb = "test"\nnew-alias = "build"\n', encoding="utf-8")
        cli_file_override = cargo_help(["--config", str(cli_alias_file), "b", "--help"])
        self.assertEqual(cli_file_override.returncode, 0, cli_file_override.stderr)
        self.assertIn("Check a local package", cli_file_override.stdout)
        cli_only_alias = cargo_help(["--config", str(cli_alias_file), "new-alias", "--help"])
        self.assertNotEqual(cli_only_alias.returncode, 0)
        self.assertIn("no such command", cli_only_alias.stderr.lower())

    def run_pipeline(
        self, workspace: Path, step: dict, output_name: str,
        archive: bool = False, profile: dict | None = None,
    ):
        config_path = self.base / (output_name + ".json")
        output = self.base / (output_name + "-evidence")
        config = {
            "schema_version": 1,
            "workspace_root": str(workspace),
            "execution": {
                "cargo_executable": CARGO,
                "continue_on_error": True,
                "default_timeout_seconds": 300,
                "termination_grace_seconds": 3,
                "environment": dict(self.cargo_test_environment),
                "unset_environment": list(self.cargo_test_unset_environment),
            },
            "steps": [step],
        }
        if profile is not None:
            config["profile"] = profile
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        stdout = io.StringIO()
        stderr = io.StringIO()
        arguments = ["--config", str(config_path), "--output-dir", str(output)]
        if archive:
            arguments.append("--archive")
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = agent.main(arguments)
        self.assertTrue((output / "manifest.json").is_file(), stderr.getvalue())
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        record = manifest["steps"][0]
        return exit_code, output, record, stdout.getvalue(), stderr.getvalue()

    def test_real_cargo_artifact_inventory_matches_archived_snapshot(self):
        workspace = self.make_crate(
            "real_artifact_inventory",
            "pub fn inventory_target() -> u32 { 9 }\n",
        )
        code, output, record, _stdout, stderr = self.run_pipeline(
            workspace,
            self.step("check", ["check", "--offline", "--message-format=json"], "cargo-json"),
            "artifact-inventory", archive=True,
            profile={
                "id": "integration-artifact-check",
                "version": 1,
                "description": "Archive integration profile",
            },
        )
        self.assertEqual(code, 0, stderr)
        self.assertEqual(record["status"], "passed")
        manifest_bytes = (output / "manifest.json").read_bytes()
        inventory_bytes = (output / "artifact-inventory.json").read_bytes()
        manifest = json.loads(manifest_bytes)
        inventory = json.loads(inventory_bytes)
        summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["artifact_inventory"], {"path": "artifact-inventory.json", "schema_version": 1})
        self.assertEqual(summary["artifact_inventory_status"], inventory["status"])
        self.assertEqual(summary["inventory_digest"], inventory["inventory_digest"])
        self.assertEqual(inventory["inventory_digest"], artifact_inventory.calculate_inventory_digest(inventory))
        profile = manifest["execution_profile"]
        self.assertEqual(profile["status"], "declared")
        self.assertEqual(profile["id"], "integration-artifact-check")
        self.assertEqual(profile["definition"]["sha256"], summary["execution_profile"]["definition_sha256"])
        self.assertEqual(summary["execution_profile"]["id"], profile["id"])
        self.assertEqual(summary["execution_profile"]["version"], profile["version"])
        redacted_config = json.loads((output / "config.redacted.json").read_text(encoding="utf-8"))
        self.assertEqual(redacted_config["profile"], {
            "id": "integration-artifact-check",
            "version": 1,
            "description": "Archive integration profile",
        })
        config_path = self.base / "artifact-inventory.json"
        source_config = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertEqual(source_config["profile"], {
            "id": "integration-artifact-check",
            "version": 1,
            "description": "Archive integration profile",
        })
        loaded_config, source_bytes, _ = agent.load_config(config_path)
        self.assertEqual(manifest["config"]["sha256"], agent.sha256_bytes(source_bytes))
        self.assertEqual(
            manifest["provenance"]["config"]["semantic_sha256"],
            agent.sha256_bytes(agent.canonical_json_bytes(agent.redacted_config(loaded_config))),
        )
        self.assertTrue(all(item["sha256"] for item in inventory["artifacts"]))
        archive_path = Path(manifest["archive"]["path"])
        sidecar_path = Path(manifest["archive"]["integrity_sidecar_path"])
        sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
        archive_hash, archive_size = artifact_inventory.sha256_file(archive_path)
        inventory_hash, inventory_size = artifact_inventory.sha256_file(output / "artifact-inventory.json")
        self.assertEqual(sidecar["archive"]["sha256"], archive_hash)
        self.assertEqual(sidecar["archive"]["size_bytes"], archive_size)
        self.assertEqual(sidecar["artifact_inventory"]["sha256"], inventory_hash)
        self.assertEqual(sidecar["artifact_inventory"]["size_bytes"], inventory_size)
        manifest_hash, _ = artifact_inventory.sha256_file(output / "manifest.json")
        self.assertEqual(sidecar["manifest"]["sha256"], manifest_hash)
        inventory_records = {item["path"]: item for item in inventory["artifacts"]}
        for filename in ("manifest.json", "summary.json"):
            digest, size = artifact_inventory.sha256_file(output / filename)
            self.assertEqual(inventory_records[filename]["sha256"], digest)
            self.assertEqual(inventory_records[filename]["size_bytes"], size)
        with tarfile.open(archive_path, "r:gz") as archive_file:
            for filename, expected in (
                ("manifest.json", manifest_bytes),
                ("summary.json", (output / "summary.json").read_bytes()),
                ("artifact-inventory.json", inventory_bytes),
            ):
                name = output.name + "/" + filename
                self.assertEqual(archive_file.extractfile(name).read(), expected)

    def step(self, step_id: str, args: list, parser: str) -> dict:
        return {
            "id": step_id,
            "enabled": True,
            "args": args,
            "parser": parser,
            "cwd": ".",
        }

    def test_real_cargo_success_check_test_and_build(self):
        workspace = self.make_crate(
            "real_cargo_success",
            """pub fn add(left: u64, right: u64) -> u64 { left + right }

#[cfg(test)]
mod tests {
    #[test]
    fn addition_is_correct() {
        assert_eq!(super::add(2, 2), 4);
    }
}
""",
        )
        lock_result = subprocess.run(
            [CARGO, "generate-lockfile", "--offline"], cwd=str(workspace),
            env=dict(os.environ, CARGO_NET_OFFLINE="true"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60, check=False,
        )
        self.assertEqual(lock_result.returncode, 0, lock_result.stderr.decode("utf-8", errors="replace"))
        config_path = self.base / "success.json"
        output = self.base / "success-evidence"
        config = {
            "schema_version": 1,
            "workspace_root": str(workspace),
            "execution": {
                "cargo_executable": CARGO,
                "continue_on_error": True,
                "default_timeout_seconds": 300,
                "termination_grace_seconds": 3,
                "environment": dict(self.cargo_test_environment),
                "unset_environment": list(self.cargo_test_unset_environment),
            },
            "steps": [
                self.step("check", ["check", "--offline", "--message-format=json"], "cargo-json"),
                self.step("test", ["test", "--offline", "--message-format=json"], "cargo-json+libtest"),
                self.step("build", ["build", "--offline", "--message-format=json"], "cargo-json"),
            ],
        }
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        out = io.StringIO()
        err = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = agent.main(["--config", str(config_path), "--output-dir", str(output)])
        self.assertEqual(code, 0, err.getvalue() + out.getvalue())
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "passed")
        self.assertEqual(manifest["execution_profile"], {"status": "not_declared"})
        self.assertEqual(
            json.loads((output / "summary.json").read_text(encoding="utf-8"))["execution_profile"],
            {"status": "not_declared"},
        )
        provenance = manifest["provenance"]
        self.assertEqual(provenance["status"], "complete", provenance["issues"])
        self.assertEqual(provenance["schema_version"], 1)
        self.assertEqual(provenance["config"]["bytes_sha256"], manifest["config"]["sha256"])
        self.assertEqual(provenance["workspace"]["change_status"], "unchanged")
        self.assertEqual(provenance["workspace"]["digest_before"], provenance["workspace"]["digest_after"])
        for step_id in ("check", "test", "build"):
            self.assertEqual(provenance["steps"][step_id]["cargo"]["version_probe"]["status"], "succeeded")
            self.assertEqual(provenance["steps"][step_id]["rustc"]["version_probe"]["status"], "succeeded")
            self.assertEqual(provenance["steps"][step_id]["cargo_metadata_probe"]["status"], "succeeded")
            self.assertEqual(
                provenance["steps"][step_id]["output"]["build_directory"]["path"],
                provenance["steps"][step_id]["output"]["target_directory"]["path"],
            )
        self.assertEqual(provenance["workspace"]["manifest_files"]["Cargo.toml"]["before"]["status"], "present")
        self.assertEqual(provenance["workspace"]["manifest_files"]["Cargo.lock"]["before"]["status"], "present")
        self.assertTrue((output / "provenance.json").is_file())
        inventory = json.loads((output / "workspace-inventory.json").read_text(encoding="utf-8"))
        self.assertIsNotNone(inventory["before"])
        self.assertIsNotNone(inventory["after"])
        self.assertEqual(inventory["differences"]["counts"]["modified"], 0)
        records = {item["id"]: item for item in manifest["steps"]}
        self.assertEqual({key: records[key]["status"] for key in records}, {
            "check": "passed", "test": "passed", "build": "passed",
        })
        for step_id in ("check", "test", "build"):
            self.assertEqual(records[step_id]["execution_status"], "completed")
            self.assertEqual(records[step_id]["evidence_status"], "complete")
            self.assertTrue(records[step_id]["build_finished_success"] is True)
            raw_events = [
                json.loads(line)
                for line in (output / step_id / "raw.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertTrue(any(item.get("reason") == "build-finished" for item in raw_events))
        redacted_config = json.loads((output / "config.redacted.json").read_text(encoding="utf-8"))
        redacted_steps = {item["id"]: item for item in redacted_config["steps"]}
        self.assertTrue(redacted_steps["test"]["evidence_requirements"]["require_test_summary"])
        test_results = json.loads((output / "test" / "test-results.json").read_text(encoding="utf-8"))
        self.assertEqual(test_results["observation"], "observed")
        self.assertGreaterEqual(test_results["suite_totals"]["passed"], 1)

    def test_real_cargo_build_detects_workspace_change_without_changing_pipeline_status(self):
        workspace = self.base / "workspace_change"
        (workspace / "src").mkdir(parents=True)
        (workspace / "Cargo.toml").write_text(
            '[package]\nname = "workspace_change"\nversion = "0.1.0"\nedition = "2021"\nbuild = "build.rs"\n',
            encoding="utf-8",
        )
        (workspace / "src" / "lib.rs").write_text("pub fn answer() -> u32 { 42 }\n", encoding="utf-8")
        (workspace / "build.rs").write_text(
            'fn main() { let root = std::env::var("CARGO_MANIFEST_DIR").unwrap(); '
            'std::fs::write(format!("{}/provenance-marker.txt", root), "observed").unwrap(); '
            'println!("cargo:rerun-if-changed=build.rs"); }\n',
            encoding="utf-8",
        )
        lock_result = subprocess.run(
            [CARGO, "generate-lockfile", "--offline"], cwd=str(workspace),
            env=dict(os.environ, CARGO_NET_OFFLINE="true"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60, check=False,
        )
        self.assertEqual(lock_result.returncode, 0, lock_result.stderr.decode("utf-8", errors="replace"))
        code, output, record, stdout, stderr = self.run_pipeline(
            workspace,
            self.step("check", ["check", "--offline", "--message-format=json"], "cargo-json"),
            "workspace-change",
        )
        self.assertEqual(code, 0, stderr + stdout)
        self.assertEqual(record["status"], "passed")
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "passed")
        self.assertEqual(manifest["provenance"]["workspace"]["change_status"], "changed")
        self.assertEqual(manifest["provenance"]["workspace"]["inventory_status"], "complete")
        self.assertEqual(manifest["provenance"]["workspace"]["provenance_status"], "incomplete")
        self.assertEqual(manifest["provenance"]["workspace"]["digest_before"] == manifest["provenance"]["workspace"]["digest_after"], False)
        self.assertEqual(manifest["provenance"]["status"], "incomplete")
        inventory = json.loads((output / "workspace-inventory.json").read_text(encoding="utf-8"))
        self.assertEqual(inventory["inventory_status"], "complete")
        self.assertEqual(inventory["change_status"], "changed")
        self.assertEqual(inventory["provenance_status"], "incomplete")
        marker_change = next(item for item in inventory["differences"]["entries"]
                             if item["relative_path"] == "provenance-marker.txt")
        self.assertEqual(marker_change["status"], "created")

    def test_real_cargo_manifest_selection_and_target_directory_are_step_specific(self):
        workspace = self.base / "manifest_workspace"
        member = workspace / "member"
        (member / "src").mkdir(parents=True)
        (workspace / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["member"]\nresolver = "2"\n', encoding="utf-8",
        )
        member_manifest = member / "Cargo.toml"
        member_manifest.write_text(
            '[package]\nname = "manifest_member"\nversion = "0.1.0"\nedition = "2021"\n', encoding="utf-8",
        )
        (member / "src" / "lib.rs").write_text("pub fn value() -> u32 { 7 }\n", encoding="utf-8")
        (workspace / ".cargo").mkdir()
        (workspace / ".cargo" / "config.toml").write_text(
            '[build]\ntarget-dir = "target-config"\n', encoding="utf-8",
        )
        lock_result = subprocess.run(
            [CARGO, "generate-lockfile", "--offline"], cwd=str(workspace),
            env=dict(os.environ, CARGO_NET_OFFLINE="true"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60, check=False,
        )
        self.assertEqual(lock_result.returncode, 0, lock_result.stderr.decode("utf-8", errors="replace"))
        first = self.step(
            "manifest-space-target-cli",
            ["check", "--offline", "--manifest-path", "member/Cargo.toml", "--target-dir", "target-cli", "--message-format=json"],
            "cargo-json",
        )
        second = self.step(
            "manifest-equals-target-env",
            ["check", "--offline", "--manifest-path=member/Cargo.toml", "--message-format=json"],
            "cargo-json",
        )
        second["environment"] = {"CARGO_TARGET_DIR": "target-env"}
        third = self.step(
            "manifest-equals-build-target-env",
            ["check", "--offline", "--manifest-path=member/Cargo.toml", "--message-format=json"],
            "cargo-json",
        )
        third["environment"] = {
            "CARGO_BUILD_TARGET_DIR": "target-build-env",
        }
        fourth = self.step(
            "manifest-equals-target-config",
            ["check", "--offline", "--manifest-path=member/Cargo.toml", "--message-format=json"],
            "cargo-json",
        )
        config_path = self.base / "manifest-targets.json"
        output = self.base / "manifest-targets-evidence"
        config_path.write_text(json.dumps({
            "schema_version": 1,
            "workspace_root": str(workspace),
            "execution": {
                "cargo_executable": CARGO, "continue_on_error": True,
                "default_timeout_seconds": 300, "termination_grace_seconds": 3,
                "environment": dict(self.cargo_test_environment), "unset_environment": list(self.cargo_test_unset_environment),
            },
            "steps": [first, second, third, fourth],
        }, indent=2), encoding="utf-8")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = agent.main(["--config", str(config_path), "--output-dir", str(output)])
        self.assertEqual(code, 0, stderr.getvalue() + stdout.getvalue())
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        provenance = manifest["provenance"]
        target_dirs = {
            "manifest-space-target-cli": workspace / "target-cli",
            "manifest-equals-target-env": workspace / "target-env",
            "manifest-equals-build-target-env": workspace / "target-build-env",
            "manifest-equals-target-config": workspace / "target-config",
        }
        self.assertEqual(len({str(path.resolve()) for path in target_dirs.values()}), 4)
        exclusions = {item["path"] for item in provenance["workspace"]["excluded_paths"]
                      if item["reason"] == "cargo_target_directory" and item["applied"]}
        for step_id, target_path in target_dirs.items():
            step_record = provenance["steps"][step_id]
            self.assertEqual(step_record["manifest"]["selected_manifest_path"], str(member_manifest.resolve()))
            self.assertEqual(step_record["output"]["target_directory"]["path"], str(target_path.resolve()))
            self.assertTrue(target_path.is_dir())
            self.assertIn(target_path.relative_to(workspace).as_posix(), exclusions)
            metadata_argv = step_record["cargo_metadata_probe"]["argv"]
            self.assertIn("--manifest-path", metadata_argv)
            self.assertIn(str(member_manifest.resolve()), metadata_argv)
            self.assertNotIn("--target-dir", metadata_argv)
        self.assertEqual(
            provenance["steps"]["manifest-equals-target-config"]["output"]["target_directory"]["source"],
            "cargo_config_file",
        )
        member_fingerprint = provenance["workspace"]["manifest_files"]["steps"]["manifest-space-target-cli"]["manifest"]
        expected_digest = agent.provenance_sha256_bytes(member_manifest.read_bytes())
        self.assertEqual(member_fingerprint["path"], str(member_manifest.resolve()))
        self.assertEqual(member_fingerprint["before"]["sha256"], expected_digest)
        self.assertEqual(member_fingerprint["after"]["sha256"], expected_digest)
        self.assertEqual(
            provenance["workspace"]["manifest_files"]["steps"]["manifest-space-target-cli"]["lockfile"]["path"],
            str((workspace / "Cargo.lock").resolve()),
        )
        inventory = json.loads((output / "workspace-inventory.json").read_text(encoding="utf-8"))
        inventory_paths = {item["relative_path"] for item in inventory["before"]["entries"]}
        for target_path in target_dirs.values():
            self.assertNotIn(target_path.relative_to(workspace).as_posix(), inventory_paths)

    def test_real_cargo_cli_config_overrides_target_environment_and_tracks_build_directory(self):
        workspace = self.make_crate("real_cargo_config_precedence", "pub fn value() -> u32 { 1 }\n")
        lock_result = subprocess.run(
            [CARGO, "generate-lockfile", "--offline"], cwd=str(workspace),
            env=dict(os.environ, CARGO_NET_OFFLINE="true"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60, check=False,
        )
        self.assertEqual(lock_result.returncode, 0, lock_result.stderr.decode("utf-8", errors="replace"))
        rustc = shutil.which("rustc")
        rustc_version = subprocess.run(
            [rustc, "-Vv"], cwd=str(workspace), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False,
        ).stdout.decode("utf-8", errors="replace")
        host_target = next((line.split(":", 1)[1].strip() for line in rustc_version.splitlines() if line.startswith("host:")), None)
        self.assertTrue(host_target, rustc_version)
        step = self.step(
            "cli-config-output",
            [
                "check", "--offline", "--message-format=json",
                "--config", 'build.target-dir="target-from-cli-config"',
                "--config", 'build.build-dir="build-from-cli-config"',
                "--config", 'build.target="{}"'.format(host_target),
            ],
            "cargo-json",
        )
        step["environment"] = {
            "CARGO_BUILD_TARGET_DIR": "target-from-environment",
            "CARGO_BUILD_TARGET": "definitely-not-a-target",
            "CARGO_INCREMENTAL": "0",
        }
        code, output, record, stdout, stderr = self.run_pipeline(workspace, step, "cargo-config-precedence")
        self.assertEqual(code, 0, stderr + stdout)
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        provenance = manifest["provenance"]
        step_record = provenance["steps"]["cli-config-output"]
        target_path = (workspace / "target-from-cli-config").resolve()
        build_path = (workspace / "build-from-cli-config").resolve()
        self.assertEqual(Path(step_record["output"]["target_directory"]["path"]), target_path)
        self.assertEqual(Path(step_record["output"]["build_directory"]["path"]), build_path)
        self.assertEqual(step_record["target"]["selected_build_target"]["value"], host_target)
        self.assertEqual(step_record["target"]["selected_build_target"]["source"], "cargo_--config")
        self.assertNotEqual(target_path, build_path)
        self.assertTrue(target_path.is_dir())
        self.assertTrue(build_path.is_dir())
        self.assertEqual(provenance["workspace"]["change_status"], "unchanged")
        exclusions = [item for item in provenance["workspace"]["excluded_paths"] if item.get("applied")]
        self.assertTrue(any(item["path"] == "target-from-cli-config" and item["reason"] == "cargo_target_directory" for item in exclusions))
        self.assertTrue(any(item["path"] == "build-from-cli-config" and item["reason"] == "cargo_build_directory" for item in exclusions))
        metadata_argv = step_record["cargo_metadata_probe"]["argv"]
        self.assertIn('build.target-dir="target-from-cli-config"', metadata_argv)
        self.assertIn('build.build-dir="build-from-cli-config"', metadata_argv)

    def test_real_cargo_config_include_activation_matches_native_version(self):
        workspace = self.make_crate("real_cargo_config_include", "pub fn value() -> u32 { 1 }\n")
        version = subprocess.run(
            [CARGO, "-Vv"], cwd=str(workspace), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False,
        ).stdout.decode("utf-8", errors="replace")
        release_line = next((line.split(":", 1)[1].strip() for line in version.splitlines() if line.startswith("release:")), "")
        channel_line = next((line.split(":", 1)[1].strip() for line in version.splitlines() if line.startswith("channel:")), "")
        if not channel_line:
            channel_line = "nightly" if "nightly" in release_line else "beta" if "beta" in release_line else "stable"
        major_minor = tuple(int(part) for part in release_line.split(".")[:2] if part.isdigit())
        stable_support = channel_line in {"stable", "beta"} and major_minor >= (1, 93)
        include_supported = stable_support or channel_line == "nightly"
        config_dir = workspace / ".cargo"
        config_dir.mkdir()
        included = config_dir / "included.toml"
        included.write_text('[build]\ntarget-dir="target-from-include"\n', encoding="utf-8")
        include_config = (
            '[[include]]\npath="included.toml"\n'
            if include_supported else 'include = "included.toml"\n'
        )
        (config_dir / "config.toml").write_text(include_config, encoding="utf-8")
        lock_result = subprocess.run(
            [CARGO, "generate-lockfile", "--offline"], cwd=str(workspace),
            env=dict(os.environ, CARGO_NET_OFFLINE="true"), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60, check=False,
        )
        self.assertEqual(lock_result.returncode, 0, lock_result.stderr.decode("utf-8", errors="replace"))
        args = ["check", "--offline", "--message-format=json"]
        if channel_line == "nightly":
            args.append("-Zconfig-include")
        code, output, _record, stdout, stderr = self.run_pipeline(
            workspace, self.step("include", args, "cargo-json"), "cargo-config-include",
        )
        self.assertEqual(code, 0, stderr + stdout)
        manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
        step_record = manifest["provenance"]["steps"]["include"]
        capability = step_record["cargo_configuration"]["include_support"]
        expected_active = stable_support or channel_line == "nightly"
        self.assertEqual(capability["active"], expected_active)
        discovery = step_record["cargo_configuration"]["include_discoveries"][0]
        self.assertEqual(discovery["supported"], stable_support or channel_line == "nightly")
        self.assertEqual(discovery["active"], expected_active)
        expected_target = workspace / ("target-from-include" if expected_active else "target")
        self.assertEqual(Path(step_record["output"]["target_directory"]["path"]), expected_target.resolve())
        included_rows = [item for item in step_record["cargo_configuration"]["files"] if item["path"] == str(included.resolve())]
        self.assertEqual(bool(included_rows), expected_active)
        self.assertEqual(discovery["fingerprinted"], expected_active)

    def test_real_cargo_metadata_with_missing_lockfile_is_non_mutating_and_explicit(self):
        workspace = self.make_crate("missing_lock_metadata", "pub fn value() -> u32 { 1 }\n")
        cargo_home = self.base / "isolated-cargo-home"
        cargo_home.mkdir()
        self.assertFalse((workspace / "Cargo.lock").exists())
        step = self.step("metadata", ["check", "--offline", "--locked"], "cargo-json")
        step.update({"environment": {}, "unset_environment": []})
        environment = os.environ.copy()
        environment.update({"CARGO_HOME": str(cargo_home), "CARGO_NET_OFFLINE": "true"})
        record, _target, _unreadable = agent.collect_step_provenance(
            CARGO, step, workspace, environment,
            {"environment": {}, "unset_environment": []},
            agent.prepare_step_environment, agent.resolve_cwd,
        )
        self.assertFalse((workspace / "Cargo.lock").exists())
        observation = record["cargo_metadata_probe"]["lockfile_observation"]
        self.assertEqual(observation["before_probe"], "not_present")
        self.assertEqual(observation["after_probe"], "not_present")
        self.assertIn("--locked", record["cargo_metadata_probe"]["argv"])
        self.assertIn("not generated", observation["mutation_policy"])
        self.assertEqual(record["manifest"]["lockfile_status_before_probe"], "not_present")
        self.assertEqual(record["manifest"]["lockfile_status_after_probe"], "not_present")

    def test_real_cargo_compile_error_is_failed_with_structured_diagnostic(self):
        workspace = self.make_crate(
            "real_cargo_compile_failure",
            'pub fn broken() -> u32 { "this is not a number" }\n',
        )
        code, output, record, _stdout, _stderr = self.run_pipeline(
            workspace,
            self.step("compile-failure", ["check", "--offline", "--message-format=json"], "cargo-json"),
            "compile-failure",
        )
        self.assertEqual(code, 1)
        self.assertEqual(record["status"], "failed")
        self.assertNotEqual(record["exit_code"], 0)
        self.assertGreater(record["diagnostics"]["events"], 0)
        diagnostics = [
            json.loads(line)
            for line in (output / "compile-failure" / "diagnostics.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertTrue(any(item["severity"] == "error" for item in diagnostics), diagnostics)
        self.assertTrue((output / "compile-failure" / "raw.jsonl").is_file())

    def test_real_cargo_test_failure_is_failed_and_test_failure_is_observed(self):
        workspace = self.make_crate(
            "real_cargo_test_failure",
            """#[cfg(test)]
mod tests {
    #[test]
    fn deliberately_failing_assertion() {
        assert_eq!(1, 2, "intentional integration-test failure");
    }
}
""",
        )
        code, output, record, _stdout, _stderr = self.run_pipeline(
            workspace,
            self.step("test-failure", ["test", "--offline", "--message-format=json"], "cargo-json+libtest"),
            "test-failure",
        )
        self.assertEqual(code, 1)
        self.assertEqual(record["status"], "failed")
        self.assertNotEqual(record["exit_code"], 0)
        self.assertIsNotNone(record["tests"])
        self.assertEqual(record["tests"]["state"], "test-failures-observed")
        self.assertGreater(record["tests"]["suite_totals"]["failed"], 0)
        self.assertTrue((output / "test-failure" / "test-results.json").is_file())

    def test_real_cargo_zero_test_summary_requires_explicit_allowance(self):
        workspace = self.make_crate("real_cargo_zero_tests", "pub fn answer() -> u32 { 42 }\n")
        results = {}
        for allowed in (False, True):
            step = self.step(
                "zero-tests-allowed" if allowed else "zero-tests-default",
                ["test", "--offline", "--message-format=json"],
                "cargo-json+libtest",
            )
            step["evidence_requirements"] = {
                "require_valid_json_events": True,
                "require_build_finished": True,
                "require_test_summary": True,
                "allow_zero_tests": allowed,
            }
            code, output, record, _stdout, _stderr = self.run_pipeline(
                workspace, step, "zero-tests-allowed" if allowed else "zero-tests-default",
            )
            results[allowed] = (code, output, record)
        disallowed_code, disallowed_output, disallowed = results[False]
        self.assertEqual(disallowed_code, 1)
        self.assertEqual(
            (disallowed["status"], disallowed["evidence_status"]),
            ("incomplete", "incomplete"),
            "unexpected zero-test step result: {}".format(json.dumps({
                key: disallowed.get(key)
                for key in ("exit_code", "status", "evidence_status", "orphan_processes_detected",
                            "supervision_error", "process_tree")
            }, sort_keys=True)),
        )
        self.assertEqual(disallowed["tests"]["state"], "zero-tests-not-allowed")
        self.assertEqual(disallowed["tests"]["executed_test_count"], 0)
        self.assertTrue(json.loads((disallowed_output / "zero-tests-default" / "test-results.json").read_text(encoding="utf-8"))[
            "test_summary_observed"
        ])

        allowed_code, _allowed_output, allowed_record = results[True]
        self.assertEqual(allowed_code, 0)
        self.assertEqual((allowed_record["status"], allowed_record["evidence_status"]), ("passed", "complete"))
        self.assertEqual(allowed_record["tests"]["state"], "zero-tests-allowed")
        self.assertEqual(allowed_record["tests"]["executed_test_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
