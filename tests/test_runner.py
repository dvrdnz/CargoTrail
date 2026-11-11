# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import importlib.util
import io
import contextlib
import json
import os
import signal
import stat
import sys
import subprocess
import tarfile
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock
from pathlib import Path
import provenance
import artifact_inventory

SCRIPT = Path(__file__).resolve().parents[1] / "cargotrail.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("cargotrail", SCRIPT)
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)
import process_supervision as supervision


def _pid_is_running(pid):
    if sys.platform.startswith("linux"):
        try:
            stat = Path("/proc") / str(pid) / "stat"
            raw = stat.read_text(encoding="utf-8")
            close = raw.rfind(")")
            state = raw[close + 2:].split()[0]
            return state not in {"Z", "X"}
        except OSError:
            return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.GetExitCodeProcess.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x1000, False, int(pid))
        if not handle:
            return False
        try:
            code = wintypes.DWORD(0)
            if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel.CloseHandle(handle)
    if sys.platform == "darwin":
        # kill(pid, 0) also succeeds for zombies on macOS. A zombie is no
        # longer executing and must not be reported as a surviving process.
        try:
            completed = subprocess.run(
                ["ps", "-p", str(int(pid)), "-o", "stat="],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2.0,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return True  # Unable to prove that the process has exited.
        if completed.returncode != 0:
            # Apple ps exits with status 1 and no output when -p matches no
            # process. That is the normal result after successful cleanup, not
            # a probe error. Keep other non-zero results conservative.
            if (
                completed.returncode == 1
                and not completed.stdout.strip()
                and not getattr(completed, "stderr", "").strip()
            ):
                return False
            return True
        state = completed.stdout.strip().split()
        if not state:
            # A successful ps invocation without a state row is unexpected;
            # only the explicit no-match result above proves that the PID is gone.
            return True
        return not state[0].startswith(("Z", "X"))
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


class StrictJSONTests(unittest.TestCase):
    def test_valid_json_matches_standard_decoder_for_nested_values(self):
        text = '{"object":{"array":[1,true,null,"é",{"value":-2.5e3}]},"distinct":false}'
        self.assertEqual(provenance.strict_json_loads(text), json.loads(text))

    def test_duplicate_keys_are_rejected_recursively_and_without_values(self):
        cases = (
            '{"token":"top-secret","token":"other-secret"}',
            '{"outer":{"token":"inner-secret","token":"other"}}',
            '{"items":[{"value":"array-secret","value":"other"}]}',
            '{"token":"escaped-secret","\\u0074oken":"other"}',
            '{"first":1,"unrelated":2,"unrelated":3}',
        )
        for text in cases:
            with self.subTest(text=text):
                with self.assertRaises(provenance.DuplicateJSONKeyError) as raised:
                    provenance.strict_json_loads(text)
                self.assertNotIn("secret", str(raised.exception))
                self.assertNotIn(text, str(raised.exception))

    def test_case_sensitive_distinct_keys_remain_distinct(self):
        self.assertEqual(
            provenance.strict_json_loads('{"Token":1,"token":2}'),
            {"Token": 1, "token": 2},
        )

    def test_invalid_json_remains_a_json_syntax_error(self):
        for text in ('{"key": [}', '{"key":1,"key":2} trailing'):
            with self.subTest(text=text), self.assertRaises(json.JSONDecodeError):
                provenance.strict_json_loads(text)


class CargoInvocationAnalysisTests(unittest.TestCase):
    CARGO_VERSION = {"parsed": {"release": "1.91.1", "channel": "stable", "commit_date": "2025-10-10"}}

    def make_project(self, root):
        cwd = root / "project"
        cwd.mkdir(parents=True, exist_ok=True)
        (cwd / "Cargo.toml").write_text('[package]\nname="invocation-test"\nversion="0.1.0"\n', encoding="utf-8")
        cargo_home = root / "cargo-home"
        cargo_home.mkdir(parents=True, exist_ok=True)
        return cwd, {"CARGO_HOME": str(cargo_home)}

    def analyze(self, args, cwd, env, version=None):
        return provenance.analyze_cargo_invocation(
            list(args), cwd, env, version or self.CARGO_VERSION,
            agent.BUILD_PRODUCING_SUBCOMMANDS,
        )

    def test_global_and_command_options_keep_original_indexes(self):
        with tempfile.TemporaryDirectory() as temp:
            cwd, env = self.make_project(Path(temp))
            (cwd / ".cargo").mkdir()
            (cwd / ".cargo" / "config.toml").write_text('[alias]\nci = "build"\n', encoding="utf-8")
            args = [
                "+nightly", "--locked", "--config", "alias.ci='build'",
                "--config=./extra.toml", "-Z", "config-include", "ci",
                "--message-format", "json", "--manifest-path=workspace/Cargo.toml",
                "--target", "x86_64-test", "--target-dir=target-dir", "--",
                "--target", "payload-target", "--config", "after-separator",
            ]
            (cwd / "extra.toml").write_text("# deliberately empty\n", encoding="utf-8")
            original = list(args)
            analysis = self.analyze(args, cwd, env)
            self.assertEqual(args, original)
            self.assertEqual(analysis["toolchain_selector"], "nightly")
            self.assertEqual(analysis["toolchain_selector_index"], 0)
            self.assertEqual(analysis["requested_subcommand"], "ci")
            self.assertEqual(analysis["requested_subcommand_index"], 7)
            self.assertEqual(analysis["resolved_subcommand"], "build")
            self.assertEqual(analysis["message_format"], "json")
            self.assertEqual(analysis["manifest_path"], "workspace/Cargo.toml")
            self.assertEqual(analysis["explicit_target"], "x86_64-test")
            self.assertEqual(analysis["explicit_target_dir"], "target-dir")
            self.assertEqual([item["value"] for item in analysis["global_options"]["z_flags"]], ["config-include"])
            self.assertEqual([item["argument_index"] for item in analysis["config_occurrences"]], [2, 4])
            self.assertEqual(analysis["config_occurrences"][0]["value_argument_index"], 3)
            self.assertEqual(analysis["source_index_map"], list(range(len(args))))

            combined_z = self.analyze(["-Zconfig-include", "build"], cwd, env)
            self.assertEqual([item["value"] for item in combined_z["global_options"]["z_flags"]], ["config-include"])

    def test_option_values_that_look_like_commands_are_not_subcommands(self):
        with tempfile.TemporaryDirectory() as temp:
            cwd, env = self.make_project(Path(temp))
            analysis = self.analyze(["--color", "build", "--config", "test", "check"], cwd, env)
            self.assertEqual(analysis["requested_subcommand"], "check")
            self.assertEqual(analysis["global_options"]["values"][0]["value"], "build")
            self.assertEqual(analysis["config_occurrences"][0]["value"], "test")
            malformed = self.analyze(["--config", "--locked", "build"], cwd, env)
            self.assertIn("cargo_option_value_missing", [item["code"] for item in malformed["parse_issues"]])

    def test_separator_stops_all_cargo_option_parsing(self):
        with tempfile.TemporaryDirectory() as temp:
            cwd, env = self.make_project(Path(temp))
            analysis = self.analyze([
                "build", "--message-format=json", "--", "--target", "ignored",
                "--config", "alias.ci='test'",
            ], cwd, env)
            self.assertEqual(analysis["message_format"], "json")
            self.assertIsNone(analysis["explicit_target"])
            self.assertEqual(analysis["config_occurrences"], [])

    def test_top_level_cargo_commands_remain_valid_for_text_steps(self):
        with tempfile.TemporaryDirectory() as temp:
            cwd, env = self.make_project(Path(temp))
            version = {"parsed": {"release": "1.91.1", "channel": "stable"}}
            for args, expected in ((["--version"], "version"), (["-h"], "help"), (["--list"], "list"),
                                   (["--explain", "E0004"], "explain")):
                with self.subTest(args=args):
                    analysis = self.analyze(args, cwd, env, version)
                    self.assertIsNone(analysis["requested_subcommand"])
                    self.assertEqual(analysis["top_level_command"], expected)
                    self.assertEqual(analysis["resolved_subcommand"], expected)
                    self.assertEqual(analysis["classification"], "known_non_build_builtin")
                    agent.validate_invocation_policy({
                        "id": "top-level", "parser": "text", "evidence_requirements": {},
                    }, analysis)

    def test_missing_options_and_empty_subcommands_fail_with_value_free_issues(self):
        with tempfile.TemporaryDirectory() as temp:
            cwd, env = self.make_project(Path(temp))
            cases = (["--config"], ["build", "--message-format"], ["--manifest-path", "--", "build"], [""])
            for args in cases:
                with self.subTest(args=args):
                    analysis = self.analyze(args, cwd, env)
                    self.assertTrue(analysis["parse_issues"])
                    self.assertTrue(all(set(issue) == {"code"} for issue in analysis["parse_issues"]))
                    for value in args:
                        if value:
                            self.assertNotIn(value, json.dumps(analysis["parse_issues"]))

    def test_string_and_array_aliases_and_user_argument_order(self):
        with tempfile.TemporaryDirectory() as temp:
            cwd, env = self.make_project(Path(temp))
            (cwd / ".cargo").mkdir()
            (cwd / ".cargo" / "config.toml").write_text(
                '[alias]\nbase = "build --release"\nci = "base --target first"\n'
                'array = ["test", "--message-format=json"]\n',
                encoding="utf-8",
            )
            args = ["ci", "--target", "last"]
            original = list(args)
            analysis = self.analyze(args, cwd, env)
            self.assertEqual(args, original)
            self.assertEqual(analysis["alias_chain"], ["ci", "base"])
            self.assertEqual(analysis["resolved_subcommand"], "build")
            self.assertEqual(analysis["classification"], "build_producing_command")
            self.assertEqual(analysis["explicit_target"], "last")
            array = self.analyze(["array"], cwd, env)
            self.assertEqual(array["resolved_subcommand"], "test")
            self.assertEqual(array["message_format"], "json")
            self.assertEqual(provenance._alias_value_words('custom "two words"')[0], ["custom", '"two', 'words"'])

    def test_builtin_alias_defaults_and_shadowing_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            cwd, env = self.make_project(Path(temp))
            expected = {"b": "build", "c": "check", "d": "doc", "r": "run", "t": "test", "rm": "remove"}
            for alias, command in expected.items():
                with self.subTest(alias=alias):
                    analysis = self.analyze([alias], cwd, env)
                    self.assertEqual(analysis["resolved_subcommand"], command)
                    self.assertEqual(analysis["alias_resolution_status"], "resolved")
            (cwd / ".cargo").mkdir()
            (cwd / ".cargo" / "config.toml").write_text(
                '[alias]\nb = "check"\nbuild = "test"\n', encoding="utf-8",
            )
            self.assertEqual(self.analyze(["b"], cwd, env)["resolved_subcommand"], "check")
            built_in = self.analyze(["build"], cwd, env)
            self.assertEqual(built_in["resolved_subcommand"], "build")
            self.assertEqual(built_in["classification"], "build_producing_command")

    def test_environment_and_cli_alias_precedence(self):
        with tempfile.TemporaryDirectory() as temp:
            cwd, env = self.make_project(Path(temp))
            (cwd / ".cargo").mkdir()
            (cwd / ".cargo" / "config.toml").write_text('[alias]\nci = "check"\n', encoding="utf-8")
            env["CARGO_ALIAS_CI"] = "test"
            effective = self.analyze(["ci", "--message-format=json"], cwd, env)
            self.assertEqual(effective["resolved_subcommand"], "test")
            cli = self.analyze([
                "--config", "alias.ci='build'", "ci", "--message-format=json",
            ], cwd, env)
            # Cargo expands aliases before it applies CLI --config options.
            self.assertEqual(cli["resolved_subcommand"], "test")
            cli_after_command = self.analyze([
                "ci", "--config", "alias.ci='build'", "--message-format=json",
            ], cwd, env)
            self.assertEqual(cli_after_command["resolved_subcommand"], "test")
            self.assertEqual(len(cli_after_command["config_occurrences"]), 1)
            file_a = cwd / "first.toml"
            file_b = cwd / "second.toml"
            file_a.write_text('[alias]\nci = "check"\n', encoding="utf-8")
            file_b.write_text('[alias]\nci = "test"\n', encoding="utf-8")
            ordered = self.analyze([
                "--config", str(file_a), "--config", str(file_b), "ci",
                "--message-format=json",
            ], cwd, {"CARGO_HOME": env["CARGO_HOME"]})
            self.assertEqual(ordered["resolved_subcommand"], "check")
            ordered_after_command = self.analyze([
                "ci", "--config", str(file_a), "--config={}".format(file_b),
                "--message-format=json",
            ], cwd, {"CARGO_HOME": env["CARGO_HOME"]})
            self.assertEqual(ordered_after_command["resolved_subcommand"], "check")
            cli_only_alias = self.analyze([
                "--config", "alias.cli_only='build'", "cli_only", "--message-format=json",
            ], cwd, {"CARGO_HOME": env["CARGO_HOME"]})
            self.assertEqual(cli_only_alias["resolved_subcommand"], "cli_only")
            self.assertEqual(cli_only_alias["classification"], "custom_or_external")

    def test_alias_arrays_merge_in_cargo_configuration_order(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cwd, env = self.make_project(root)
            home_config = Path(env["CARGO_HOME"]) / "config.toml"
            home_config.write_text('[alias]\nci = ["check"]\n', encoding="utf-8")
            (root / ".cargo").mkdir()
            (root / ".cargo" / "config.toml").write_text(
                '[alias]\nci = ["--message-format=json"]\n', encoding="utf-8",
            )
            analysis = self.analyze(["ci"], cwd, env)
            self.assertEqual(analysis["resolved_subcommand"], "check")
            self.assertEqual(analysis["message_format"], "json")
            self.assertEqual(analysis["alias_chain"], ["ci"])

    def test_project_home_and_extensionless_config_precedence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cwd, env = self.make_project(root)
            home_config = Path(env["CARGO_HOME"]) / "config.toml"
            home_config.write_text('[alias]\nci = "check"\n', encoding="utf-8")
            (root / ".cargo").mkdir()
            (root / ".cargo" / "config.toml").write_text('[alias]\nci = "test"\n', encoding="utf-8")
            (cwd / ".cargo").mkdir()
            (cwd / ".cargo" / "config").write_text('[alias]\nci = "build"\n', encoding="utf-8")
            (cwd / ".cargo" / "config.toml").write_text('[alias]\nci = "check"\n', encoding="utf-8")
            analysis = self.analyze(["ci"], cwd, env)
            self.assertEqual(analysis["resolved_subcommand"], "build")

    def test_alias_cycles_empty_values_and_invalid_types_are_unresolved(self):
        with tempfile.TemporaryDirectory() as temp:
            cwd, env = self.make_project(Path(temp))
            (cwd / ".cargo").mkdir()
            (cwd / ".cargo" / "config.toml").write_text(
                '[alias]\na = "a"\nb = "c"\nc = "b"\nempty = ""\n'
                'bad = 3\nbad_array = ["build", 3]\n', encoding="utf-8",
            )
            for name, issue in (
                ("a", "cargo_alias_cycle"), ("b", "cargo_alias_cycle"),
                ("empty", "cargo_alias_empty"), ("bad", "cargo_alias_type_invalid"),
                ("bad_array", "cargo_alias_array_element_invalid"),
            ):
                with self.subTest(name=name):
                    analysis = self.analyze([name], cwd, env)
                    self.assertEqual(analysis["classification"], "unresolved")
                    self.assertIn(issue, [item["code"] for item in analysis["resolution_issues"]])

    def test_include_precedence_and_version_capability(self):
        with tempfile.TemporaryDirectory() as temp:
            cwd, env = self.make_project(Path(temp))
            cargo_dir = cwd / ".cargo"
            cargo_dir.mkdir()
            (cargo_dir / "first.toml").write_text('[alias]\norder = "check"\n', encoding="utf-8")
            (cargo_dir / "second.toml").write_text('[alias]\norder = "build"\n', encoding="utf-8")
            (cargo_dir / "config.toml").write_text(
                'include = ["first.toml", "second.toml"]\n[alias]\nci = "test"\n',
                encoding="utf-8",
            )
            stable_194 = {"parsed": {"release": "1.94.0", "channel": "stable"}}
            active = self.analyze(["order"], cwd, env, stable_194)
            self.assertEqual(active["resolved_subcommand"], "build")
            self.assertTrue(active["include_support"]["active"])
            old = self.analyze(["order"], cwd, env, self.CARGO_VERSION)
            self.assertEqual(old["classification"], "custom_or_external")
            self.assertFalse(old["include_support"]["active"])
            beta_unknown = {"parsed": {"release": "1.94.0-beta", "channel": "beta"}}
            unresolved = self.analyze(["order"], cwd, env, beta_unknown)
            self.assertEqual(unresolved["classification"], "unresolved")
            self.assertEqual(unresolved["alias_resolution_status"], "unresolved")

    def test_builtin_inventory_is_conservative_for_new_versions(self):
        with tempfile.TemporaryDirectory() as temp:
            cwd, env = self.make_project(Path(temp))
            reviewed = self.analyze(["my-json-command", "--message-format=json"], cwd, env, {
                "parsed": {"release": "1.94.0", "channel": "stable"},
            })
            self.assertEqual(reviewed["classification"], "custom_or_external")
            newer = self.analyze(["cargo-new-command"], cwd, env, {"parsed": {"release": "1.95.0", "channel": "stable"}})
            self.assertEqual(newer["classification"], "unresolved")
            (cwd / ".cargo").mkdir()
            (cwd / ".cargo" / "config.toml").write_text(
                '[alias]\ncargo-new-command = "build"\n', encoding="utf-8",
            )
            newer_with_alias = self.analyze(
                ["cargo-new-command", "--message-format=json"], cwd, env,
                {"parsed": {"release": "1.95.0", "channel": "stable"}},
            )
            self.assertEqual(newer_with_alias["classification"], "unresolved")
            build = self.analyze(["build"], cwd, env, {"parsed": {"release": "1.95.0", "channel": "stable"}})
            self.assertEqual(build["classification"], "build_producing_command")
            beta_custom = self.analyze(["possible-beta-builtin"], cwd, env, {
                "parsed": {"release": "1.94.0-beta.1", "channel": "beta", "commit_date": "2026-01-22"},
            })
            self.assertEqual(beta_custom["classification"], "unresolved")
            old_version_sensitive = self.analyze(["add"], cwd, env, {
                "parsed": {"release": "1.70.0", "channel": "stable"},
            })
            self.assertEqual(old_version_sensitive["classification"], "unresolved")

    def test_rustup_proxies_keep_identity_on_cargo_versions_beyond_reviewed_window(self):
        with tempfile.TemporaryDirectory() as temp:
            cwd, env = self.make_project(Path(temp))
            for release in ("1.94.0", "1.95.0", "1.97.0"):
                version = {"parsed": {"release": release, "channel": "stable"}}
                with self.subTest(release=release):
                    self.assertEqual(
                        self.analyze(["fmt", "--all", "--", "--check"], cwd, env, version)["classification"],
                        "known_special_external",
                    )
                    self.assertEqual(
                        self.analyze(["clippy", "--message-format=json"], cwd, env, version)["classification"],
                        "build_producing_command",
                    )

    def test_build_evidence_and_parser_policy_use_resolved_command(self):
        with tempfile.TemporaryDirectory() as temp:
            cwd, env = self.make_project(Path(temp))
            (cwd / ".cargo").mkdir()
            (cwd / ".cargo" / "config.toml").write_text(
                '[alias]\nbuild_alias = "build"\nfmt_alias = "fmt"\nt_alias = "test"\n'
                'custom_alias = "custom-missing"\ncycle = "cycle"\n',
                encoding="utf-8",
            )
            for command in agent.BUILD_PRODUCING_SUBCOMMANDS:
                direct = self.analyze([command, "--message-format=json"], cwd, env)
                self.assertEqual(direct["classification"], "build_producing_command", command)
            build_alias = self.analyze(["build_alias", "--message-format=json"], cwd, env)
            self.assertEqual(build_alias["classification"], "build_producing_command")
            env_build = self.analyze(
                ["ci", "--message-format=json"], cwd, dict(env, CARGO_ALIAS_CI="build"),
            )
            self.assertEqual(env_build["classification"], "build_producing_command")
            for alias, expected in (("fmt_alias", "fmt"), ("t_alias", "test"), ("custom_alias", "custom-missing")):
                resolved = self.analyze([alias, "--message-format=json"], cwd, env)
                self.assertEqual(resolved["resolved_subcommand"], expected)
            false_build = {
                "id": "build", "parser": "cargo-json",
                "evidence_requirements": {
                    "require_valid_json_events": True, "require_build_finished": False,
                },
            }
            with self.assertRaises(agent.ConfigError):
                agent.validate_invocation_policy(false_build, build_alias)
            false_unresolved = dict(false_build, id="cycle")
            with self.assertRaises(agent.ConfigError):
                agent.validate_invocation_policy(false_unresolved, self.analyze(["cycle", "--message-format=json"], cwd, env))
            true_unresolved = dict(false_unresolved, evidence_requirements={
                "require_valid_json_events": True, "require_build_finished": True,
            })
            unresolved_analysis = self.analyze(["cycle", "--message-format=json"], cwd, env)
            self.assertEqual(unresolved_analysis["classification"], "unresolved")
            self.assertIsNone(unresolved_analysis["resolved_subcommand"])
            agent.validate_invocation_policy(true_unresolved, unresolved_analysis)
            direct_custom = self.analyze(["missing-custom", "--message-format=json"], cwd, env)
            agent.validate_invocation_policy(false_build, direct_custom)
            json_fmt = dict(false_build, id="fmt", evidence_requirements={
                "require_valid_json_events": True, "require_build_finished": True,
            })
            with self.assertRaises(agent.ConfigError):
                agent.validate_invocation_policy(json_fmt, self.analyze(["fmt_alias", "--message-format=json"], cwd, env))
            text_fmt = {"id": "fmt", "parser": "text", "evidence_requirements": {}}
            agent.validate_invocation_policy(text_fmt, self.analyze(["fmt_alias"], cwd, env))
            libtest = {"id": "test", "parser": "cargo-json+libtest", "evidence_requirements": {
                "require_valid_json_events": True, "require_build_finished": True,
            }}
            agent.validate_invocation_policy(libtest, self.analyze(["t_alias", "--message-format=json"], cwd, env))
            with self.assertRaises(agent.ConfigError):
                agent.validate_invocation_policy(libtest, self.analyze(["custom_alias", "--message-format=json"], cwd, env))

    def test_custom_external_alias_is_never_probed_or_executed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cwd, env = self.make_project(root)
            marker = root / "external-was-run"
            (cwd / ".cargo").mkdir()
            (cwd / ".cargo" / "config.toml").write_text(
                '[alias]\ncustom = "{}"\n'.format(marker.as_posix()), encoding="utf-8",
            )
            step = {
                "id": "custom", "args": ["custom", "--message-format=json"], "parser": "cargo-json",
                "cwd": ".", "enabled": True, "environment": {}, "unset_environment": [],
                "evidence_requirements": {"require_valid_json_events": True, "require_build_finished": False},
            }
            config = {"execution": {
                "cargo_executable": "cargo", "environment": {"CARGO_HOME": env["CARGO_HOME"]},
                "unset_environment": [], "termination_grace_seconds": 1,
            }, "steps": [step]}
            def version_probe(name, command, probe_cwd, probe_env, **kwargs):
                self.assertEqual(command, ["cargo", "-Vv"])
                return {"name": name, "status": "succeeded", "stdout_excerpt": "release: 1.91.1\nchannel: stable\n"}
            with mock.patch.object(agent, "run_probe", side_effect=version_probe):
                outcome = agent.preflight_cargo_invocations(config, root)
            self.assertEqual(outcome.status, "completed")
            self.assertEqual(outcome.contexts["custom"]["analysis"]["classification"], "custom_or_external")
            self.assertFalse(marker.exists())

    def test_preflight_signal_is_first_class_and_stops_later_version_probes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            cwd, env = self.make_project(root)
            cancellation = supervision.CancellationContext()
            first = {
                "id": "first", "args": ["check"], "parser": "text", "cwd": ".",
                "enabled": True, "environment": {}, "unset_environment": [],
            }
            second = dict(first, id="second", args=["test"])
            config = {
                "execution": {
                    "cargo_executable": "cargo", "environment": {"CARGO_HOME": env["CARGO_HOME"]},
                    "unset_environment": [], "termination_grace_seconds": 1,
                },
                "steps": [first, second],
            }
            calls = []

            def interrupted_probe(name, command, probe_cwd, probe_env, **kwargs):
                calls.append((name, list(command)))
                self.assertEqual(kwargs["cancellation"], cancellation)
                cancellation.request(signal.SIGTERM)
                return {
                    "name": name, "status": "interrupted", "signal_number": signal.SIGTERM,
                    "signal_name": "SIGTERM", "exit_code": -signal.SIGTERM,
                    "stdout_excerpt": "", "stderr_excerpt": "", "stdout_bytes": 4096,
                    "stderr_bytes": 0, "stdout_sha256": "a" * 64, "stderr_sha256": "e3b0c442",
                    "stdout_capture_truncated": True, "stderr_capture_truncated": False,
                    "capture_status": "complete", "process_tree": {
                        "cleanup_verified": True, "cleanup_complete": True,
                        "trigger": "signal", "active_members_after_cleanup": [],
                    },
                }

            with mock.patch.object(agent, "run_probe", side_effect=interrupted_probe):
                outcome = agent.preflight_cargo_invocations(config, root, cancellation)
            self.assertEqual(outcome.status, "interrupted")
            self.assertEqual(calls, [("cargo_version", ["cargo", "-Vv"])])
            self.assertEqual(outcome.interrupted_step_id, "first")
            self.assertEqual(outcome.not_preflighted_step_ids, ["second"])
            self.assertEqual((outcome.signal_number, outcome.signal_name), (signal.SIGTERM, "SIGTERM"))
            self.assertEqual(outcome.contexts["first"]["cargo_version_probe"]["status"], "interrupted")
            self.assertEqual(outcome.contexts["first"]["cargo_version_probe"]["capture_status"], "complete")
            self.assertEqual(outcome.contexts["first"]["preflight_status"], "interrupted")
            self.assertEqual(outcome.contexts["second"]["preflight_status"], "not_run_interrupted")

    def test_unsafe_alias_policy_fails_before_output_creation_or_step_launch(self):
        for alias, definition in (("build_alias", "build"), ("cycle", "cycle")):
            with self.subTest(alias=alias), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                workspace = root / "workspace"
                workspace.mkdir()
                (workspace / "Cargo.toml").write_text(
                    '[package]\nname="preflight-test"\nversion="0.1.0"\n', encoding="utf-8",
                )
                cargo_dir = workspace / ".cargo"
                cargo_dir.mkdir()
                (cargo_dir / "config.toml").write_text(
                    '[alias]\n{} = "{}"\n'.format(alias, definition), encoding="utf-8",
                )
                cargo_home = root / "cargo-home"
                cargo_home.mkdir()
                config_path = root / "pipeline.json"
                config = {
                    "schema_version": 1, "workspace_root": str(workspace),
                    "execution": {"cargo_executable": "cargo", "environment": {"CARGO_HOME": str(cargo_home)}},
                    "steps": [{
                        "id": "unsafe", "args": [alias, "--message-format=json"], "parser": "cargo-json",
                        "evidence_requirements": {
                            "require_valid_json_events": True, "require_build_finished": False,
                        },
                    }],
                }
                config_path.write_text(json.dumps(config), encoding="utf-8")
                output = root / "evidence"

                def version_probe(name, command, _cwd, _env, **_kwargs):
                    self.assertEqual(name, "cargo_version")
                    self.assertEqual(command, ["cargo", "-Vv"])
                    return {"name": name, "status": "succeeded", "stdout_excerpt": "release: 1.91.1\nchannel: stable\n"}

                with mock.patch.object(agent, "run_probe", side_effect=version_probe) as probe, \
                     mock.patch.object(agent, "run_process") as process:
                    self.assertEqual(agent.main([
                        "--config", str(config_path), "--output-dir", str(output),
                    ]), 2)
                self.assertEqual(probe.call_count, 1)
                process.assert_not_called()
                self.assertFalse(output.exists())

    def test_malformed_global_option_fails_preflight_before_probe_or_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text(
                '[package]\nname="malformed-preflight"\nversion="0.1.0"\n', encoding="utf-8",
            )
            cargo_home = root / "cargo-home"
            cargo_home.mkdir()
            config_path = root / "pipeline.json"
            config_path.write_text(json.dumps({
                "schema_version": 1,
                "workspace_root": str(workspace),
                "execution": {"cargo_executable": "cargo", "environment": {"CARGO_HOME": str(cargo_home)}},
                "steps": [{
                    "id": "malformed", "args": ["--config", "--locked", "build", "--message-format=json"],
                    "parser": "cargo-json", "evidence_requirements": {
                        "require_valid_json_events": True, "require_build_finished": True,
                    },
                }],
            }), encoding="utf-8")
            output = root / "evidence"
            with mock.patch.object(agent, "run_probe") as probe, mock.patch.object(agent, "run_process") as process:
                self.assertEqual(agent.main(["--config", str(config_path), "--output-dir", str(output)]), 2)
            probe.assert_not_called()
            process.assert_not_called()
            self.assertFalse(output.exists())

    def test_alias_override_redaction_never_persists_target_values(self):
        secret = "H04_ALIAS_SECRET_CANARY"
        raw = ["--config", 'alias.ci="build --token {}"'.format(secret), "ci"]
        redacted = provenance.redact_args(raw)
        self.assertNotIn(secret, json.dumps(redacted))
        self.assertEqual(redacted[1], "alias.ci=<REDACTED>")
        self.assertEqual(provenance._redact_environment_value("CARGO_ALIAS_CI", "build --token " + secret), "<REDACTED>")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Cargo.toml").write_text(
                '[package]\nname="alias-redaction"\nversion="0.1.0"\n', encoding="utf-8",
            )
            cargo_home = root / "cargo-home"
            cargo_home.mkdir()
            (root / ".cargo").mkdir()
            file_secret = "H04_FILE_ALIAS_SECRET_CANARY"
            (root / ".cargo" / "config.toml").write_text(
                '[alias]\nci = "external --token {}"\n'.format(file_secret), encoding="utf-8",
            )
            args = ["--config", 'alias.override="build --token {}"'.format(secret), "ci", "--message-format=json"]
            step = {
                "id": "alias-redaction", "args": args, "cwd": ".", "parser": "cargo-json",
                "environment": {}, "unset_environment": [], "redact_arg_indexes": [],
            }
            execution = {"environment": {}, "unset_environment": [], "termination_grace_seconds": 1}
            base_env = {"PATH": os.environ.get("PATH", ""), "CARGO_HOME": str(cargo_home)}
            analysis = self.analyze(args, root, base_env)

            def fake_probe(name, command, probe_cwd, env, **kwargs):
                if name == "cargo_metadata":
                    raw_metadata = json.dumps({
                        "workspace_root": str(root), "target_directory": str(root / "target"),
                    }).encode("utf-8")
                    return {
                        "name": name, "status": "succeeded", "exit_code": 0,
                        "stdout_sha256": "metadata", "_raw_stdout": raw_metadata,
                    }
                return {"name": name, "status": "unavailable", "exit_code": None, "stdout_excerpt": ""}

            with mock.patch.object(provenance, "run_probe", side_effect=fake_probe):
                record, _target_dir, _unreadable = provenance.collect_step_provenance(
                    "cargo", step, root, base_env, execution,
                    agent.prepare_step_environment, agent.resolve_cwd,
                    invocation_analysis=analysis,
                    cargo_version_probe={
                        "name": "cargo_version", "status": "succeeded",
                        "stdout_excerpt": "release: 1.91.1\nchannel: stable\n",
                    },
                )
            encoded_record = json.dumps(record)
            self.assertNotIn(secret, encoded_record)
            self.assertNotIn(file_secret, encoded_record)
            self.assertEqual(record["cargo_configuration"]["invocation_analysis"]["resolved_subcommand"], "external")

    def test_fake_cargo_receives_original_config_order_and_payload(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[package]\nname="argv-test"\nversion="0.1.0"\n', encoding="utf-8")
            capture = root / "captured.json"
            script = root / "fake_cargo.py"
            script.write_text(
                "import json, os, sys\n"
                "open(os.environ['ARGV_CAPTURE'], 'w').write(json.dumps(sys.argv[1:]))\n",
                encoding="utf-8",
            )
            original = [
                str(script), "check", "--config", "registry.token=ARGV_CANARY",
                "--config=build.target='x86_64-test'", "--", "--config", "after", "--target", "payload",
            ]
            step = {
                "id": "argv", "args": list(original), "parser": "text", "cwd": ".",
                "timeout_seconds": 5, "environment": {"ARGV_CAPTURE": str(capture)},
                "unset_environment": [], "redact_arg_indexes": [], "evidence_requirements": {},
            }
            execution = {"default_timeout_seconds": 5, "termination_grace_seconds": 1,
                         "environment": {}, "unset_environment": []}
            output = root / "evidence"
            output.mkdir()
            analysis = self.analyze(original, workspace, {"CARGO_HOME": str(root / "cargo-home")})
            with mock.patch.object(agent, "run_process", wraps=agent.run_process) as run_process:
                agent.process_step(
                    sys.executable, step, workspace, output, os.environ.copy(), execution,
                    invocation_analysis=analysis,
                )
            self.assertEqual(json.loads(capture.read_text(encoding="utf-8")), original[1:])
            self.assertEqual(run_process.call_args.args[0], [sys.executable] + original)


def _mock_darwin_pid_probe_platform():
    """Select the Darwin/POSIX branch without mutating process-global modules."""
    fake_os = type("PosixOS", (), {"name": "posix"})()
    fake_sys = type("DarwinSys", (), {"platform": "darwin"})()
    return mock.patch.dict(_pid_is_running.__globals__, {"os": fake_os, "sys": fake_sys})


class RunnerUnitTests(unittest.TestCase):
    def test_darwin_pid_probe_treats_zombie_as_exited(self):
        with _mock_darwin_pid_probe_platform(), \
                mock.patch.object(supervision.subprocess, "run") as run:
            run.return_value = type("Completed", (), {"returncode": 0, "stdout": "Z+\n"})()
            self.assertFalse(_pid_is_running(43210))
            self.assertEqual(run.call_args.args[0], ["ps", "-p", "43210", "-o", "stat="])

    def test_darwin_pid_probe_treats_live_state_as_running(self):
        with _mock_darwin_pid_probe_platform(), \
                mock.patch.object(supervision.subprocess, "run") as run:
            run.return_value = type("Completed", (), {"returncode": 0, "stdout": "S+\n"})()
            self.assertTrue(_pid_is_running(43210))

    def test_darwin_pid_probe_fails_closed_when_ps_cannot_verify(self):
        with _mock_darwin_pid_probe_platform(), \
                mock.patch.object(supervision.subprocess, "run", side_effect=OSError("ps unavailable")):
            self.assertTrue(_pid_is_running(43210))

    def test_darwin_pid_probe_treats_no_matching_process_as_exited(self):
        with _mock_darwin_pid_probe_platform(), \
                mock.patch.object(supervision.subprocess, "run") as run:
            run.return_value = type(
                "Completed", (), {"returncode": 1, "stdout": "", "stderr": ""},
            )()
            self.assertFalse(_pid_is_running(43210))

    def test_darwin_pid_probe_fails_closed_on_ps_error(self):
        with _mock_darwin_pid_probe_platform(), \
                mock.patch.object(supervision.subprocess, "run") as run:
            run.return_value = type(
                "Completed", (), {"returncode": 1, "stdout": "", "stderr": "ps: simulated error"},
            )()
            self.assertTrue(_pid_is_running(43210))

    def test_darwin_pid_probe_fails_closed_on_empty_successful_ps_output(self):
        with _mock_darwin_pid_probe_platform(), \
                mock.patch.object(supervision.subprocess, "run") as run:
            run.return_value = type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            self.assertTrue(_pid_is_running(43210))

    def test_cli_version_option_reports_current_release_without_config(self):
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "CargoTrail 1.5.1")
        self.assertEqual(completed.stderr, "")

    EXPECTED_RUNTIME_SOURCE_FILES = (
        "cargotrail.py",
        "process_supervision.py",
        "provenance.py",
        "artifact_inventory.py",
    )

    def write_runtime_source_fixture(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        for index, name in enumerate(self.EXPECTED_RUNTIME_SOURCE_FILES):
            (directory / name).write_bytes(("runtime fixture {}\n".format(index)).encode("utf-8"))

    def make_complete_provenance_record(self):
        return {
            "agent": {"runtime_source_files": []}, "issues": [],
            "steps": {"check": {
                "cargo": {"version_probe": {"status": "succeeded"}},
                "rustc": {"version_probe": {"status": "succeeded"}, "selection_certainty": "resolved"},
                "toolchain": {},
                "manifest": {"selected_manifest_path": "Cargo.toml"},
                "target": {"selected_build_target": {"status": "resolved"}},
                "output": {
                    "target_directory": {"status": "resolved"},
                    "build_directory": {"status": "resolved"},
                },
                "cargo_configuration": {"effective_settings": {}, "files": [], "include_issues": []},
                "cargo_metadata_probe": {
                    "status": "succeeded", "extraction_status": "succeeded",
                    "lockfile_observation": {"status": "present"},
                },
                "cargo_metadata": {"workspace_root": "/workspace", "target_directory": "/workspace/target"},
            }},
        }

    def test_complete_provenance_status_handles_normal_and_explicit_interrupted_shapes(self):
        normal = self.make_complete_provenance_record()
        self.assertEqual(provenance.complete_provenance_status(normal), ("complete", []))

        step = {"id": "check", "args": ["check"], "cwd": "."}
        interrupted = provenance.interrupted_step_provenance(
            step, "cargo", Path("/workspace"), {"PATH": ""},
            {"analysis": {"requested_subcommand": "check"}, "cargo_version_probe": {
                "name": "cargo_version", "status": "interrupted", "signal_number": signal.SIGTERM,
                "signal_name": "SIGTERM", "exit_code": -signal.SIGTERM,
                "stdout_excerpt": "", "stderr_excerpt": "", "process_tree": {"cleanup_verified": True},
            }},
            signal_number=signal.SIGTERM, signal_name="SIGTERM",
        )
        status, issues = provenance.complete_provenance_status({
            "agent": {"runtime_source_files": []}, "issues": [], "steps": {"check": interrupted},
        })
        self.assertEqual(status, "incomplete")
        self.assertIn("cargo_version_probe_interrupted", [item["code"] for item in issues])
        self.assertIn("invocation_preflight_interrupted", [item["code"] for item in issues])
        self.assertEqual(interrupted["cargo"]["version_probe"]["signal_name"], "SIGTERM")

        not_started = provenance.interrupted_step_provenance(
            dict(step, id="later"), "cargo", Path("/workspace"), {"PATH": ""},
            {"analysis": {"requested_subcommand": "test"}},
            signal_number=signal.SIGTERM, signal_name="SIGTERM", not_preflighted=True,
        )
        status, issues = provenance.complete_provenance_status({
            "agent": {"runtime_source_files": []}, "issues": [], "steps": {"later": not_started},
        })
        self.assertEqual(status, "incomplete")
        self.assertIn("invocation_preflight_not_run_interrupted", [item["code"] for item in issues])
        self.assertIsNone(not_started["cargo_metadata"])

        malformed = {"agent": {"runtime_source_files": []}, "issues": [], "steps": {"broken": {"cargo": None}}}
        status, issues = provenance.complete_provenance_status(malformed)
        self.assertEqual(status, "incomplete")
        self.assertIn("step_provenance_structure_invalid", [item["code"] for item in issues])

    def test_interrupted_preflight_runner_finalizes_partial_archive_and_sidecar(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            runner, output = self.make_finalization_runner(base)
            cancellation = supervision.CancellationContext()

            def interrupt_probe(name, command, cwd, env, **kwargs):
                cancellation.request(signal.SIGTERM)
                return {
                    "name": name, "status": "interrupted", "signal_number": signal.SIGTERM,
                    "signal_name": "SIGTERM", "exit_code": -signal.SIGTERM,
                    "stdout_excerpt": "", "stderr_excerpt": "", "stdout_bytes": 0,
                    "stderr_bytes": 0, "capture_status": "complete",
                    "process_tree": {"cleanup_verified": True, "cleanup_complete": True, "trigger": "signal"},
                }

            with mock.patch.object(agent, "run_probe", side_effect=interrupt_probe):
                outcome = agent.preflight_cargo_invocations(runner.config, runner.root, cancellation)
            runner.cancellation = cancellation
            runner.preflight_outcome = outcome
            runner.invocation_context = outcome.contexts
            self.assertEqual(outcome.status, "interrupted")
            runner.execute()
            runner.finalize()

            self.assertTrue(runner._finalization_state["complete"], runner._finalization_errors)
            self.assertIsNone(runner.runner_error)
            self.assertIsNone(runner.archive_error)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
            self.assertNotEqual(summary["status"], "passed")
            self.assertEqual(manifest["steps"][0]["status"], "not_run_interrupted")
            saved = manifest["provenance"]["steps"]["check"]
            self.assertEqual(saved["cargo"]["version_probe"]["status"], "interrupted")
            self.assertEqual(saved["cargo"]["version_probe"]["signal_number"], signal.SIGTERM)
            status, issues = provenance.complete_provenance_status(manifest["provenance"])
            self.assertEqual(status, "incomplete")
            self.assertIn("cargo_version_probe_interrupted", [item["code"] for item in issues])
            for filename in ("workspace-inventory.json", "artifact-inventory.json", "provenance.json"):
                self.assertTrue((output / filename).is_file(), filename)
            archive_path = Path(manifest["archive"]["path"])
            sidecar_path = Path(manifest["archive"]["integrity_sidecar_path"])
            inventory = json.loads((output / "artifact-inventory.json").read_text(encoding="utf-8"))
            agent.verify_archive_snapshot(archive_path, output, inventory)
            self.assertEqual(json.loads(sidecar_path.read_text(encoding="utf-8"))["status"], "created")

    def test_validate_and_dry_run_return_signal_without_output_on_interrupted_preflight(self):
        for mode in ("--validate-config", "--dry-run"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                workspace = root / "workspace"
                workspace.mkdir()
                (workspace / "Cargo.toml").write_text("[workspace]\nmembers = []\n", encoding="utf-8")
                config_path = root / "pipeline.json"
                cargo_home = root / "cargo-home"
                cargo_home.mkdir()
                config_path.write_text(json.dumps({
                    "schema_version": 1, "workspace_root": str(workspace),
                    "execution": {"cargo_executable": "cargo", "environment": {"CARGO_HOME": str(cargo_home)}},
                    "steps": [
                        {"id": "check", "args": ["check"], "parser": "text"},
                        {"id": "later", "args": ["test"], "parser": "text"},
                    ],
                }), encoding="utf-8")
                output = root / "evidence"
                cancellation = supervision.CancellationContext()

                def interrupt_probe(name, command, cwd, env, **kwargs):
                    cancellation.request(signal.SIGTERM)
                    return {"name": name, "status": "interrupted", "signal_number": signal.SIGTERM, "signal_name": "SIGTERM"}

                captured = io.StringIO()
                with mock.patch.object(agent, "run_probe", side_effect=interrupt_probe), \
                        mock.patch("sys.stdout", captured):
                    exit_code = agent._main([
                        "--config", str(config_path), "--output-dir", str(output), mode,
                    ], cancellation)
                self.assertEqual(exit_code, 128 + signal.SIGTERM)
                self.assertFalse(output.exists())
                self.assertEqual(captured.getvalue(), "")

    def make_finalization_runner(self, root):
        workspace = root / "workspace"
        workspace.mkdir()
        (workspace / "Cargo.toml").write_text('[workspace]\nmembers = []\n', encoding="utf-8")
        output = root / "evidence"
        output.mkdir()
        config = {
            "schema_version": 1,
            "workspace_root": str(workspace),
            "execution": {
                "cargo_executable": "cargo", "continue_on_error": True,
                "default_timeout_seconds": None, "termination_grace_seconds": 1,
                "environment": {}, "unset_environment": [],
            },
            "steps": [{
                "id": "check", "enabled": True, "args": ["check"], "parser": "text",
                "cwd": ".", "timeout_seconds": None, "environment": {},
                "unset_environment": [], "redact_arg_indexes": [],
            }],
            "_config_path": str(root / "pipeline.json"), "_config_sha256": "test-hash",
        }
        return agent.Runner(config, workspace, output, True), output

    def run_evidence_step(self, parser, stdout_bytes, requirements=None, exit_code=0):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            workspace = base / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[package]\nname="x"\nversion="0.1.0"\n', encoding="utf-8")
            output = base / "evidence"
            output.mkdir()
            args = ["test", "--message-format=json"] if parser == "cargo-json+libtest" else ["check", "--message-format=json"]
            step = {
                "id": "step", "args": args, "parser": parser, "cwd": ".",
                "timeout_seconds": None, "environment": {}, "unset_environment": [],
                "redact_arg_indexes": [],
            }
            defaults = {
                "require_valid_json_events": parser in ("cargo-json", "cargo-json+libtest"),
                "require_build_finished": parser in ("cargo-json", "cargo-json+libtest"),
                "require_test_summary": parser == "cargo-json+libtest",
                "allow_zero_tests": False,
            }
            if requirements:
                defaults.update(requirements)
            step["evidence_requirements"] = defaults
            execution = {
                "default_timeout_seconds": 10, "termination_grace_seconds": 1,
                "environment": {}, "unset_environment": [],
            }
            cargo_home = base / "cargo-home"
            cargo_home.mkdir()
            effective_env = {"CARGO_HOME": str(cargo_home)}
            invocation_analysis = provenance.analyze_cargo_invocation(
                args, workspace, effective_env,
                {"parsed": {"release": "1.91.1", "channel": "stable"}},
                agent.BUILD_PRODUCING_SUBCOMMANDS,
            )
            def fake_run(_command, _cwd, _env, stdout_path, stderr_path, _timeout, _grace):
                stdout_path.write_bytes(stdout_bytes)
                stderr_path.write_bytes(b"")
                return {
                    "exit_code": exit_code, "native_exit_code": exit_code,
                    "interrupted": False, "timed_out": False, "duration_ms": 1,
                    "spawn_error": None, "supervision_error": None,
                    "process_tree": {"cleanup_verified": True, "cleanup_complete": True},
                }
            with mock.patch.object(agent, "run_process", side_effect=fake_run):
                record = agent.process_step(
                    "cargo", step, workspace, output, effective_env, execution,
                    invocation_analysis=invocation_analysis,
                )
            non_json_path = output / "step" / "non-json.stdout.bin"
            non_json = non_json_path.read_bytes() if non_json_path.exists() else b""
            return record, non_json

    def test_write_jsonl_writes_records(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "records.jsonl"
            agent.write_jsonl(path, [{"one": 1}, {"two": "é"}])
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(rows, [{"one": 1}, {"two": "é"}])

    def test_parser_requires_explicit_json_flag(self):
        with tempfile.TemporaryDirectory() as temp:
            config_path = Path(temp) / "pipeline.json"
            workspace = Path(temp) / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[workspace]\nmembers=[]\n', encoding="utf-8")
            config = {
                "schema_version": 1,
                "workspace_root": str(workspace),
                "execution": {},
                "steps": [{"id": "check", "args": ["check"], "parser": "cargo-json"}],
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            loaded, _raw, _digest = agent.load_config(config_path)
            analysis = provenance.analyze_cargo_invocation(
                loaded["steps"][0]["args"], workspace, {"CARGO_HOME": str(Path(temp) / "cargo-home")},
                {"parsed": {"release": "1.91.1", "channel": "stable"}},
                agent.BUILD_PRODUCING_SUBCOMMANDS,
            )
            with self.assertRaises(agent.ConfigError):
                agent.validate_invocation_policy(loaded["steps"][0], analysis)

    def test_config_duplicate_keys_fail_preflight_without_evidence_or_cargo(self):
        duplicate_documents = (
            '{"schema_version":1,"workspace_root":".","execution":{},'
            '"steps":[{"id":"check","args":["check"],"parser":"text"}],'
            '"steps":[{"id":"release","args":["build"],"parser":"text"}]}',
            '{"schema_version":1,"workspace_root":".",'
            '"execution":{"continue_on_error":true,"continue_on_error":false},"steps":[]}',
        )
        for index, document in enumerate(duplicate_documents):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                config_path = root / "pipeline.json"
                config_path.write_text(document, encoding="utf-8")
                output = root / "evidence"
                with mock.patch.object(agent, "run_process") as run_process:
                    if index == 0:
                        code = agent.main([
                            "--config", str(config_path), "--output-dir", str(output),
                        ])
                        self.assertEqual(code, 2)
                        with self.assertRaises(agent.ConfigError) as raised:
                            agent.load_config(config_path)
                        self.assertEqual(str(raised.exception), "Duplicate key in JSON configuration")
                    else:
                        with self.assertRaisesRegex(agent.ConfigError, "Duplicate key"):
                            agent.load_config(config_path)
                run_process.assert_not_called()
                self.assertFalse(output.exists())

    def test_duplicate_key_cargo_events_are_malformed_invalid_and_preserved(self):
        duplicate_lines = (
            b'{"reason":"build-finished","success":false,"success":true}\n',
            b'{"reason":"build-finished","success":true,"nested":{"x":1,"x":2}}\n',
            b'{"reason":"build-finished","success":false,"reas\\u006fn":"build-finished","success":true}\n',
            b'{"label":"ordinary","label":"duplicate-without-reason-hint"}\n',
        )
        for raw_line in duplicate_lines:
            with self.subTest(raw_line=raw_line):
                record, non_json = self.run_evidence_step("cargo-json", raw_line)
                self.assertEqual(non_json, raw_line)
                self.assertEqual(record["status"], "parser_error")
                self.assertEqual(record["evidence_status"], "invalid")
                self.assertIsNone(record["build_finished_success"])
                issues = record["evidence_issues"]
                self.assertIn("duplicate_key_cargo_json_event", [item["code"] for item in issues])
                self.assertEqual(record["cargo_json_event_count"], 0)

    def test_unique_build_finished_event_remains_valid(self):
        record, non_json = self.run_evidence_step(
            "cargo-json", b'{"reason":"build-finished","success":true}\n',
        )
        self.assertEqual(non_json, b"")
        self.assertEqual(record["status"], "passed")
        self.assertIs(record["build_finished_success"], True)

    def test_argv_is_not_modified_by_config_loader(self):
        with tempfile.TemporaryDirectory() as temp:
            config_path = Path(temp) / "pipeline.json"
            expected = ["clippy", "--locked", "--message-format=json", "--", "-D", "warnings"]
            config = {
                "schema_version": 1,
                "workspace_root": ".",
                "execution": {},
                "steps": [{"id": "clippy", "args": expected, "parser": "cargo-json"}],
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            loaded, _raw, _digest = agent.load_config(config_path)
            self.assertEqual(loaded["steps"][0]["args"], expected)

    def test_evidence_requirement_defaults_and_validation(self):
        with tempfile.TemporaryDirectory() as temp:
            config_path = Path(temp) / "pipeline.json"
            base = {
                "schema_version": 1, "workspace_root": ".", "execution": {},
                "steps": [{"id": "check", "args": ["check", "--message-format=json"], "parser": "cargo-json"}],
            }
            config_path.write_text(json.dumps(base), encoding="utf-8")
            loaded, _raw, _digest = agent.load_config(config_path)
            self.assertEqual(loaded["schema_version"], 1)
            self.assertEqual(loaded["steps"][0]["evidence_requirements"], {
                "require_valid_json_events": True, "require_build_finished": True,
                "require_test_summary": False, "allow_zero_tests": False,
            })
            bad_requirements = (
                {"unknown": True},
                {"require_build_finished": "false"},
                {"allow_zero_tests": True},
                {"require_test_summary": True},
                {"require_valid_json_events": False},
            )
            for requirements in bad_requirements:
                with self.subTest(requirements=requirements):
                    broken = json.loads(json.dumps(base))
                    broken["steps"][0]["evidence_requirements"] = requirements
                    config_path.write_text(json.dumps(broken), encoding="utf-8")
                    with self.assertRaises(agent.ConfigError):
                        agent.load_config(config_path)
            text_config = json.loads(json.dumps(base))
            text_config["steps"][0] = {"id": "text", "args": ["check"], "parser": "text",
                                       "evidence_requirements": {"require_build_finished": False}}
            config_path.write_text(json.dumps(text_config), encoding="utf-8")
            with self.assertRaises(agent.ConfigError):
                agent.load_config(config_path)

            custom = {
                "schema_version": 1, "workspace_root": ".", "execution": {},
                "steps": [{
                    "id": "custom", "args": ["my-json-command", "--message-format=json"],
                    "parser": "cargo-json", "evidence_requirements": {
                        "require_valid_json_events": True, "require_build_finished": False,
                    },
                }],
            }
            config_path.write_text(json.dumps(custom), encoding="utf-8")
            loaded_custom, _raw, _digest = agent.load_config(config_path)
            self.assertFalse(loaded_custom["steps"][0]["evidence_requirements"]["require_build_finished"])

            false_build = json.loads(json.dumps(base))
            false_build["steps"][0]["evidence_requirements"] = {"require_build_finished": False}
            config_path.write_text(json.dumps(false_build), encoding="utf-8")
            loaded_false_build, _raw, _digest = agent.load_config(config_path)
            step = loaded_false_build["steps"][0]
            analysis = provenance.analyze_cargo_invocation(
                step["args"], Path(temp), {"CARGO_HOME": str(Path(temp) / "cargo-home")},
                {"parsed": {"release": "1.91.1", "channel": "stable"}},
                agent.BUILD_PRODUCING_SUBCOMMANDS,
            )
            with self.assertRaises(agent.ConfigError):
                agent.validate_invocation_policy(step, analysis)

    def test_normal_cargo_check_cannot_bypass_build_finished_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[package]\nname="x"\nversion="0.1.0"\n', encoding="utf-8")
            output = root / "evidence"
            output.mkdir()
            step = {
                "id": "check", "args": ["check", "--message-format=json"], "parser": "cargo-json",
                "cwd": ".", "timeout_seconds": None, "environment": {}, "unset_environment": [],
                "redact_arg_indexes": [], "evidence_requirements": {
                    "require_valid_json_events": True, "require_build_finished": False,
                    "require_test_summary": False, "allow_zero_tests": False,
                },
            }
            execution = {"default_timeout_seconds": 10, "termination_grace_seconds": 1,
                         "environment": {}, "unset_environment": []}
            invocation_analysis = provenance.analyze_cargo_invocation(
                step["args"], workspace, {},
                {"parsed": {"release": "1.91.1", "channel": "stable"}},
                agent.BUILD_PRODUCING_SUBCOMMANDS,
            )
            with mock.patch.object(agent, "run_process") as run:
                with self.assertRaises(agent.ConfigError):
                    agent.process_step(
                        "cargo", step, workspace, output, {}, execution,
                        invocation_analysis=invocation_analysis,
                    )
            run.assert_not_called()
            self.assertFalse((output / "check").exists())

    def test_redaction_masks_index_and_known_flags(self):
        args = ["clippy", "--token", "abc123", "--password=secret", "--locked"]
        masked = agent.redact_args(args, [4])
        self.assertEqual(masked, ["clippy", "--token", "<REDACTED>", "--password=<REDACTED>", "<REDACTED>"])

    def test_shared_redaction_api_covers_every_sensitive_flag_form(self):
        self.assertIs(agent.redact_args, provenance.redact_args)
        for flag in sorted(provenance.SENSITIVE_FLAGS):
            with self.subTest(flag=flag, form="separate"):
                self.assertEqual(
                    provenance.redact_args(["check", flag, "FLAG_CANARY"]),
                    ["check", flag, "<REDACTED>"],
                )
            with self.subTest(flag=flag, form="equals"):
                self.assertEqual(
                    provenance.redact_args(["check", flag + "=FLAG_CANARY"]),
                    ["check", flag + "=<REDACTED>"],
                )

    def test_explicit_indexes_are_applied_after_automatic_secret_detection(self):
        args = ["check", "--token", "TOKEN_CANARY", "--locked", "ordinary"]
        self.assertEqual(
            provenance.redact_args(args, [2]),
            ["check", "--token", "<REDACTED>", "--locked", "ordinary"],
        )
        self.assertEqual(
            provenance.redact_args(args, [1]),
            ["check", "<REDACTED>", "<REDACTED>", "--locked", "ordinary"],
        )
        self.assertEqual(
            provenance.redact_args(args, [4]),
            ["check", "--token", "<REDACTED>", "--locked", "<REDACTED>"],
        )
        self.assertEqual(
            provenance.redact_args(["check", "--token=TOKEN_CANARY"], [1]),
            ["check", "<REDACTED>"],
        )

    def test_cargo_config_redaction_preserves_setting_names_and_sanitizes_urls(self):
        self.assertEqual(
            provenance.redact_args(["--config", "registry.token=CONFIG_CANARY"]),
            ["--config", "registry.token=<REDACTED>"],
        )
        self.assertEqual(
            provenance.redact_args(["--config=registries.private.password=CONFIG_CANARY"]),
            ["--config=registries.private.password=<REDACTED>"],
        )
        self.assertEqual(
            provenance.redact_args(["--config", 'registry.index="sparse+https://user:pass@host/index?token=URL_CANARY&channel=stable#FRAGMENT_CANARY"']),
            ["--config", 'registry.index="sparse+https://<REDACTED>@host/index?token=%3CREDACTED%3E&channel=stable#<REDACTED>"'],
        )

    def test_nested_cargo_config_inline_table_redacts_sensitive_value(self):
        args = [
            "--config",
            'registries.private = { token = "H01_NESTED_TOKEN_CANARY", protocol = "sparse" }',
        ]
        redacted = provenance.redact_args(args)
        self.assertNotIn("H01_NESTED_TOKEN_CANARY", json.dumps(redacted))
        self.assertEqual(
            redacted[1],
            'registries.private = { token = <REDACTED>, protocol = "sparse" }',
        )
        self.assertEqual(
            args[1],
            'registries.private = { token = "H01_NESTED_TOKEN_CANARY", protocol = "sparse" }',
        )

    def test_deeply_nested_config_redacts_secret_and_url_components(self):
        args = [
            "--config",
            'registries = { private = { token = "H01_DEEP_TOKEN_CANARY", '
            'index = "https://url-user:url-password@example.invalid/index'
            '?token=H01_URL_QUERY_CANARY&channel=stable#H01_URL_FRAGMENT_CANARY" } }',
        ]
        redacted = provenance.redact_args(args)
        self.assertEqual(
            redacted[1],
            'registries = { private = { token = <REDACTED>, '
            'index = "https://<REDACTED>@example.invalid/index'
            '?token=%3CREDACTED%3E&channel=stable#<REDACTED>" } }',
        )
        for secret in (
            "H01_DEEP_TOKEN_CANARY", "url-user", "url-password",
            "H01_URL_QUERY_CANARY", "H01_URL_FRAGMENT_CANARY",
        ):
            self.assertNotIn(secret, json.dumps(redacted))
        self.assertEqual(args[1].count("H01_"), 3)

    def test_config_array_of_inline_tables_redacts_values_and_preserves_order(self):
        value = (
            'registries.private.mirrors = [\n'
            '  { url = "https://example.invalid/one", token = "H01_ARRAY_TOKEN_CANARY" },\n'
            '  { url = "https://example.invalid/two", credential = "H01_ARRAY_CREDENTIAL_CANARY" }\n'
            ']'
        )
        redacted = provenance.redact_args(["--config", value])
        self.assertEqual(
            redacted[1],
            'registries.private.mirrors = [\n'
            '  { url = "https://example.invalid/one", token = <REDACTED> },\n'
            '  { url = "https://example.invalid/two", credential = <REDACTED> }\n'
            ']',
        )
        self.assertNotIn("H01_ARRAY_TOKEN_CANARY", json.dumps(redacted))
        self.assertNotIn("H01_ARRAY_CREDENTIAL_CANARY", json.dumps(redacted))
        self.assertLess(redacted[1].index("/one"), redacted[1].index("/two"))

    def test_config_scans_quoted_and_mixed_case_sensitive_keys(self):
        value = (
            'registry.inline = { "client-secret" = "H01_QUOTED_CANARY", '
            'AuthToken = "H01_CASE_CANARY", "ordinary" = "keep-me" }'
        )
        redacted = provenance.redact_args(["--config", value])
        self.assertEqual(
            redacted[1],
            'registry.inline = { "client-secret" = <REDACTED>, '
            'AuthToken = <REDACTED>, "ordinary" = "keep-me" }',
        )
        self.assertNotIn("H01_QUOTED_CANARY", json.dumps(redacted))
        self.assertNotIn("H01_CASE_CANARY", json.dumps(redacted))

    def test_config_scans_sensitive_components_of_dotted_inline_keys(self):
        value = (
            'registry.inline = { registry.private.token = "H01_DOTTED_TOKEN_CANARY", '
            'protocol = "sparse" }'
        )
        redacted = provenance.redact_args(["--config", value])
        self.assertEqual(
            redacted[1],
            'registry.inline = { registry.private.token = <REDACTED>, protocol = "sparse" }',
        )
        self.assertNotIn("H01_DOTTED_TOKEN_CANARY", json.dumps(redacted))

    def test_sensitive_config_key_redacts_its_entire_complex_value(self):
        value = (
            'registries.private = { token = [ { password = "H01_COMPLEX_CANARY" }, '
            '"second" ], protocol = "sparse" }'
        )
        redacted = provenance.redact_args(["--config=" + value])
        self.assertEqual(
            redacted[0],
            '--config=registries.private = { token = <REDACTED>, protocol = "sparse" }',
        )
        self.assertNotIn("H01_COMPLEX_CANARY", json.dumps(redacted))

    def test_unsupported_or_invalid_config_value_fails_closed(self):
        values = [
            'registries.private = { token = "H01_INVALID_CANARY", mirrors = [ { url = "x" }',
            'registries.private = { token = "H01_TRAILING_CANARY", }',
        ]
        for value in values:
            with self.subTest(value=value):
                original = ["--config", value]
                redacted = provenance.redact_args(original)
                self.assertNotIn("H01_INVALID_CANARY", json.dumps(redacted))
                self.assertNotIn("H01_TRAILING_CANARY", json.dumps(redacted))
                self.assertTrue(redacted[1].endswith("=<REDACTED>"))
                self.assertEqual(original[1], value)

    def test_cargo_config_comments_are_replaced_without_changing_values_or_strings(self):
        cases = [
            ("registry.index=1 # password=COMMENT_CANARY", "COMMENT_CANARY"),
            ('registry.index=1 # token = "COMMENT_TOKEN_CANARY"', "COMMENT_TOKEN_CANARY"),
            (
                'registry.index="https://example.invalid/index" '
                '# https://comment-user:COMMENT_URL_CANARY@example.invalid/path',
                "COMMENT_URL_CANARY",
            ),
            (
                'registry.index="https://example.invalid/index" '
                "# ?token=COMMENT_QUERY_CANARY&channel=stable",
                "COMMENT_QUERY_CANARY",
            ),
            (
                'registry.values = [\n  "first", # password=ARRAY_COMMENT_CANARY\n'
                '  "second"\n]',
                "ARRAY_COMMENT_CANARY",
            ),
        ]
        for value, canary in cases:
            with self.subTest(canary=canary):
                redacted = provenance.redact_args(["--config", value])
                self.assertIn("#<REDACTED_COMMENT>", redacted[1])
                self.assertNotIn(canary, json.dumps(redacted))
        self.assertEqual(
            provenance.redact_args(["--config", "registry.index=1 # password=COMMENT_CANARY"])[1],
            "registry.index=1 #<REDACTED_COMMENT>",
        )
        self.assertEqual(
            provenance.redact_args(["--config", 'registry.label="literal # is string content"'])[1],
            'registry.label="literal # is string content"',
        )
        self.assertNotIn(
            "comment-user",
            provenance.redact_args([
                "--config",
                'registry.index="https://example.invalid/index" '
                "# https://comment-user:COMMENT_URL_CANARY@example.invalid/path",
            ])[1],
        )
        self.assertEqual(
            provenance.redact_args(["--config", 'registry.values=["first", # hidden\n "second"]'])[1],
            'registry.values=["first", #<REDACTED_COMMENT>\n "second"]',
        )

    def test_invalid_or_unsupported_toml_values_fail_closed(self):
        values = [
            "registry.index=garbage=INVALID_ATOM_CANARY",
            'registry.index={ foo bar = "INVALID_KEY_CANARY" }',
            "registry.index=1#password=NO_SPACE_CANARY",
            'registry.index="safe"#password=NO_STRING_SPACE_CANARY',
            'registry.index={ "unfinished = "INVALID_QUOTED_KEY_CANARY" }',
            'registry.index="bad\\qINVALID_ESCAPE_CANARY"',
            'registry.index={ foo = "DUPLICATE_KEY_CANARY", "foo" = "second" }',
            'registry.index={ foo.bar = "first", foo = "DOTTED_CONFLICT_CANARY" }',
            "registry.index=01",
            "registry.index=1__2",
            "registry.index=2023-02-29",
            "registry.index=24:00:00",
            'registry.index=["one", "two"',
            'registry.index={ foo = "INCOMPLETE_TABLE_CANARY"',
            "registry.index=1 TRAILING_TEXT_CANARY",
            "registry.index=" + ("[" * 130) + '"DEPTH_LIMIT_CANARY"' + ("]" * 130),
        ]
        for value in values:
            with self.subTest(value=value[:80]):
                redacted = provenance.redact_args(["--config", value])
                self.assertEqual(redacted[1], "registry.index=<REDACTED>")
                for canary in (
                    "INVALID_ATOM_CANARY", "INVALID_KEY_CANARY", "NO_SPACE_CANARY",
                    "NO_STRING_SPACE_CANARY",
                    "INVALID_QUOTED_KEY_CANARY", "INVALID_ESCAPE_CANARY",
                    "DUPLICATE_KEY_CANARY", "DOTTED_CONFLICT_CANARY",
                    "INCOMPLETE_TABLE_CANARY", "TRAILING_TEXT_CANARY", "DEPTH_LIMIT_CANARY",
                ):
                    self.assertNotIn(canary, redacted[1])

    def test_valid_toml_scalar_forms_and_quoted_url_are_preserved_safely(self):
        value = (
            'registry.values=[true, false, 0, -1, +2, 0xDEAD, 0o755, 0b10, '
            '1.25, -2e3, inf, -nan, 1979-05-27, 07:32:00, '
            '1979-05-27T07:32:00Z]'
        )
        self.assertEqual(provenance.redact_args(["--config", value])[1], value)
        url_value = (
            'registry.index="https://user:pass@example.invalid/index?token=URL_VALUE_CANARY&channel=stable"'
        )
        self.assertEqual(
            provenance.redact_args(["--config", url_value])[1],
            'registry.index="https://<REDACTED>@example.invalid/index?token=%3CREDACTED%3E&channel=stable"',
        )
        self.assertEqual(
            provenance.redact_args(["--config", "registry.index=sparse+https://user:pass@example.invalid/path"])[1],
            "registry.index=<REDACTED>",
        )

    def test_equals_config_form_scans_nested_toml_and_keeps_original_argv(self):
        argument = (
            '--config=registries.private = { "client-secret" = "H01_EQUALS_CANARY", '
            'protocol = "sparse" }'
        )
        original = [argument]
        redacted = provenance.redact_args(original)
        self.assertEqual(
            redacted[0],
            '--config=registries.private = { "client-secret" = <REDACTED>, protocol = "sparse" }',
        )
        self.assertNotIn("H01_EQUALS_CANARY", json.dumps(redacted))
        self.assertEqual(original, [argument])

    def test_url_redaction_is_shared_by_arguments_and_observed_environment(self):
        url = "https://url-user:url-password@example.invalid:8443/index?channel=stable&api-key=QUERY_CANARY#FRAGMENT_CANARY"
        redacted = "https://<REDACTED>@example.invalid:8443/index?channel=stable&api-key=%3CREDACTED%3E#<REDACTED>"
        self.assertEqual(provenance.redact_args(["--index", url])[1], redacted)
        self.assertEqual(
            provenance._redact_environment_value("CARGO_REGISTRIES_PRIVATE_URL", url),
            redacted,
        )
        self.assertEqual(
            provenance._redact_environment_value("CARGO_REGISTRIES_PRIVATE_TOKEN", "TOKEN_CANARY"),
            "<REDACTED>",
        )
        self.assertEqual(
            provenance._redact_environment_value("RUSTUP_DIST_SERVER", url),
            redacted,
        )

    def test_probe_persists_redacted_argv_but_executes_original_argv(self):
        command = [
            "cargo", "metadata", "--config", "registry.token=PROBE_CANARY",
            "--index", "https://user:pass@example.invalid/?password=QUERY_CANARY",
        ]
        capture_paths = []

        def supervised(command_arg, _cwd, _env, stdout_path, stderr_path, timeout, grace, **kwargs):
            capture_paths.append(stdout_path.parent)
            stdout_path.write_bytes(b"")
            stderr_path.write_bytes(b"")
            empty_hash = provenance.sha256_bytes(b"")
            return {
                "exit_code": 0, "duration_ms": 1, "interrupted": False, "timed_out": False,
                "spawn_error": None, "supervision_error": None,
                "process_tree": {"cleanup_complete": True},
                "capture": {
                    "stdout": {"bytes": 0, "sha256": empty_hash, "truncated": False, "errors": []},
                    "stderr": {"bytes": 0, "sha256": empty_hash, "truncated": False, "errors": []},
                },
            }

        with mock.patch.object(provenance, "run_supervised_process", side_effect=supervised) as run:
            result = provenance.run_probe("cargo_metadata", command, Path("."), {})
        self.assertEqual(run.call_args.args[0], command)
        self.assertEqual(run.call_args.args[5], provenance.PROBE_TIMEOUT_SECONDS)
        self.assertEqual(run.call_args.args[6], 5.0)
        self.assertEqual(run.call_args.kwargs["capture_limits"]["stdout"], provenance.PROBE_OUTPUT_LIMIT)
        self.assertFalse(capture_paths[0].exists(), "probe temporary capture directory was not removed")
        self.assertEqual(command[3], "registry.token=PROBE_CANARY")
        self.assertEqual(result["argv"][3], "registry.token=<REDACTED>")
        self.assertNotIn("PROBE_CANARY", json.dumps(result["argv"]))
        self.assertNotIn("QUERY_CANARY", json.dumps(result["argv"]))

    def test_metadata_probe_argument_selection_maps_explicit_source_indexes(self):
        original = [
            "check", "--config", "build.target='x86_64-test'",
            "--target", "ignored-target",
            "--config=registry.token=MAP_CANARY",
            "--", "--config", "after-separator",
        ]
        selected, source_indexes = provenance._cargo_config_arguments_with_source_indexes(original)
        self.assertEqual(
            selected,
            ["--config", "build.target='x86_64-test'", "--config=registry.token=MAP_CANARY"],
        )
        self.assertEqual(source_indexes, [1, 2, 5])
        self.assertEqual(
            provenance._map_redact_arg_indexes([1, 2, 5], source_indexes, destination_offset=8),
            [8, 9, 10],
        )
        self.assertEqual(
            provenance._map_redact_arg_indexes([0, 2, 4], source_indexes, destination_offset=8),
            [9],
        )

    def test_configuration_refresh_uses_original_invocation_arguments(self):
        original_args = ["check", "--config", "registry.token=REFRESH_CANARY"]
        step_record = {
            "cwd": ".",
            "cargo_metadata_probe": {"argv": ["cargo", "metadata", "--config", "registry.token=<REDACTED>"]},
            "cargo_configuration": {"files": [], "cargo_home_search_path": None},
        }
        with mock.patch.object(provenance, "_cargo_config_files", return_value=[]) as config_files:
            provenance.refresh_step_cargo_configuration(step_record, original_args=original_args)
        self.assertEqual(config_files.call_args.args[2], original_args)

    def test_environment_values_never_appear_in_redacted_config(self):
        config = {
            "schema_version": 1,
            "workspace_root": ".",
            "execution": {
                "cargo_executable": "cargo",
                "continue_on_error": True,
                "default_timeout_seconds": None,
                "termination_grace_seconds": 5,
                "environment": {"API_TOKEN": "do-not-leak"},
                "unset_environment": [],
            },
            "steps": [{
                "id": "check", "args": ["check"], "enabled": True, "parser": "text",
                "cwd": ".", "timeout_seconds": None, "environment": {"PASS": "also-secret"},
                "unset_environment": [], "redact_arg_indexes": [],
            }],
        }
        encoded = json.dumps(agent.redacted_config(config))
        self.assertNotIn("do-not-leak", encoded)
        self.assertNotIn("also-secret", encoded)
        self.assertIn("<REDACTED>", encoded)

    def test_parse_cargo_json_preserves_events_and_deduplicates_diagnostics(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stdout = root / "stdout.bin"
            step_dir = root / "step"
            step_dir.mkdir()
            diagnostic_event = {
                "reason": "compiler-message",
                "package_id": "path+file:///project#demo@0.1.0",
                "target": {"name": "demo", "kind": ["lib"]},
                "message": {
                    "level": "warning",
                    "code": {"code": "dead_code", "explanation": None},
                    "message": "unused item",
                    "spans": [{
                        "file_name": "src/lib.rs", "line_start": 4, "column_start": 1,
                        "is_primary": True, "text": [],
                    }],
                    "children": [],
                },
            }
            finished = {"reason": "build-finished", "success": True}
            raw_lines = [
                (json.dumps(diagnostic_event, separators=(",", ":")) + "\n").encode(),
                (json.dumps(diagnostic_event, separators=(",", ":")) + "\n").encode(),
                (json.dumps(finished) + "\n").encode(),
                b"this is not json\n",
            ]
            stdout.write_bytes(b"".join(raw_lines))
            result = agent.parse_cargo_json(stdout, step_dir)
            self.assertEqual(result["raw_event_count"], 3)
            self.assertEqual(result["diagnostic_event_count"], 2)
            self.assertEqual(result["unique_diagnostic_count"], 1)
            self.assertTrue(result["build_finished_success"])
            self.assertEqual((step_dir / "raw.jsonl").read_bytes(), b"".join(raw_lines[:3]))
            unique = [json.loads(line) for line in (step_dir / "diagnostics-unique.jsonl").read_text().splitlines()]
            self.assertEqual(unique[0]["occurrence_count"], 2)
            self.assertEqual((step_dir / "non-json.stdout.bin").read_bytes(), raw_lines[3])

    def test_parse_cargo_json_flags_malformed_events_but_keeps_unknown_reasons(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stdout, step_dir = root / "stdout.bin", root / "step"
            step_dir.mkdir()
            lines = [
                b'{"reason":"future-cargo-event","payload":1}\n',
                b'{"reason":"compiler-message", broken}\n',
                b"ordinary build-script output\n",
            ]
            stdout.write_bytes(b"".join(lines))
            result = agent.parse_cargo_json(stdout, step_dir)
            self.assertEqual(result["raw_event_count"], 1)
            self.assertEqual(result["event_counts"], {"future-cargo-event": 1})
            self.assertEqual(result["issues"][0]["code"], "malformed_cargo_json_event")
            self.assertEqual((step_dir / "raw.jsonl").read_bytes(), lines[0])
            self.assertEqual((step_dir / "non-json.stdout.bin").read_bytes(), b"".join(lines[1:]))

    def test_cargo_evidence_status_matrix(self):
        build_true = json.dumps({"reason": "build-finished", "success": True}).encode() + b"\n"
        build_false = json.dumps({"reason": "build-finished", "success": False}).encode() + b"\n"
        cases = (
            (build_true, 0, "passed", "complete"),
            (b"", 0, "incomplete", "incomplete"),
            (b"ordinary output\n", 0, "incomplete", "incomplete"),
            (b'{"reason":"compiler-artifact", broken}\n', 0, "parser_error", "invalid"),
            (b'{"reason":"compiler-artifact"}\n', 0, "incomplete", "incomplete"),
            (build_false, 0, "failed", "complete"),
            (b'{"reason":"build-finished","success":"true"}\n', 0, "parser_error", "invalid"),
            (build_true + build_true, 0, "parser_error", "invalid"),
            (json.dumps({"reason": "future-event"}).encode() + b"\n" + build_true, 0, "passed", "complete"),
            (build_true + b"ordinary subprocess output\n", 0, "passed", "complete"),
        )
        for output, exit_code, status, evidence_status in cases:
            with self.subTest(output=output):
                record, non_json = self.run_evidence_step("cargo-json", output, exit_code=exit_code)
                self.assertEqual(record["execution_status"], "completed")
                self.assertEqual(record["status"], status)
                self.assertEqual(record["evidence_status"], evidence_status)
                if b"ordinary subprocess output" in output:
                    self.assertIn(b"ordinary subprocess output", non_json)

    def test_libtest_summaries_are_complete_validated_and_aggregated(self):
        summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        two_summaries = summary + summary.replace("1 passed", "2 passed")
        result, _ = self.run_evidence_step(
            "cargo-json+libtest",
            json.dumps({"reason": "build-finished", "success": True}).encode() + b"\n" + two_summaries.encode(),
        )
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["evidence_status"], "complete")
        self.assertEqual(result["tests"]["suite_totals"]["passed"], 3)

        zero = "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
        cargo = json.dumps({"reason": "build-finished", "success": True}).encode() + b"\n"
        disallowed, _ = self.run_evidence_step("cargo-json+libtest", cargo + zero.encode())
        self.assertEqual((disallowed["status"], disallowed["evidence_status"]), ("incomplete", "incomplete"))
        self.assertIn("zero_tests_not_allowed", [issue["code"] for issue in disallowed["evidence_issues"]])
        allowed, _ = self.run_evidence_step(
            "cargo-json+libtest", cargo + zero.encode(), {"allow_zero_tests": True},
        )
        self.assertEqual((allowed["status"], allowed["evidence_status"]), ("passed", "complete"))
        self.assertEqual(allowed["tests"]["state"], "zero-tests-allowed")

    def test_missing_and_malformed_libtest_summaries_never_pass(self):
        cargo = json.dumps({"reason": "build-finished", "success": True}).encode() + b"\n"
        case_only = b"test module::works ... ok\n"
        missing, _ = self.run_evidence_step("cargo-json+libtest", cargo + case_only)
        self.assertEqual((missing["status"], missing["evidence_status"]), ("incomplete", "incomplete"))
        self.assertFalse(missing["tests"]["test_summary_observed"])
        allowed_missing, _ = self.run_evidence_step(
            "cargo-json+libtest", cargo + case_only, {"allow_zero_tests": True},
        )
        self.assertEqual(allowed_missing["evidence_status"], "incomplete")
        self.assertIn("missing_test_summary", [issue["code"] for issue in allowed_missing["evidence_issues"]])

        malformed = b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; finished in 0.01s\n"
        invalid, _ = self.run_evidence_step("cargo-json+libtest", cargo + malformed)
        self.assertEqual((invalid["status"], invalid["evidence_status"]), ("parser_error", "invalid"))

        inconsistent = b"test result: ok. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        invalid_status, _ = self.run_evidence_step("cargo-json+libtest", cargo + inconsistent)
        self.assertEqual(invalid_status["status"], "parser_error")

        duplicate = b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; 0 passed; finished in 0.01s\n"
        invalid_duplicate, _ = self.run_evidence_step("cargo-json+libtest", cargo + duplicate)
        self.assertEqual(invalid_duplicate["status"], "parser_error")
        failed_without_failures = b"test result: FAILED. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        invalid_failed, _ = self.run_evidence_step("cargo-json+libtest", cargo + failed_without_failures)
        self.assertEqual(invalid_failed["status"], "parser_error")

        negative_but_incomplete, _ = self.run_evidence_step(
            "cargo-json+libtest",
            json.dumps({"reason": "build-finished", "success": False}).encode() + b"\n",
        )
        self.assertEqual(negative_but_incomplete["status"], "failed")
        self.assertEqual(negative_but_incomplete["evidence_status"], "incomplete")

    def test_libtest_summary_requires_full_supported_completion_line(self):
        cargo = json.dumps({"reason": "build-finished", "success": True}).encode() + b"\n"
        valid_summaries = (
            b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
            b"test result: ok. 0 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0s\n",
        )
        record, _ = self.run_evidence_step("cargo-json+libtest", cargo + b"".join(valid_summaries))
        self.assertEqual(record["evidence_status"], "complete")
        self.assertEqual(record["tests"]["suite_count"], 2)
        self.assertEqual(record["tests"]["suite_totals"]["passed"], 1)

        malformed_summaries = (
            b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; MALFORMED JUNK\n",
            b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n",
        )
        for summary in malformed_summaries:
            with self.subTest(summary=summary):
                invalid, _ = self.run_evidence_step("cargo-json+libtest", cargo + summary)
                self.assertEqual(invalid["evidence_status"], "invalid")
                self.assertEqual(invalid["status"], "parser_error")
                self.assertIn(
                    "malformed_test_summary",
                    [issue["code"] for issue in invalid["evidence_issues"]],
                )

    def test_all_ignored_and_filtered_test_suites_require_zero_test_allowance(self):
        cargo = json.dumps({"reason": "build-finished", "success": True}).encode() + b"\n"
        cases = (
            (b"test result: ok. 0 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.00s\n", 2),
            (b"test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s\n", 3),
        )
        for summary, not_executed_count in cases:
            with self.subTest(summary=summary):
                disallowed, _ = self.run_evidence_step("cargo-json+libtest", cargo + summary)
                self.assertEqual(disallowed["evidence_status"], "incomplete")
                self.assertEqual(disallowed["tests"]["executed_test_count"], 0)
                self.assertEqual(disallowed["evidence_issues"][-1]["code"], "zero_tests_not_allowed")
                allowed, _ = self.run_evidence_step(
                    "cargo-json+libtest", cargo + summary, {"allow_zero_tests": True},
                )
                self.assertEqual(allowed["evidence_status"], "complete")
                self.assertEqual(allowed["tests"]["state"], "zero-tests-allowed")
                self.assertEqual(allowed["tests"]["suite_totals"]["ignored"] +
                                 allowed["tests"]["suite_totals"]["filtered_out"], not_executed_count)

    def test_pipeline_incomplete_and_parser_error_control_flow(self):
        for continue_on_error, first_status, expected_calls, expected_pipeline in (
            (True, "incomplete", 2, "incomplete"),
            (False, "incomplete", 1, "incomplete"),
            (True, "parser_error", 1, "error"),
        ):
            with self.subTest(continue_on_error=continue_on_error, first_status=first_status), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                workspace = root / "workspace"
                workspace.mkdir()
                output = root / "evidence"
                output.mkdir()
                config = {
                    "schema_version": 1, "workspace_root": str(workspace),
                    "execution": {"cargo_executable": "cargo", "continue_on_error": continue_on_error,
                                  "default_timeout_seconds": None, "termination_grace_seconds": 1,
                                  "environment": {}, "unset_environment": []},
                    "steps": [
                        {"id": "first", "enabled": True, "args": ["check"], "parser": "text",
                         "cwd": ".", "timeout_seconds": None, "environment": {},
                         "unset_environment": [], "redact_arg_indexes": []},
                        {"id": "second", "enabled": True, "args": ["test"], "parser": "text",
                         "cwd": ".", "timeout_seconds": None, "environment": {},
                         "unset_environment": [], "redact_arg_indexes": []},
                    ],
                    "_config_path": str(root / "pipeline.json"), "_config_sha256": "test-hash",
                }
                runner = agent.Runner(config, workspace, output, False)
                first = {"id": "first", "enabled": True, "status": first_status, "exit_code": 0,
                         "evidence_status": "invalid" if first_status == "parser_error" else "incomplete",
                         "evidence_issues": [{"code": "missing_build_finished", "message": "missing"}]}
                second = {"id": "second", "enabled": True, "status": "passed", "exit_code": 0,
                          "evidence_status": "not_applicable"}
                with mock.patch.object(agent, "process_step", side_effect=[first, second]) as process:
                    runner.execute()
                self.assertEqual(process.call_count, expected_calls)
                self.assertEqual(runner.make_summary()["status"], expected_pipeline)
                self.assertEqual(runner.make_summary()["incomplete_steps"], 1 if first_status == "incomplete" else 0)
                self.assertEqual(runner.make_summary()["parser_error_steps"], 1 if first_status == "parser_error" else 0)

    def test_parse_libtest_records_cases_and_suite_totals(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stdout = root / "stdout.log"
            stderr = root / "stderr.log"
            step_dir = root / "step"
            step_dir.mkdir()
            stdout.write_text(
                "test module::works ... ok (0.00s)\n"
                "test module::broken ... FAILED\n"
                "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n",
                encoding="utf-8",
            )
            stderr.write_text("", encoding="utf-8")
            result = agent.parse_libtest(stdout, stderr, step_dir)
            self.assertEqual(result["case_count"], 2)
            self.assertEqual(result["case_status_counts"]["failed"], 1)
            self.assertEqual(result["suite_totals"]["passed"], 1)
            self.assertEqual(result["suite_totals"]["failed"], 1)


    def test_custom_cargo_subcommand_and_toolchain_are_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            config_path = Path(temp) / "pipeline.json"
            config = {
                "schema_version": 1,
                "workspace_root": ".",
                "execution": {},
                "steps": [{"id": "custom", "args": ["+nightly", "my-cargo-plugin", "--flag"]}],
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            loaded, _raw, _digest = agent.load_config(config_path)
            self.assertEqual(agent.cargo_subcommand(loaded["steps"][0]["args"]), "my-cargo-plugin")

    def test_cargo_json_parser_is_not_allowed_for_fmt(self):
        with tempfile.TemporaryDirectory() as temp:
            config_path = Path(temp) / "pipeline.json"
            config = {
                "schema_version": 1,
                "workspace_root": ".",
                "execution": {},
                "steps": [{
                    "id": "fmt", "args": ["fmt", "--message-format=json"], "parser": "cargo-json"
                }],
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            loaded, _raw, _digest = agent.load_config(config_path)
            analysis = provenance.analyze_cargo_invocation(
                loaded["steps"][0]["args"], Path(temp), {"CARGO_HOME": str(Path(temp) / "cargo-home")},
                {"parsed": {"release": "1.91.1", "channel": "stable"}},
                agent.BUILD_PRODUCING_SUBCOMMANDS,
            )
            with self.assertRaises(agent.ConfigError):
                agent.validate_invocation_policy(loaded["steps"][0], analysis)

    def test_environment_cannot_be_set_and_unset_in_same_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            config_path = Path(temp) / "pipeline.json"
            config = {
                "schema_version": 1,
                "workspace_root": ".",
                "execution": {"environment": {"TOKEN": "value"}, "unset_environment": ["TOKEN"]},
                "steps": [{"id": "check", "args": ["check"]}],
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaises(agent.ConfigError):
                agent.load_config(config_path)

    def test_write_jsonl_atomic_replaces_existing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "records.jsonl"
            path.write_text("old\n", encoding="utf-8")
            agent.write_jsonl_atomic(path, [{"new": True}])
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(rows, [{"new": True}])
            self.assertFalse(path.with_name(path.name + ".writing").exists())

    def test_step_working_directory_cannot_escape_workspace(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            root = parent / "workspace"
            outside = parent / "outside"
            root.mkdir()
            outside.mkdir()
            with self.assertRaises(agent.ConfigError):
                agent.resolve_cwd(root, "../outside")

    def test_archive_uses_new_name_instead_of_overwriting(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            output = parent / "evidence"
            output.mkdir()
            (output / "summary.json").write_text("{}\n", encoding="utf-8")
            existing = parent / "evidence.tar.gz"
            existing.write_bytes(b"keep-this-file")
            created = agent.create_archive(output)
            self.assertEqual(existing.read_bytes(), b"keep-this-file")
            self.assertEqual(created.name, "evidence-1.tar.gz")
            self.assertTrue(created.is_file())

    def test_artifact_inventory_hashes_known_unknown_and_temporary_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            root.mkdir()
            for name in artifact_inventory.ROOT_ROLES:
                (root / name).write_bytes(b"root")
            step = root / "check"
            step.mkdir()
            for name in artifact_inventory.STEP_ROLES:
                (step / name).write_bytes(b"step")
            (step / "future-parser-output.dat").write_bytes(b"unknown")
            (root / "manifest.json.writing").write_bytes(b"unfinished")
            inventory = artifact_inventory.build_inventory(root, ["check"])
            by_path = {item["path"]: item for item in inventory["artifacts"]}
            for name, role in artifact_inventory.ROOT_ROLES.items():
                self.assertEqual(by_path[name]["role"], role)
            for name, role in artifact_inventory.STEP_ROLES.items():
                self.assertEqual(by_path["check/" + name]["role"], role)
            unknown = by_path["check/future-parser-output.dat"]
            self.assertEqual(unknown["role"], "unclassified")
            self.assertEqual(unknown["sha256"], agent.sha256_bytes(b"unknown"))
            self.assertEqual(by_path["manifest.json.writing"]["status"], "unfinished")
            self.assertEqual(inventory["status"], "incomplete")
            self.assertEqual(inventory["inventory_digest"], artifact_inventory.calculate_inventory_digest(inventory))
            self.assertNotIn("artifact-inventory.json", by_path)
            self.assertEqual([item["path"] for item in inventory["artifacts"]], sorted(by_path))

    def test_artifact_inventory_empty_large_and_deterministic_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "empty.bin").write_bytes(b"")
            large = b"abcd" * (artifact_inventory.HASH_BLOCK_SIZE // 4 + 17)
            (root / "large.bin").write_bytes(large)
            first = artifact_inventory.build_inventory(root)
            second = artifact_inventory.build_inventory(root)
            first_rows = {item["path"]: item for item in first["artifacts"]}
            self.assertEqual(first_rows["empty.bin"]["sha256"], agent.sha256_bytes(b""))
            self.assertEqual(first_rows["empty.bin"]["size_bytes"], 0)
            self.assertEqual(first_rows["large.bin"]["sha256"], agent.sha256_bytes(large))
            self.assertEqual(first["inventory_digest"], second["inventory_digest"])

    def test_shared_hash_rejects_pre_read_identity_change_without_observed_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            expected_path = root / "expected.bin"
            other_path = root / "other.bin"
            expected_path.write_bytes(b"expected bytes")
            other_path.write_bytes(b"external target bytes")
            expected = os.stat(expected_path, follow_symlinks=False)

            class ReadGuard:
                def __init__(self, fd):
                    self.fd = fd
                def __enter__(self):
                    return self
                def __exit__(self, exc_type, exc, tb):
                    os.close(self.fd)
                def fileno(self):
                    return self.fd
                def read(self, _size):
                    raise AssertionError("changed descriptor content must not be read")

            with mock.patch.object(
                    artifact_inventory, "open_file_no_follow",
                    side_effect=lambda *args, **kwargs: os.open(str(other_path), os.O_RDONLY)):
                with mock.patch.object(artifact_inventory.os, "fdopen", side_effect=lambda fd, *args, **kwargs: ReadGuard(fd)):
                    digest, size, status, issue = artifact_inventory.hash_regular_file(expected_path, expected)
            self.assertIsNone(digest)
            self.assertIsNone(size)
            self.assertEqual(status, "unstable")
            self.assertNotIn("observed_sha256", issue)

    @unittest.skipUnless(os.name != "nt", "requires POSIX FIFOs and O_NONBLOCK")
    def test_shared_hash_rejects_fifo_without_writer_or_observed_digest(self):
        if not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"):
            self.skipTest("POSIX FIFO/nonblocking APIs are unavailable")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "candidate.fifo"
            os.mkfifo(str(path))
            digest, size, status, issue = artifact_inventory.hash_regular_file(path)
            self.assertIsNone(digest)
            self.assertIsNone(size)
            self.assertEqual(status, "unreadable")
            self.assertEqual(issue["code"], "artifact_not_regular")
            self.assertNotIn("observed_sha256", issue)

    @unittest.skipUnless(os.name != "nt", "requires POSIX FIFOs and O_NONBLOCK")
    def test_shared_hash_nonblocking_open_rejects_fifo_swapped_after_stat(self):
        if not hasattr(os, "mkfifo") or not hasattr(os, "O_NONBLOCK"):
            self.skipTest("POSIX FIFO/nonblocking APIs are unavailable")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "candidate.bin"
            path.write_bytes(b"regular file before deterministic swap")
            original_open = os.open
            original_path_stat = artifact_inventory._path_stat
            observed_flags = []
            swapped = []

            def stat_then_swap(candidate_path, parent_fd=None, name=None):
                info = original_path_stat(candidate_path, parent_fd, name)
                if (Path(candidate_path) == path and parent_fd is not None
                        and name == path.name and not swapped):
                    # Return the original regular-file identity, then replace
                    # its directory entry before open_file_no_follow runs.
                    os.unlink(name, dir_fd=parent_fd)
                    os.mkfifo(str(path))
                    swapped.append(True)
                return info

            def observed_open(candidate, flags, mode=0o777, *, dir_fd=None):
                if candidate == path.name:
                    observed_flags.append(flags)
                return original_open(candidate, flags, mode, dir_fd=dir_fd)

            supported_dir_fd = set(getattr(os, "supports_dir_fd", set()))
            supported_dir_fd.add(observed_open)
            with mock.patch.object(artifact_inventory, "_path_stat", side_effect=stat_then_swap):
                with mock.patch.object(artifact_inventory.os, "supports_dir_fd", supported_dir_fd):
                    with mock.patch.object(artifact_inventory.os, "open", new=observed_open):
                        with mock.patch.object(artifact_inventory.os, "fdopen", side_effect=AssertionError("FIFO must not be read")):
                            digest, size, status, issue = artifact_inventory.hash_regular_file(path)
            self.assertEqual(swapped, [True])
            self.assertEqual(len(observed_flags), 1)
            self.assertTrue(observed_flags[0] & os.O_NONBLOCK)
            self.assertIsNone(digest)
            self.assertIsNone(size)
            self.assertEqual(status, "unstable")
            self.assertNotIn("observed_sha256", issue)

    def test_secure_directory_preserves_body_oserror_and_verification_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sync_error = OSError("injected parent sync failure")
            sync_error.namespace_sync_failed = True
            sync_error.durability_sync_failed = True
            sync_error.published_path = str(root / "published.tar.gz")
            with self.assertRaises(OSError) as raised_os_error:
                with artifact_inventory.secure_directory(root):
                    raise sync_error
            self.assertIs(raised_os_error.exception, sync_error)
            self.assertTrue(raised_os_error.exception.namespace_sync_failed)
            self.assertTrue(raised_os_error.exception.durability_sync_failed)
            self.assertEqual(raised_os_error.exception.published_path, str(root / "published.tar.gz"))

            verification_error = artifact_inventory.FileVerificationError("caller_failure", root)
            with self.assertRaises(artifact_inventory.FileVerificationError) as raised_verification:
                with artifact_inventory.secure_directory(root):
                    raise verification_error
            self.assertIs(raised_verification.exception, verification_error)

    @unittest.skipUnless(os.name != "nt", "requires POSIX O_NOFOLLOW and symlink creation")
    def test_shared_hash_rejects_symlink_swap_between_stat_and_open(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "candidate.bin"
            target = root / "external.bin"
            path.write_bytes(b"expected original bytes")
            target.write_bytes(b"external target bytes")
            original_open = artifact_inventory.open_file_no_follow
            opened = []

            def swap_to_symlink(candidate, *args, **kwargs):
                if Path(candidate) == path and not opened:
                    opened.append(True)
                    path.unlink()
                    path.symlink_to(target)
                return original_open(candidate, *args, **kwargs)

            with mock.patch.object(artifact_inventory, "open_file_no_follow", side_effect=swap_to_symlink):
                digest, size, status, issue = artifact_inventory.hash_regular_file(path)
            self.assertEqual(opened, [True])
            self.assertIsNone(digest)
            self.assertIsNone(size)
            self.assertEqual(status, "unstable")
            self.assertNotIn("observed_sha256", issue)

    def test_shared_hash_keeps_diagnostic_hash_only_for_post_read_instability(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "data.bin"
            content = b"stable descriptor, changed path state"
            path.write_bytes(content)
            original_same_file_state = artifact_inventory._same_file_state

            def changed_file_state(left, right):
                if stat.S_ISREG(left.st_mode):
                    return False
                return original_same_file_state(left, right)

            with mock.patch.object(artifact_inventory, "_same_file_state", side_effect=changed_file_state):
                digest, size, status, issue = artifact_inventory.hash_regular_file(path)
            self.assertIsNone(digest)
            self.assertEqual(size, len(content))
            self.assertEqual(status, "unstable")
            self.assertEqual(issue["observed_sha256"], agent.sha256_bytes(content))

    def test_shared_hash_reports_unstable_when_path_disappears_after_read(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "data.bin"
            content = b"descriptor read before path removal"
            path.write_bytes(content)
            original_path_stat = artifact_inventory._path_stat
            candidate_stat_calls = [0]

            def remove_after_read(candidate, parent_fd=None, name=None):
                if Path(candidate) == path:
                    candidate_stat_calls[0] += 1
                    if candidate_stat_calls[0] == 4:
                        path.unlink()
                        raise FileNotFoundError(str(path))
                return original_path_stat(candidate, parent_fd, name)

            with mock.patch.object(artifact_inventory, "_path_stat", side_effect=remove_after_read):
                digest, size, status, issue = artifact_inventory.hash_regular_file(path)
            self.assertEqual(candidate_stat_calls[0], 5)
            self.assertIsNone(digest)
            self.assertEqual(size, len(content))
            self.assertEqual(status, "unstable")
            self.assertEqual(issue["observed_sha256"], agent.sha256_bytes(content))

    def test_atomic_writer_sync_error_does_not_publish_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "manifest.json"
            path.write_bytes(b"old bytes")
            with mock.patch.object(agent, "sync_fd", side_effect=OSError("injected file sync failure")):
                with self.assertRaises(OSError):
                    agent.write_json_atomic(path, {"new": True})
            self.assertEqual(path.read_bytes(), b"old bytes")
            self.assertFalse(list(Path(temp).glob("*.writing")))

    @unittest.skipUnless(os.name != "nt", "requires POSIX directory fsync semantics")
    def test_atomic_replace_syncs_parent_after_visible_replace_and_reports_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, destination = root / "item.writing", root / "item.json"
            source.write_bytes(b"new")
            destination.write_bytes(b"old")
            real_sync_fd = artifact_inventory.sync_fd
            order = []

            def fail_after_replace(fd, error_code="file_sync_failed"):
                order.append(error_code)
                if error_code == "directory_sync_failed_after_replace":
                    error = OSError("injected directory sync failure")
                    error.durability_sync_failed = True
                    error.namespace_sync_failed = True
                    error.error_code = error_code
                    error.published_path = str(destination)
                    raise error
                return real_sync_fd(fd, error_code)

            with mock.patch.object(artifact_inventory, "sync_fd", side_effect=fail_after_replace):
                with self.assertRaises(OSError) as raised:
                    artifact_inventory.atomic_replace(source, destination)
            self.assertEqual(order, ["directory_sync_failed_after_replace"])
            self.assertTrue(getattr(raised.exception, "namespace_sync_failed", False))
            self.assertEqual(destination.read_bytes(), b"new")
            self.assertFalse(source.exists())

    @unittest.skipUnless(os.name != "nt", "requires POSIX descriptor-relative replace")
    def test_atomic_replace_uses_held_source_and_destination_directory_descriptors(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, destination = root / "item.writing", root / "item.json"
            source.write_bytes(b"new")
            destination.write_bytes(b"old")
            real_replace = os.replace
            calls = []

            def record_replace(src, dst, *args, **kwargs):
                calls.append((src, dst, kwargs.get("src_dir_fd"), kwargs.get("dst_dir_fd")))
                return real_replace(src, dst, *args, **kwargs)

            with mock.patch.object(artifact_inventory.os, "replace", side_effect=record_replace):
                artifact_inventory.atomic_replace(source, destination)
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][:2], (source.name, destination.name))
            self.assertIsInstance(calls[0][2], int)
            self.assertEqual(calls[0][2], calls[0][3])
            self.assertEqual(destination.read_bytes(), b"new")
            self.assertFalse(source.exists())

    @unittest.skipUnless(os.name != "nt", "requires POSIX descriptor-relative replace")
    def test_atomic_replace_fails_closed_when_descriptor_relative_rename_is_unsupported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, destination = root / "item.writing", root / "item.json"
            source.write_bytes(b"new")
            destination.write_bytes(b"old")
            with mock.patch.object(artifact_inventory.os, "supports_dir_fd", set()):
                with mock.patch.object(artifact_inventory.os, "replace", side_effect=AssertionError("unsafe fallback")):
                    with self.assertRaises(artifact_inventory.FileVerificationError) as raised:
                        artifact_inventory.atomic_replace(source, destination)
            self.assertEqual(raised.exception.code, "descriptor_relative_replace_unavailable")
            self.assertEqual(source.read_bytes(), b"new")
            self.assertEqual(destination.read_bytes(), b"old")

    @unittest.skipUnless(os.name != "nt", "requires POSIX descriptor-relative replace")
    def test_initial_manifest_publication_uses_descriptor_relative_replace(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / "manifest.json"
            agent.write_json_atomic(manifest, {"created": True})
            self.assertEqual(json.loads(manifest.read_text(encoding="utf-8")), {"created": True})
            self.assertFalse(list(manifest.parent.glob("*.writing")))

    @unittest.skipUnless(os.name != "nt", "requires POSIX directory fsync semantics")
    def test_evidence_sync_flushes_files_then_directories_bottom_up(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "evidence"
            nested = root / "nested"
            nested.mkdir(parents=True)
            (root / "root.bin").write_bytes(b"root")
            (nested / "child.bin").write_bytes(b"child")
            real_fsync = artifact_inventory.os.fsync
            observed = []

            def record_fsync(fd):
                info = os.fstat(fd)
                observed.append(("directory" if stat.S_ISDIR(info.st_mode) else "file", info.st_ino))
                return real_fsync(fd)

            with mock.patch.object(artifact_inventory.os, "fsync", side_effect=record_fsync):
                artifact_inventory.sync_evidence_tree(root)
            self.assertEqual([kind for kind, _inode in observed], ["file", "file", "directory", "directory", "directory"])
            self.assertEqual(
                [inode for _kind, inode in observed[-3:]],
                [os.stat(nested).st_ino, os.stat(root).st_ino, os.stat(base).st_ino],
            )

    @unittest.skipUnless(os.name != "nt", "requires POSIX directory fsync semantics")
    def test_archive_directory_sync_failure_preserves_candidate_for_same_path_resume(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runner, _output = self.make_finalization_runner(root)
            real_atomic_replace = agent.atomic_replace
            real_sync_fd = artifact_inventory.sync_fd
            injected = []

            def fail_archive_directory_sync(fd, error_code="file_sync_failed"):
                if error_code == "directory_sync_failed_after_replace" and not injected:
                    injected.append(True)
                    error = OSError("injected archive parent directory sync failure")
                    error.durability_sync_failed = True
                    error.namespace_sync_failed = True
                    error.error_code = error_code
                    error.published_path = str(runner.archive_path)
                    raise error
                return real_sync_fd(fd, error_code)

            def inject_only_for_archive(source, destination):
                if Path(destination) == runner.archive_path:
                    with mock.patch.object(artifact_inventory, "sync_fd", side_effect=fail_archive_directory_sync):
                        return real_atomic_replace(source, destination)
                return real_atomic_replace(source, destination)

            with mock.patch.object(agent, "atomic_replace", side_effect=inject_only_for_archive):
                runner.finalize()
                selected_path = runner.archive_path
                self.assertFalse(runner._finalization_state["complete"])
                self.assertTrue(selected_path.is_file())
                self.assertFalse(runner.archive_sidecar_path.exists())
                runner.finalize()
            self.assertTrue(runner._finalization_state["complete"], runner._finalization_errors)
            self.assertEqual(runner.archive_path, selected_path)
            self.assertTrue(runner.archive_sidecar_path.is_file())

    def test_writer_rejects_symlink_and_atomic_writer_leaves_writing_link_alone(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root / "outside.json"
            outside.write_bytes(b"outside")
            target = root / "target.json"
            writing = target.with_name(target.name + ".writing")
            try:
                target.symlink_to(outside)
                writing.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable on this platform")
            with self.assertRaises(OSError):
                agent.write_json(target, {"unsafe": True})
            agent.write_json_atomic(target, {"safe": True})
            self.assertEqual(outside.read_bytes(), b"outside")
            self.assertTrue(writing.is_symlink())
            self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"safe": True})

    def test_artifact_inventory_digest_normalizes_only_summary_sha_self_reference(self):
        inventory = {
            "schema_version": 1,
            "status": "complete",
            "artifacts": [
                {"path": "summary.json", "role": "run_summary", "sha256": "a" * 64, "size_bytes": 10},
                {"path": "output.bin", "role": "unknown", "sha256": "b" * 64, "size_bytes": 20},
            ],
        }
        digest = artifact_inventory.calculate_inventory_digest(inventory)
        changed_summary_hash = json.loads(json.dumps(inventory))
        changed_summary_hash["artifacts"][0]["sha256"] = "c" * 64
        self.assertEqual(artifact_inventory.calculate_inventory_digest(changed_summary_hash), digest)
        self.assertEqual(inventory["artifacts"][0]["sha256"], "a" * 64)

        changed_summary_size = json.loads(json.dumps(inventory))
        changed_summary_size["artifacts"][0]["size_bytes"] += 1
        self.assertNotEqual(artifact_inventory.calculate_inventory_digest(changed_summary_size), digest)
        changed_other_hash = json.loads(json.dumps(inventory))
        changed_other_hash["artifacts"][1]["sha256"] = "d" * 64
        self.assertNotEqual(artifact_inventory.calculate_inventory_digest(changed_other_hash), digest)

    def test_artifact_inventory_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            root.mkdir()
            outside = Path(temp) / "outside.bin"
            outside.write_bytes(b"outside")
            try:
                (root / "link.bin").symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            inventory = artifact_inventory.build_inventory(root)
            link = inventory["artifacts"][0]
            self.assertEqual(link["entry_type"], "symlink")
            self.assertEqual(link["status"], "not_followed")
            self.assertIsNone(link["sha256"])
            with self.assertRaises(OSError):
                artifact_inventory.sha256_file(root / "link.bin")
            self.assertEqual(inventory["status"], "incomplete")

    def test_artifact_inventory_reports_unreadable_unstable_and_escaped_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "evidence"
            root.mkdir()
            artifact = root / "data.bin"
            artifact.write_bytes(b"contents")
            with mock.patch.object(artifact_inventory, "open_file_no_follow", side_effect=PermissionError(13, "denied")):
                unreadable = artifact_inventory.build_inventory(root)
            unreadable_record = unreadable["artifacts"][0]
            self.assertEqual(unreadable_record["status"], "unreadable")
            self.assertIsNone(unreadable_record["sha256"])
            self.assertEqual(unreadable["status"], "incomplete")
            with mock.patch.object(artifact_inventory, "_cross_source_identity", return_value=False):
                unstable = artifact_inventory.build_inventory(root)
            unstable_record = unstable["artifacts"][0]
            self.assertEqual(unstable_record["status"], "unstable")
            self.assertIsNone(unstable_record["sha256"])
            self.assertEqual(unstable["status"], "incomplete")
            self.assertIsNone(artifact_inventory._relative_path(root, root.parent / "outside.bin"))

    @unittest.skipUnless(os.name != "nt", "requires POSIX descriptor-relative directory operations")
    def test_posix_inventory_stats_and_opens_children_relative_to_held_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            child = root / "child.bin"
            child.write_bytes(b"descriptor relative")
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            root_fd = os.open(str(root), flags)
            try:
                info = artifact_inventory.stat_child(child, root_fd, child.name)
                digest, size, status, issue = artifact_inventory.hash_regular_file(
                    child, info, root_fd, child.name,
                )
            finally:
                os.close(root_fd)
            self.assertEqual(status, "complete")
            self.assertIsNone(issue)
            self.assertEqual(size, len(b"descriptor relative"))
            self.assertEqual(digest, agent.sha256_bytes(b"descriptor relative"))

    def test_workspace_inventory_stops_on_directory_identity_change(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "workspace"
            changed = base / "changed"
            (root / "subtree").mkdir(parents=True)
            changed.mkdir()
            (root / "subtree" / "original.txt").write_text("original", encoding="utf-8")
            (changed / "external.txt").write_text("must not be inventoried", encoding="utf-8")
            original_secure_directory = provenance._shared_secure_directory

            def substitute_expected_directory(path, expected=None, parent_fd=None, name=None):
                if Path(path) == root / "subtree":
                    return original_secure_directory(changed, expected=expected)
                return original_secure_directory(path, expected, parent_fd, name)

            with mock.patch.object(provenance, "_shared_secure_directory", side_effect=substitute_expected_directory):
                inventory = provenance.inventory_workspace(root, [])
            subtree = next(item for item in inventory["entries"] if item["relative_path"] == "subtree")
            self.assertEqual(subtree["inclusion_status"], "unstable")
            paths = {item["relative_path"] for item in inventory["entries"]}
            self.assertNotIn("subtree/original.txt", paths)
            self.assertNotIn("external.txt", paths)

    def _prepare_symlink_archive(self, output: Path, target):
        output.mkdir()
        (output / "data.bin").write_bytes(b"data")
        (output / "other.bin").write_bytes(b"other")
        link = output / "link"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is unavailable")
        inventory = artifact_inventory.build_inventory(output)
        agent.write_json(output / "artifact-inventory.json", inventory)
        return inventory, link

    def _prepare_membership_archive(self, root: Path):
        output = root / "evidence"
        step_dir = output / "check"
        step_dir.mkdir(parents=True)
        (output / "manifest.json").write_bytes(b"{}\n")
        (step_dir / "summary.json").write_bytes(b'{"step":"check"}\n')
        inventory = artifact_inventory.build_inventory(output, ["check"])
        agent.write_json(output / "artifact-inventory.json", inventory)
        return output, inventory, agent.create_archive(output)

    def _make_tar_test_member(self, name: str, member_type: bytes, data: bytes = b"", linkname=None):
        member = tarfile.TarInfo(name)
        member.type = member_type
        if member.isfile():
            member.size = len(data)
            return member, io.BytesIO(data)
        if linkname is not None:
            member.linkname = linkname
        return member, None

    def _rewrite_archive_for_test(self, source_path: Path, destination_path: Path,
                                  remove_names=(), additions=()):
        with tarfile.open(source_path, "r:gz") as source, tarfile.open(destination_path, "w:gz") as destination:
            for member in source.getmembers():
                if member.name in remove_names:
                    continue
                content = source.extractfile(member) if member.isfile() else None
                destination.addfile(member, content)
                if content is not None:
                    content.close()
            for member, content in additions:
                destination.addfile(member, content)
                if content is not None:
                    content.close()

    def _assert_archive_rejected_after_rewrite(self, root: Path, output: Path, inventory: dict,
                                               source_path: Path, case: str,
                                               remove_names=(), additions=()):
        changed_path = root / (case + ".tar.gz")
        self._rewrite_archive_for_test(source_path, changed_path, remove_names, additions)
        with self.assertRaises(OSError):
            agent.verify_archive_snapshot(changed_path, output, inventory)

    def _archive_raw_name(self, archive_path: Path, normalized_name: str) -> str:
        with tarfile.open(archive_path, "r:gz") as archive:
            matches = [
                member.name for member in archive.getmembers()
                if member.name.replace("\\", "/").rstrip("/") == normalized_name
            ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_archive_verifies_exact_membership_with_required_directories(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, inventory, archive_path = self._prepare_membership_archive(root)
            with tarfile.open(archive_path, "r:gz") as archive:
                names = {member.name.replace("\\", "/").rstrip("/") for member in archive.getmembers()}
                self.assertIn(output.name, names)
                self.assertIn(output.name + "/check", names)
            agent.verify_archive_snapshot(archive_path, output, inventory)

    def test_archive_rejects_unexpected_top_level_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, inventory, archive_path = self._prepare_membership_archive(root)
            member, content = self._make_tar_test_member("outside.txt", tarfile.REGTYPE, b"outside")
            self._assert_archive_rejected_after_rewrite(
                root, output, inventory, archive_path, "outside-file", additions=[(member, content)],
            )

    def test_archive_rejects_unexpected_top_level_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, inventory, archive_path = self._prepare_membership_archive(root)
            member, content = self._make_tar_test_member("outside-dir/", tarfile.DIRTYPE)
            self._assert_archive_rejected_after_rewrite(
                root, output, inventory, archive_path, "outside-directory", additions=[(member, content)],
            )

    def test_archive_rejects_unexpected_empty_directory_inside_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, inventory, archive_path = self._prepare_membership_archive(root)
            member, content = self._make_tar_test_member(output.name + "/empty/", tarfile.DIRTYPE)
            self._assert_archive_rejected_after_rewrite(
                root, output, inventory, archive_path, "empty-directory", additions=[(member, content)],
            )

    def test_archive_rejects_duplicate_regular_file_member(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, inventory, archive_path = self._prepare_membership_archive(root)
            member, content = self._make_tar_test_member(
                output.name + "/check/summary.json", tarfile.REGTYPE, b'{"step":"check"}\n',
            )
            self._assert_archive_rejected_after_rewrite(
                root, output, inventory, archive_path, "duplicate-step-file", additions=[(member, content)],
            )

    def test_archive_rejects_duplicate_root_manifest_after_normalization(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, inventory, archive_path = self._prepare_membership_archive(root)
            member, content = self._make_tar_test_member(
                "./" + output.name + "/manifest.json", tarfile.REGTYPE, b"{}\n",
            )
            self._assert_archive_rejected_after_rewrite(
                root, output, inventory, archive_path, "duplicate-manifest", additions=[(member, content)],
            )

    def test_archive_rejects_duplicate_symlink_member(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, inventory, archive_path = self._prepare_membership_archive(root)
            first = self._make_tar_test_member(
                output.name + "/unexpected-link", tarfile.SYMTYPE, linkname="manifest.json",
            )
            second = self._make_tar_test_member(
                "./" + output.name + "/unexpected-link", tarfile.SYMTYPE, linkname="manifest.json",
            )
            self._assert_archive_rejected_after_rewrite(
                root, output, inventory, archive_path, "duplicate-symlink", additions=[first, second],
            )

    def test_archive_rejects_unexpected_symlink_member(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, inventory, archive_path = self._prepare_membership_archive(root)
            member = self._make_tar_test_member(
                output.name + "/unexpected-link", tarfile.SYMTYPE, linkname="manifest.json",
            )
            self._assert_archive_rejected_after_rewrite(
                root, output, inventory, archive_path, "unexpected-symlink", additions=[member],
            )

    def test_archive_rejects_conflicting_directory_and_file_member_names(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, inventory, archive_path = self._prepare_membership_archive(root)
            member, content = self._make_tar_test_member(
                output.name + "/check", tarfile.REGTYPE, b"conflict",
            )
            self._assert_archive_rejected_after_rewrite(
                root, output, inventory, archive_path, "directory-file-conflict", additions=[(member, content)],
            )

    def test_archive_rejects_absolute_member_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, inventory, archive_path = self._prepare_membership_archive(root)
            member, content = self._make_tar_test_member("/absolute.txt", tarfile.REGTYPE, b"outside")
            self._assert_archive_rejected_after_rewrite(
                root, output, inventory, archive_path, "absolute-member", additions=[(member, content)],
            )

    def test_archive_rejects_path_traversal_member(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, inventory, archive_path = self._prepare_membership_archive(root)
            member, content = self._make_tar_test_member(
                output.name + "/../escape.txt", tarfile.REGTYPE, b"outside",
            )
            self._assert_archive_rejected_after_rewrite(
                root, output, inventory, archive_path, "traversal-member", additions=[(member, content)],
            )

    def test_archive_rejects_hard_link_at_expected_file_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, inventory, archive_path = self._prepare_membership_archive(root)
            manifest_name = self._archive_raw_name(archive_path, output.name + "/manifest.json")
            member, content = self._make_tar_test_member(
                manifest_name, tarfile.LNKTYPE, linkname=output.name + "/check/summary.json",
            )
            self._assert_archive_rejected_after_rewrite(
                root, output, inventory, archive_path, "hard-link", remove_names=[manifest_name],
                additions=[(member, content)],
            )

    def test_archive_rejects_missing_expected_directory_or_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, inventory, archive_path = self._prepare_membership_archive(root)
            directory_name = self._archive_raw_name(archive_path, output.name + "/check")
            artifact_name = self._archive_raw_name(archive_path, output.name + "/check/summary.json")
            with self.subTest(missing="parent directory"):
                self._assert_archive_rejected_after_rewrite(
                    root, output, inventory, archive_path, "missing-directory", remove_names=[directory_name],
                )
            with self.subTest(missing="artifact"):
                self._assert_archive_rejected_after_rewrite(
                    root, output, inventory, archive_path, "missing-artifact", remove_names=[artifact_name],
                )

    def test_archive_rejects_changed_regular_member_content(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output, inventory, archive_path = self._prepare_membership_archive(root)
            manifest_name = self._archive_raw_name(archive_path, output.name + "/manifest.json")
            member, content = self._make_tar_test_member(manifest_name, tarfile.REGTYPE, b"[]\n")
            self._assert_archive_rejected_after_rewrite(
                root, output, inventory, archive_path, "changed-content", remove_names=[manifest_name],
                additions=[(member, content)],
            )

    def test_archive_verifies_unchanged_relative_symlink_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "evidence"
            inventory, _link = self._prepare_symlink_archive(output, "data.bin")
            archive_path = agent.create_archive(output)
            agent.verify_archive_snapshot(archive_path, output, inventory)

    def test_archive_rejects_changed_relative_symlink_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "evidence"
            inventory, link = self._prepare_symlink_archive(output, "data.bin")
            link.unlink()
            link.symlink_to("other.bin")
            archive_path = agent.create_archive(output)
            with self.assertRaisesRegex(OSError, "link target differs"):
                agent.verify_archive_snapshot(archive_path, output, inventory)

    def _assert_archive_rejects_unverifiable_symlink_target(self, root: Path, target, output_name: str):
        output = root / output_name
        inventory, _link = self._prepare_symlink_archive(output, target)
        link_record = next(item for item in inventory["artifacts"] if item["path"] == "link")
        self.assertIn(link_record["link_target_status"], {"omitted_unsafe", "unavailable"})
        archive_path = agent.create_archive(output)
        with self.assertRaisesRegex(OSError, "cannot be verified exactly"):
            agent.verify_archive_snapshot(archive_path, output, inventory)

    def test_archive_rejects_absolute_symlink_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root / "outside.bin"
            outside.write_bytes(b"outside")
            self._assert_archive_rejects_unverifiable_symlink_target(root, str(outside), "absolute-evidence")

    def test_archive_rejects_escaping_symlink_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "outside.bin").write_bytes(b"outside")
            self._assert_archive_rejects_unverifiable_symlink_target(root, "../outside.bin", "escaping-evidence")

    def test_archive_rejects_symlink_type_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "evidence"
            inventory, _link = self._prepare_symlink_archive(output, "data.bin")
            source_archive = agent.create_archive(output)
            changed_archive = root / "wrong-type.tar.gz"
            link_name = output.name + "/link"
            with tarfile.open(source_archive, "r:gz") as source, tarfile.open(changed_archive, "w:gz") as destination:
                for member in source.getmembers():
                    if member.name == link_name:
                        regular = tarfile.TarInfo(member.name)
                        regular.size = 4
                        destination.addfile(regular, io.BytesIO(b"link"))
                    elif member.isfile():
                        content = source.extractfile(member)
                        destination.addfile(member, content)
                        if content is not None:
                            content.close()
                    else:
                        destination.addfile(member)
            with self.assertRaisesRegex(OSError, "symlink type differs"):
                agent.verify_archive_snapshot(changed_archive, output, inventory)

    def test_archive_link_verification_compares_normalized_target_and_type(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "evidence"
            output.mkdir()
            data = b"data"
            other = b"other"
            inventory_bytes = b"{}\n"
            (output / "data.bin").write_bytes(data)
            (output / "other.bin").write_bytes(other)
            (output / "artifact-inventory.json").write_bytes(inventory_bytes)
            inventory = {
                "artifacts": [
                    {
                        "path": "link", "role": "unclassified", "producer": "runner",
                        "entry_type": "symlink", "size_bytes": None, "sha256": None,
                        "status": "not_followed", "link_target": "data.bin",
                        "link_target_status": "reported",
                    },
                    {
                        "path": "data.bin", "role": "unclassified", "producer": "runner",
                        "entry_type": "regular", "size_bytes": len(data),
                        "sha256": agent.sha256_bytes(data), "status": "complete",
                    },
                    {
                        "path": "other.bin", "role": "unclassified", "producer": "runner",
                        "entry_type": "regular", "size_bytes": len(other),
                        "sha256": agent.sha256_bytes(other), "status": "complete",
                    },
                ],
            }
            link_path = output / "link"
            link_info_values = list((output / "data.bin").lstat())
            link_info_values[0] = stat.S_IFLNK | 0o777
            fake_link_info = os.stat_result(tuple(link_info_values))
            current_target = ["data.bin"]
            relative_reads = []
            original_stat_child = agent.stat_child

            def fake_stat_child(path, parent_fd, name):
                if Path(path) == link_path:
                    return fake_link_info
                return original_stat_child(path, parent_fd, name)

            def fake_read_link(path, parent_fd=None, name=None, expected=None):
                if Path(path) == link_path:
                    relative_reads.append((parent_fd, name))
                    return current_target[0]
                return agent.read_link(path, parent_fd, name, expected)

            def make_archive(path: Path, link_type: bytes, link_target: str) -> None:
                with tarfile.open(path, "w:gz") as archive:
                    evidence_root = tarfile.TarInfo(output.name + "/")
                    evidence_root.type = tarfile.DIRTYPE
                    archive.addfile(evidence_root)
                    link = tarfile.TarInfo(output.name + "/link")
                    if link_type == tarfile.SYMTYPE:
                        link.type = tarfile.SYMTYPE
                        link.linkname = link_target
                        archive.addfile(link)
                    else:
                        link.size = 4
                        archive.addfile(link, io.BytesIO(b"fake"))
                    for filename, content in (
                        ("data.bin", data),
                        ("other.bin", other),
                        ("artifact-inventory.json", inventory_bytes),
                    ):
                        member = tarfile.TarInfo(output.name + "/" + filename)
                        member.size = len(content)
                        archive.addfile(member, io.BytesIO(content))

            with mock.patch.object(agent, "stat_child", side_effect=fake_stat_child), \
                    mock.patch.object(agent, "read_link", side_effect=fake_read_link):
                matching_archive = root / "matching.tar.gz"
                make_archive(matching_archive, tarfile.SYMTYPE, "data.bin")
                agent.verify_archive_snapshot(matching_archive, output, inventory)
                self.assertTrue(relative_reads and relative_reads[-1][0] is not None)
                self.assertEqual(relative_reads[-1][1], "link")

                changed_archive = root / "changed.tar.gz"
                make_archive(changed_archive, tarfile.SYMTYPE, "other.bin")
                with self.assertRaisesRegex(OSError, "link target differs"):
                    agent.verify_archive_snapshot(changed_archive, output, inventory)

                wrong_type_archive = root / "wrong-type.tar.gz"
                make_archive(wrong_type_archive, tarfile.REGTYPE, "data.bin")
                with self.assertRaisesRegex(OSError, "symlink type differs"):
                    agent.verify_archive_snapshot(wrong_type_archive, output, inventory)

    @unittest.skipUnless(os.name != "nt", "directory rename race requires POSIX open-directory semantics")
    def test_archive_snapshot_link_verification_uses_held_parent_handle_and_rejects_directory_swap(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "evidence"
            nested = output / "nested"
            nested.mkdir(parents=True)
            (nested / "data.bin").write_bytes(b"original")
            (nested / "other.bin").write_bytes(b"replacement")
            (output / "manifest.json").write_text("{}\n", encoding="utf-8")
            link = nested / "link"
            try:
                link.symlink_to("data.bin")
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable")
            inventory = artifact_inventory.build_inventory(output)
            agent.write_json(output / "artifact-inventory.json", inventory)
            archive_path = agent.create_archive(output)

            original_read_link = agent.read_link
            observed = []

            def swap_directory_then_read(path, parent_fd=None, name=None, expected=None):
                observed.append((Path(path), parent_fd, name))
                if Path(path) == link and len(observed) == 1:
                    os.rename(nested, output / "nested-held")
                    replacement = output / "nested"
                    replacement.mkdir()
                    (replacement / "data.bin").write_bytes(b"replacement-data")
                    (replacement / "other.bin").write_bytes(b"other")
                    (replacement / "link").symlink_to("other.bin")
                return original_read_link(path, parent_fd, name, expected)

            with mock.patch.object(agent, "read_link", side_effect=swap_directory_then_read):
                with self.assertRaisesRegex(OSError, "link target could not be re-read"):
                    agent.verify_archive_snapshot(archive_path, output, inventory)

            self.assertEqual(len(observed), 1)
            self.assertIsNotNone(observed[0][1], "link read must be relative to a held parent descriptor")
            self.assertEqual(observed[0][2], "link")

    def test_environment_layers_are_applied_in_order(self):
        base = {"KEEP": "base", "REMOVE": "base", "OVERRIDE": "base", "STEP_REMOVE": "base"}
        execution = {
            "unset_environment": ["REMOVE"],
            "environment": {"GLOBAL": "global", "OVERRIDE": "global"},
        }
        step = {
            "unset_environment": ["STEP_REMOVE"],
            "environment": {"STEP": "step", "OVERRIDE": "step"},
        }
        result = agent.prepare_step_environment(base, execution, step)
        self.assertNotIn("REMOVE", result)
        self.assertNotIn("STEP_REMOVE", result)
        self.assertEqual(result["OVERRIDE"], "step")
        self.assertEqual(result["GLOBAL"], "global")
        self.assertEqual(result["STEP"], "step")

    def test_interrupt_marks_remaining_steps_as_not_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[workspace]\nmembers = []\n', encoding="utf-8")
            config = {
                "schema_version": 1,
                "workspace_root": str(workspace),
                "execution": {"continue_on_error": True, "default_timeout_seconds": None,
                              "termination_grace_seconds": 0, "environment": {}, "unset_environment": [],
                              "cargo_executable": "cargo"},
                "steps": [
                    {"id": "first", "args": ["check"], "enabled": True, "parser": "text",
                     "cwd": ".", "timeout_seconds": None, "environment": {},
                     "unset_environment": [], "redact_arg_indexes": []},
                    {"id": "second", "args": ["test"], "enabled": True, "parser": "text",
                     "cwd": ".", "timeout_seconds": None, "environment": {},
                     "unset_environment": [], "redact_arg_indexes": []},
                ],
                "_config_path": str(root / "pipeline.json"),
                "_config_sha256": "test-hash",
            }
            output = root / "evidence"
            output.mkdir()
            runner = agent.Runner(config, workspace, output, False)
            with mock.patch.object(agent, "process_step", side_effect=KeyboardInterrupt):
                runner.execute()
            self.assertTrue(runner.interrupted)
            self.assertEqual([item["status"] for item in runner.steps], ["interrupted", "not_run_interrupted"])

    def test_unverified_process_cleanup_stops_pipeline_even_when_continue_on_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[workspace]\nmembers = []\n', encoding="utf-8")
            config = {
                "schema_version": 1,
                "workspace_root": str(workspace),
                "execution": {
                    "continue_on_error": True,
                    "default_timeout_seconds": None,
                    "termination_grace_seconds": 0,
                    "environment": {},
                    "unset_environment": [],
                    "cargo_executable": "cargo",
                },
                "steps": [
                    {"id": "first", "args": ["check"], "enabled": True, "parser": "text",
                     "cwd": ".", "timeout_seconds": None, "environment": {},
                     "unset_environment": [], "redact_arg_indexes": []},
                    {"id": "second", "args": ["test"], "enabled": True, "parser": "text",
                     "cwd": ".", "timeout_seconds": None, "environment": {},
                     "unset_environment": [], "redact_arg_indexes": []},
                ],
                "_config_path": str(root / "pipeline.json"),
                "_config_sha256": "test-hash",
            }
            output = root / "evidence"
            output.mkdir()
            runner = agent.Runner(config, workspace, output, False)
            failed_cleanup_record = {
                "id": "first", "enabled": True, "status": "process_cleanup_failed",
                "exit_code": 126, "native_exit_code": 0,
                "orphan_processes_detected": True,
                "process_tree": {"cleanup_complete": False, "active_members_after_cleanup": None},
            }
            with mock.patch.object(agent, "process_step", return_value=failed_cleanup_record) as process:
                runner.execute()
            process.assert_called_once()
            self.assertEqual(
                [item["status"] for item in runner.steps],
                ["process_cleanup_failed", "not_run_fail_fast"],
            )
            self.assertIn("cleanup could not be verified", runner.process_cleanup_error)
            self.assertEqual(runner.make_summary()["status"], "error")
            self.assertEqual(runner.make_summary()["process_cleanup_failed_steps"], 1)

    def test_runner_and_launch_errors_always_stop_pipeline(self):
        for failure_kind in ("runner_exception", "launch_error", "supervision_error", "regular_failure"):
            with self.subTest(failure_kind=failure_kind), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                workspace = root / "workspace"
                workspace.mkdir()
                output = root / "evidence"
                output.mkdir()
                steps = [
                    {"id": "first", "enabled": True, "args": ["check"], "parser": "text",
                     "cwd": ".", "timeout_seconds": None, "environment": {},
                     "unset_environment": [], "redact_arg_indexes": []},
                    {"id": "second", "enabled": True, "args": ["test"], "parser": "text",
                     "cwd": ".", "timeout_seconds": None, "environment": {},
                     "unset_environment": [], "redact_arg_indexes": []},
                ]
                config = {
                    "schema_version": 1, "workspace_root": str(workspace),
                    "execution": {"cargo_executable": "cargo", "continue_on_error": True,
                                  "default_timeout_seconds": None, "termination_grace_seconds": 1,
                                  "environment": {}, "unset_environment": []},
                    "steps": steps, "_config_path": str(root / "pipeline.json"),
                    "_config_sha256": "test-hash",
                }
                runner = agent.Runner(config, workspace, output, False)
                if failure_kind == "runner_exception":
                    process_step = mock.patch.object(agent, "process_step", side_effect=RuntimeError("supervisor init failed"))
                elif failure_kind == "launch_error":
                    process_step = mock.patch.object(agent, "process_step", return_value={
                        "id": "first", "enabled": True, "status": "launch_error",
                        "exit_code": 127, "spawn_error": "CreateProcessW failed",
                        "process_startup": {"stage": "create_process", "process_created": False},
                    })
                elif failure_kind == "supervision_error":
                    process_step = mock.patch.object(agent, "process_step", return_value={
                        "id": "first", "enabled": True, "status": "supervision_error",
                        "exit_code": 126, "supervision_error": "AssignProcessToJobObject failed",
                        "process_tree": {"cleanup_complete": True, "cleanup_verified": True},
                    })
                else:
                    process_step = mock.patch.object(agent, "process_step", side_effect=[
                        {"id": "first", "enabled": True, "status": "failed", "exit_code": 1,
                         "native_exit_code": 1, "process_tree": {"cleanup_complete": True}},
                        {"id": "second", "enabled": True, "status": "passed", "exit_code": 0,
                         "native_exit_code": 0, "process_tree": {"cleanup_complete": True}},
                    ])
                with process_step as mocked:
                    runner.execute()
                if failure_kind == "regular_failure":
                    self.assertEqual(mocked.call_count, 2)
                    self.assertEqual([record["status"] for record in runner.steps], ["failed", "passed"])
                    self.assertIsNone(runner.runner_error)
                else:
                    mocked.assert_called_once()
                    self.assertEqual(
                        [record["status"] for record in runner.steps],
                        ["runner_error", "not_run_fail_fast"] if failure_kind == "runner_exception"
                        else [failure_kind, "not_run_fail_fast"],
                    )
                    if failure_kind == "launch_error":
                        self.assertIn("Could not start", runner.launch_error)
                    elif failure_kind == "supervision_error":
                        self.assertIn("cleanup was verified", runner.supervision_error)
                        summary = runner.make_summary()
                        self.assertEqual(summary["supervision_error_steps"], 1)
                        self.assertEqual(summary["status"], "error")
                    else:
                        self.assertTrue(runner.runner_error)

    def test_message_format_after_separator_does_not_enable_json_parser(self):
        with tempfile.TemporaryDirectory() as temp:
            config_path = Path(temp) / "pipeline.json"
            config = {
                "schema_version": 1,
                "workspace_root": ".",
                "execution": {},
                "steps": [{
                    "id": "check", "args": ["check", "--", "--message-format=json"],
                    "parser": "cargo-json",
                }],
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            loaded, _raw, _digest = agent.load_config(config_path)
            analysis = provenance.analyze_cargo_invocation(
                loaded["steps"][0]["args"], Path(temp), {"CARGO_HOME": str(Path(temp) / "cargo-home")},
                {"parsed": {"release": "1.91.1", "channel": "stable"}},
                agent.BUILD_PRODUCING_SUBCOMMANDS,
            )
            with self.assertRaises(agent.ConfigError):
                agent.validate_invocation_policy(loaded["steps"][0], analysis)

    def test_fmt_diff_marks_step_diagnostic(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stdout = root / "stdout.log"
            stderr = root / "stderr.log"
            stdout.write_text("Diff in src/lib.rs:10:\n", encoding="utf-8")
            stderr.write_text("", encoding="utf-8")
            records = agent.parse_fmt_output(stdout, stderr, "fmt", 1)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["code"], "rustfmt::formatting-diff")

    def test_zero_exit_with_orphan_descendants_is_not_passed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[package]\nname="x"\nversion="0.1.0"\n', encoding="utf-8")
            output = root / "evidence"
            output.mkdir()
            step = {
                "id": "run", "args": ["run"], "parser": "text", "cwd": ".",
                "timeout_seconds": None, "environment": {}, "unset_environment": [],
                "redact_arg_indexes": [],
            }
            execution = {
                "default_timeout_seconds": 10, "termination_grace_seconds": 1,
                "environment": {}, "unset_environment": [],
            }
            result = {
                "exit_code": 0, "native_exit_code": 0, "interrupted": False, "timed_out": False,
                "duration_ms": 20, "spawn_error": None, "supervision_error": None,
                "orphan_processes_detected": True,
                "process_tree": {
                    "supervision": "posix-session-process-groups", "trigger": "orphaned-descendants",
                    "descendants_detected": True, "term_signal_sent": True, "kill_signal_sent": True,
                    "cleanup_complete": True, "active_members_after_cleanup": 0,
                    "process_groups_signalled": [1234], "errors": [],
                },
            }
            def fake_run(*args, **kwargs):
                args[3].write_bytes(b"")
                args[4].write_bytes(b"")
                return result
            with mock.patch.object(agent, "run_process", side_effect=fake_run):
                record = agent.process_step("cargo", step, workspace, output, {}, execution)
            self.assertEqual(record["exit_code"], 0)
            self.assertEqual(record["status"], "failed")
            self.assertTrue(record["orphan_processes_detected"])

    def test_verified_vctip_ancillary_cleanup_does_not_fail_successful_step(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text(
                '[package]\nname="x"\nversion="0.1.0"\n', encoding="utf-8",
            )
            output = root / "evidence"
            output.mkdir()
            step = {
                "id": "run", "args": ["run"], "parser": "text", "cwd": ".",
                "timeout_seconds": None, "environment": {}, "unset_environment": [],
                "redact_arg_indexes": [],
            }
            execution = {
                "default_timeout_seconds": 10, "termination_grace_seconds": 3,
                "environment": {}, "unset_environment": [],
            }
            result = {
                "exit_code": 0, "native_exit_code": 0, "interrupted": False, "timed_out": False,
                "duration_ms": 20, "spawn_error": None, "supervision_error": None,
                "orphan_processes_detected": False,
                "process_tree": {
                    "supervision": "windows-job-object",
                    "trigger": "expected-ancillary-process",
                    "descendants_detected": True,
                    "unexpected_descendants_detected": False,
                    "expected_ancillary_processes_detected": True,
                    "expected_ancillary_processes": [{
                        "pid": 1234, "name": "vctip.exe",
                        "image_path": (
                            r"C:\Program Files\Microsoft Visual Studio\18\Enterprise"
                            r"\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\vctip.exe"
                        ),
                    }],
                    "cleanup_complete": True, "cleanup_verified": True,
                    "active_members_after_cleanup": 0, "job_empty": True,
                },
            }

            def fake_run(*args, **kwargs):
                args[3].write_bytes(b"")
                args[4].write_bytes(b"")
                return result

            with mock.patch.object(agent, "run_process", side_effect=fake_run):
                record = agent.process_step("cargo", step, workspace, output, {}, execution)

            self.assertEqual(record["status"], "passed")
            self.assertTrue(record["process_tree"]["descendants_detected"])
            self.assertFalse(record["orphan_processes_detected"])
            self.assertTrue(record["process_tree"]["cleanup_complete"])
            self.assertTrue(record["process_tree"]["job_empty"])

    def test_unverified_tree_cleanup_is_never_reported_as_passed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[package]\nname="x"\nversion="0.1.0"\n', encoding="utf-8")
            output = root / "evidence"
            output.mkdir()
            config = {
                "execution": {"cargo_executable": "cargo", "default_timeout_seconds": 10,
                              "termination_grace_seconds": 1, "environment": {},
                              "unset_environment": []},
            }
            step = {
                "id": "check", "args": ["check"], "parser": "text", "cwd": ".",
                "timeout_seconds": None, "environment": {}, "unset_environment": [],
                "redact_arg_indexes": [],
            }
            expected = {
                "exit_code": 0, "native_exit_code": 0, "interrupted": False, "timed_out": False,
                "duration_ms": 10, "spawn_error": None, "supervision_error": "verification failed",
                "orphan_processes_detected": False,
                "process_tree": {"cleanup_complete": False, "errors": ["could not verify"]},
            }
            def fake_run(*args, **kwargs):
                args[3].write_bytes(b"")
                args[4].write_bytes(b"")
                return expected
            with mock.patch.object(agent, "run_process", side_effect=fake_run):
                record = agent.process_step("cargo", step, workspace, output, {}, config["execution"])
            self.assertEqual(record["status"], "process_cleanup_failed")
            self.assertNotEqual(record["status"], "passed")

    def test_process_capture_and_timeout(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            out, err = root / "out.bin", root / "err.bin"
            ok = agent.run_process(
                [sys.executable, "-c", "import sys; sys.stdout.write('hello\\n'); sys.stderr.write('problem\\n')"],
                root, os.environ.copy(), out, err, 5, 0.1,
            )
            self.assertEqual(ok["exit_code"], 0)
            self.assertIn(b"hello", out.read_bytes())
            self.assertIn(b"problem", err.read_bytes())

            timed_out = agent.run_process(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                root, os.environ.copy(), root / "out2.bin", root / "err2.bin", 0.1, 0.1,
            )
            self.assertTrue(timed_out["timed_out"])
            self.assertEqual(timed_out["exit_code"], 124)

    def test_supervisor_cancellation_before_launch_and_during_process_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            marker = root / "must-not-spawn"
            pre_cancelled = supervision.CancellationContext()
            pre_cancelled.request(signal.SIGTERM)
            before = supervision.run_supervised_process(
                [sys.executable, "-c", "open({!r}, 'w').write('spawned')".format(str(marker))],
                root, os.environ.copy(), root / "before.out", root / "before.err", 5, 0.2,
                cancellation=pre_cancelled,
            )
            self.assertFalse(marker.exists())
            self.assertTrue(before["interrupted"])
            self.assertEqual(before["signal_number"], signal.SIGTERM)
            self.assertEqual(before["exit_code"], 128 + signal.SIGTERM)
            self.assertEqual(before["startup"]["stage"], "cancelled_before_launch")

            ready = root / "ready"
            pids_path = root / "pids.json"
            script = (
                "import json, os, pathlib, subprocess, sys, time\n"
                "grandchild = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                "pathlib.Path(sys.argv[1]).write_text('ready')\n"
                "pathlib.Path(sys.argv[2]).write_text(json.dumps([os.getpid(), grandchild.pid]))\n"
                "time.sleep(60)\n"
            )
            cancellation = supervision.CancellationContext()
            signal_number = signal.SIGTERM
            observed = threading.Event()

            def request_when_ready():
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    if ready.exists() and pids_path.exists():
                        cancellation.request(signal_number)
                        observed.set()
                        return
                    time.sleep(0.01)

            waiter = threading.Thread(target=request_when_ready)
            waiter.start()
            if os.name == "nt":
                original_cleanup = supervision._WindowsJob.terminate_tree

                def second_request_during_cleanup(job, process, grace, reason):
                    if hasattr(signal, "SIGHUP"):
                        cancellation.request(signal.SIGHUP)
                    return original_cleanup(job, process, grace, reason)

                patcher = mock.patch.object(
                    supervision._WindowsJob, "terminate_tree", new=second_request_during_cleanup,
                )
            else:
                original_cleanup = supervision._posix_cleanup

                def second_request_during_cleanup(*args):
                    if hasattr(signal, "SIGHUP"):
                        cancellation.request(signal.SIGHUP)
                    return original_cleanup(*args)

                patcher = mock.patch.object(
                    supervision, "_posix_cleanup", side_effect=second_request_during_cleanup,
                )
            with patcher:
                result = supervision.run_supervised_process(
                    [sys.executable, "-c", script, str(ready), str(pids_path)],
                    root, os.environ.copy(), root / "tree.out", root / "tree.err", 10, 0.2,
                    cancellation=cancellation,
                )
            waiter.join(timeout=2)
            self.assertTrue(observed.is_set(), "readiness synchronization did not request cancellation")
            self.assertFalse(waiter.is_alive())
            self.assertTrue(result["interrupted"])
            self.assertEqual(result["signal_number"], signal_number, "a repeated signal replaced the first reason")
            self.assertEqual(result["exit_code"], 128 + signal_number)
            self.assertTrue(result["process_tree"]["cleanup_complete"], result["process_tree"])
            pids = json.loads(pids_path.read_text(encoding="utf-8"))
            for pid in pids:
                self.assertFalse(_pid_is_running(pid), "cancelled process {} survived cleanup".format(pid))

    def test_probe_bounded_capture_drains_both_streams_and_removes_temporary_files(self):
        stdout_payload = b"A" * 250000
        stderr_payload = b"B" * 275000
        script = (
            "import sys; "
            "sys.stdout.buffer.write(b'A' * 250000); sys.stdout.flush(); "
            "sys.stderr.buffer.write(b'B' * 275000); sys.stderr.flush()"
        )
        capture_directories = []
        real_supervisor = provenance.run_supervised_process

        def capture_temp_paths(*args, **kwargs):
            capture_directories.append(args[3].parent)
            return real_supervisor(*args, **kwargs)

        with tempfile.TemporaryDirectory() as temp:
            evidence = Path(temp) / "evidence"
            evidence.mkdir()
            (evidence / "summary.json").write_text("{}\n", encoding="utf-8")
            with mock.patch.object(provenance, "run_supervised_process", side_effect=capture_temp_paths):
                result = provenance.run_probe(
                    "large_probe", [sys.executable, "-c", script], Path.cwd(), os.environ.copy(),
                )
            archive_path = agent.create_archive(evidence)
            with tarfile.open(archive_path, "r:gz") as archive:
                members = archive.getnames()
            self.assertFalse(any("stdout.capture" in name or "stderr.capture" in name for name in members))
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["stdout_bytes"], len(stdout_payload))
        self.assertEqual(result["stderr_bytes"], len(stderr_payload))
        self.assertEqual(result["stdout_sha256"], provenance.sha256_bytes(stdout_payload))
        self.assertEqual(result["stderr_sha256"], provenance.sha256_bytes(stderr_payload))
        self.assertTrue(result["stdout_truncated"])
        self.assertTrue(result["stderr_truncated"])
        self.assertEqual(len(result["stdout_excerpt"].encode("utf-8")), provenance.PROBE_OUTPUT_LIMIT)
        self.assertFalse(capture_directories[0].exists(), "probe raw output directory was not removed")

    def test_capture_writer_failure_is_explicit_and_keeps_memory_bounded(self):
        payload = b"X" * (2 * 1024 * 1024)
        metrics = {}

        class BrokenDestination:
            def write(self, _chunk):
                raise OSError("injected disk write failure")

        supervision._capture_stream(
            io.BytesIO(payload), BrokenDestination(), 8192, metrics,
        )
        self.assertEqual(metrics["bytes"], len(payload))
        self.assertEqual(metrics["sha256"], provenance.sha256_bytes(payload))
        self.assertEqual(metrics["retained_bytes"], 0)
        self.assertEqual(len(metrics["errors"]), 1)
        self.assertIn("capture write failed", metrics["errors"][0])

    def test_probe_temp_capture_is_removed_after_timeout_cancellation_and_supervisor_error(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ready = root / "probe-ready"
            pid_path = root / "probe-pid"
            command = [
                sys.executable, "-c",
                "import os,pathlib,sys,time; pathlib.Path(sys.argv[1]).write_text('ready'); "
                "pathlib.Path(sys.argv[2]).write_text(str(os.getpid())); time.sleep(30)",
                str(ready), str(pid_path),
            ]
            directories = []
            real_supervisor = provenance.run_supervised_process

            def record_directory(*args, **kwargs):
                directories.append(args[3].parent)
                return real_supervisor(*args, **kwargs)

            with mock.patch.object(provenance, "PROBE_TIMEOUT_SECONDS", 1.5), \
                    mock.patch.object(provenance, "run_supervised_process", side_effect=record_directory):
                result = provenance.run_probe(
                    "timeout_probe", command, root, os.environ.copy(), termination_grace_seconds=0.2,
                )
            self.assertEqual(result["status"], "timed_out")
            self.assertTrue(ready.exists())
            self.assertFalse(_pid_is_running(int(pid_path.read_text(encoding="utf-8"))))
            self.assertFalse(directories[-1].exists())

            cancelled = supervision.CancellationContext()
            cancelled.request(signal.SIGTERM)
            marker = root / "not-launched"
            directories_before_cancel = len(directories)
            with mock.patch.object(provenance, "run_supervised_process", side_effect=record_directory):
                interrupted = provenance.run_probe(
                    "cancelled_probe", [sys.executable, "-c", "open({!r}, 'w').write('x')".format(str(marker))],
                    root, os.environ.copy(), cancellation=cancelled,
                )
            self.assertEqual(interrupted["status"], "interrupted")
            self.assertEqual(interrupted["signal_number"], signal.SIGTERM)
            self.assertFalse(marker.exists())
            self.assertEqual(len(directories), directories_before_cancel, "cancelled probe created a capture directory")

            def fail_supervisor(*args, **kwargs):
                directories.append(args[3].parent)
                raise RuntimeError("capture failed")

            with mock.patch.object(provenance, "run_supervised_process", side_effect=fail_supervisor):
                failed = provenance.run_probe("broken_probe", ["cargo", "-Vv"], root, os.environ.copy())
            self.assertEqual(failed["status"], "unavailable")
            self.assertEqual(failed["error_type"], "RuntimeError")
            self.assertFalse(directories[-1].exists())

            def fail_capture(*args, **_kwargs):
                directories.append(args[3].parent)
                args[3].write_bytes(b"")
                args[4].write_bytes(b"")
                empty_hash = provenance.sha256_bytes(b"")
                stream = {
                    "bytes": 0, "sha256": empty_hash, "truncated": False,
                    "retained_bytes": 0, "errors": [],
                }
                stdout_metrics = dict(stream, errors=["capture read failed: OSError"])
                return {
                    "exit_code": 0, "native_exit_code": 0, "interrupted": False,
                    "timed_out": False, "duration_ms": 1, "supervision_error": "capture failed",
                    "process_tree": {"cleanup_complete": True},
                    "capture": {"stdout": stdout_metrics, "stderr": stream},
                }

            with mock.patch.object(provenance, "run_supervised_process", side_effect=fail_capture):
                capture_failed = provenance.run_probe(
                    "reader_failure", ["cargo", "-Vv"], root, os.environ.copy(), include_raw_stdout=True,
                )
            self.assertEqual(capture_failed["status"], "failed")
            self.assertEqual(capture_failed["capture_status"], "failed")
            self.assertNotIn("_raw_stdout", capture_failed)
            self.assertFalse(directories[-1].exists())

    def test_metadata_capture_limit_rejects_truncated_json_without_parsing_prefix(self):
        raw = json.dumps({
            "workspace_root": str(Path.cwd()), "target_directory": str(Path.cwd() / "target"),
            "packages": [], "padding": "x" * 9000,
        }).encode("utf-8")
        for capture_truncated, expected_status in (
            (False, "succeeded"), (True, "capture_limit_exceeded"),
        ):
            probe_result = {
                "name": "cargo_metadata", "status": "succeeded", "exit_code": 0,
                "stdout_truncated": True, "stdout_capture_truncated": capture_truncated,
                "_raw_stdout": raw,
            }
            with self.subTest(capture_truncated=capture_truncated), mock.patch.object(
                provenance, "run_probe", return_value=probe_result,
            ):
                probe, metadata = provenance._cargo_metadata(["cargo", "metadata"], Path.cwd(), {})
            self.assertEqual(probe["extraction_status"], expected_status)
            self.assertEqual(metadata is not None, not capture_truncated)
            self.assertNotIn("_raw_stdout", probe)

    def test_cargo_metadata_duplicate_keys_reject_the_complete_response(self):
        documents = (
            '{"workspace_root":"secret-root","workspace_root":"other-root",'
            '"target_directory":"secret-target","packages":[]}',
            '{"workspace_root":"secret-root","target_directory":"secret-target",'
            '"target_directory":"other-target","packages":[]}',
            '{"workspace_root":"secret-root","target_directory":"secret-target",'
            '"packages":[],"packages":[]}',
            '{"workspace_root":"secret-root","target_directory":"secret-target",'
            '"packages":[{"name":"secret-package","name":"other-package",'
            '"manifest_path":"secret-manifest"}]}',
        )
        for raw in documents:
            with self.subTest(raw=raw), mock.patch.object(
                provenance,
                "run_probe",
                return_value={
                    "name": "cargo_metadata", "status": "succeeded", "exit_code": 0,
                    "stdout_capture_truncated": False, "_raw_stdout": raw.encode("utf-8"),
                },
            ):
                probe, metadata = provenance._cargo_metadata(["cargo", "metadata"], Path.cwd(), {})
            self.assertIsNone(metadata)
            self.assertEqual(probe["extraction_status"], "duplicate_json_key")
            self.assertNotIn("_raw_stdout", probe)
            self.assertNotIn("secret", json.dumps(probe))

            minimal_step = {
                "cargo_configuration": {"effective_settings": {}, "files": [], "include_issues": []},
                "cargo": {"version_probe": {"status": "succeeded"}},
                "rustc": {"version_probe": {"status": "succeeded"}},
                "cargo_metadata_probe": probe,
                "cargo_metadata": metadata,
                "output": {},
                "manifest": {"selected_manifest_path": "Cargo.toml"},
                "target": {"selected_build_target": {"status": "resolved"}},
            }
            minimal_provenance = {
                "agent": {"runtime_source_files": []}, "issues": [], "steps": {"check": minimal_step},
            }
            status, issues = provenance.complete_provenance_status(minimal_provenance)
            self.assertEqual(status, "incomplete")
            self.assertIn("cargo_metadata_extraction_unavailable", [item["code"] for item in issues])

        valid = b'{"workspace_root":"/workspace","target_directory":"/workspace/target",' \
            b'"packages":[{"name":"pkg","manifest_path":"/workspace/Cargo.toml"}]}'
        with mock.patch.object(provenance, "run_probe", return_value={
            "name": "cargo_metadata", "status": "succeeded", "exit_code": 0,
            "stdout_capture_truncated": False, "_raw_stdout": valid,
        }):
            probe, metadata = provenance._cargo_metadata(["cargo", "metadata"], Path.cwd(), {})
        self.assertEqual(probe["extraction_status"], "succeeded")
        self.assertEqual(metadata, {
            "workspace_root": "/workspace", "target_directory": "/workspace/target",
            "build_directory": None,
            "package_manifest_paths": [{"name": "pkg", "manifest_path": "/workspace/Cargo.toml"}],
        })

    def test_duplicate_inventory_readback_fails_before_archive_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runner, output = self.make_finalization_runner(root)
            inventory_path = output / "artifact-inventory.json"
            inventory_path.write_text(
                '{"schema_version":1,"artifacts":[],"artifacts":[]}', encoding="utf-8",
            )
            with mock.patch.object(runner, "_write_artifact_inventory", return_value=None):
                runner.finalize()
            self.assertIsNotNone(runner.archive_error)
            self.assertIn("DuplicateJSONKeyError", runner.archive_error)
            self.assertFalse(runner.archive_path.exists())
            self.assertFalse(runner.archive_sidecar_path.exists())
            self.assertFalse(runner._finalization_state["complete"])

    def test_duplicate_sidecar_readback_fails_closed_and_removes_owned_success_pair(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runner, _output = self.make_finalization_runner(root)
            runner.finalize()
            self.assertTrue(runner._finalization_state["complete"])
            sidecar = runner.archive_sidecar_path
            sidecar.write_text(
                '{"schema_version":1,"schema_version":1,"status":"created"}',
                encoding="utf-8",
            )
            runner._finalization_state["complete"] = False
            runner.finalize()
            self.assertIsNotNone(runner.archive_error)
            self.assertIn("DuplicateJSONKeyError", runner.archive_error)
            self.assertFalse(sidecar.exists())
            self.assertFalse(runner.archive_path.exists())
            self.assertFalse(runner._finalization_state["complete"])

    def test_cancellation_between_steps_and_before_first_step_prevents_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[workspace]\nmembers = []\n', encoding="utf-8")
            steps = [{
                "id": name, "enabled": True, "args": [name], "parser": "text", "cwd": ".",
                "timeout_seconds": None, "environment": {}, "unset_environment": [],
                "redact_arg_indexes": [],
            } for name in ("first", "second")]
            config = {
                "schema_version": 1, "workspace_root": str(workspace),
                "execution": {
                    "cargo_executable": "cargo", "continue_on_error": True,
                    "default_timeout_seconds": None, "termination_grace_seconds": 1,
                    "environment": {}, "unset_environment": [],
                },
                "steps": steps, "_config_path": str(root / "pipeline.json"),
                "_config_sha256": "test-hash",
            }
            context = supervision.CancellationContext()
            output = root / "evidence"
            output.mkdir()
            runner = agent.Runner(config, workspace, output, False, context)
            provenance_record = {
                "status": "incomplete", "output": {}, "manifest": {}, "cargo_metadata": {},
            }
            process_calls = []

            def complete_first(_cargo, step, *_args, **_kwargs):
                process_calls.append(step["id"])
                context.request(signal.SIGTERM)
                return {
                    "id": step["id"], "enabled": True, "status": "passed", "exit_code": 0,
                    "duration_ms": 1, "timed_out": False, "interrupted": False,
                    "process_tree": {"cleanup_complete": True},
                }

            with mock.patch.object(agent, "collect_step_provenance", return_value=(provenance_record, None, [])), \
                    mock.patch.object(agent, "process_step", side_effect=complete_first):
                runner.execute()
            self.assertEqual(process_calls, ["first"])
            self.assertEqual([step["status"] for step in runner.steps], ["passed", "not_run_interrupted"])
            self.assertTrue(runner.interrupted)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[workspace]\nmembers = []\n', encoding="utf-8")
            config = {
                "schema_version": 1, "workspace_root": str(workspace),
                "execution": {
                    "cargo_executable": "cargo", "continue_on_error": True,
                    "default_timeout_seconds": None, "termination_grace_seconds": 1,
                    "environment": {}, "unset_environment": [],
                },
                "steps": steps, "_config_path": str(root / "pipeline.json"),
                "_config_sha256": "test-hash",
            }
            context = supervision.CancellationContext()
            context.request(signal.SIGTERM)
            output = root / "evidence"
            output.mkdir()
            runner = agent.Runner(config, workspace, output, False, context)
            with mock.patch.object(agent, "process_step") as process_step:
                runner.execute()
            process_step.assert_not_called()
            self.assertEqual([step["status"] for step in runner.steps], ["not_run_interrupted", "not_run_interrupted"])

    def test_signal_during_finalization_keeps_completed_steps_and_finishes_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[workspace]\nmembers = []\n', encoding="utf-8")
            config_path = root / "pipeline.json"
            config_path.write_text(json.dumps({
                "schema_version": 1,
                "workspace_root": str(workspace),
                "execution": {"cargo_executable": "cargo", "continue_on_error": True},
                "steps": [{"id": "check", "args": ["check"], "parser": "text"}],
            }), encoding="utf-8")
            output = root / "evidence"
            real_finalize = agent.Runner.finalize

            def completed_step(runner):
                runner.steps.append({
                    "id": "check", "enabled": True, "status": "passed", "exit_code": 0,
                    "duration_ms": 1, "timed_out": False, "interrupted": False,
                    "process_tree": {"cleanup_complete": True},
                })

            def signal_then_finalize(runner):
                signal.raise_signal(signal.SIGTERM)
                return real_finalize(runner)

            with mock.patch.object(agent.Runner, "execute", completed_step), \
                    mock.patch.object(agent.Runner, "finalize", signal_then_finalize):
                exit_code = agent.main([
                    "--config", str(config_path), "--output-dir", str(output), "--archive",
                ])

            self.assertEqual(exit_code, 128 + signal.SIGTERM)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["steps"][0]["status"], "passed")
            self.assertEqual(summary["status"], "passed")
            archive_path = Path(manifest["archive"]["path"])
            sidecar_path = Path(manifest["archive"]["integrity_sidecar_path"])
            inventory = json.loads((output / "artifact-inventory.json").read_text(encoding="utf-8"))
            agent.verify_archive_snapshot(archive_path, output, inventory)
            self.assertEqual(json.loads(sidecar_path.read_text(encoding="utf-8"))["status"], "created")

    @unittest.skipIf(os.name == "nt", "POSIX signal delivery is required; Windows SIGTERM cannot be caught")
    def test_agent_signal_integration_stops_steps_and_probes_and_finalizes_archive(self):
        script_body = (
            "import json, os, pathlib, subprocess, sys, time\n"
            "args = sys.argv[1:]\n"
            "def block_with_child(label):\n"
            "    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "    pathlib.Path(os.environ['FAKE_PIDS']).write_text(json.dumps([os.getpid(), child.pid]))\n"
            "    pathlib.Path(os.environ['FAKE_READY']).write_text(label)\n"
            "    sys.stdout.buffer.write(b'A' * 20000); sys.stdout.flush()\n"
            "    time.sleep(60)\n"
            "if '-Vv' in args:\n"
            "    if os.environ.get('FAKE_MODE') == 'probe': block_with_child('probe')\n"
            "    sys.stdout.write('release: 1.80.0\\nhost: x86_64-test\\n')\n"
            "elif 'metadata' in args:\n"
            "    print(json.dumps({'workspace_root': os.getcwd(), 'target_directory': os.path.join(os.getcwd(), 'target'), 'packages': []}))\n"
            "elif args and args[0] == 'check' and os.environ.get('FAKE_MODE') == 'step':\n"
            "    block_with_child('step')\n"
            "elif args and args[0] == 'test':\n"
            "    pathlib.Path(os.environ['FAKE_SECOND']).write_text('started')\n"
            "    print('second step ran')\n"
            "else:\n"
            "    print('fake cargo completed')\n"
        )

        def run_case(base, mode, stop_signal):
            workspace = base / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[workspace]\nmembers = []\n', encoding="utf-8")
            fake_cargo = base / "fake-cargo"
            fake_cargo.write_text("#!{}\n".format(sys.executable) + script_body, encoding="utf-8")
            fake_cargo.chmod(0o755)
            ready = base / "ready"
            pids_path = base / "pids.json"
            second = base / "second-started"
            probe_temp = base / "probe-temp"
            probe_temp.mkdir()
            config_path = base / "pipeline.json"
            output = base / "evidence"
            config = {
                "schema_version": 1, "workspace_root": str(workspace),
                "execution": {
                    "cargo_executable": str(fake_cargo), "continue_on_error": True,
                    "default_timeout_seconds": 45, "termination_grace_seconds": 1,
                    "environment": {
                        "FAKE_MODE": mode, "FAKE_READY": str(ready), "FAKE_PIDS": str(pids_path),
                        "FAKE_SECOND": str(second),
                    },
                    "unset_environment": [],
                },
                "steps": [
                    {"id": "check", "args": ["check"], "parser": "text"},
                    {"id": "second", "args": ["test"], "parser": "text"},
                ],
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            child_env = os.environ.copy()
            child_env["TMPDIR"] = str(probe_temp)
            agent_process = subprocess.Popen(
                [sys.executable, str(SCRIPT), "--config", str(config_path), "--output-dir", str(output), "--archive"],
                cwd=str(workspace), env=child_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline and agent_process.poll() is None:
                    if ready.is_file() and pids_path.is_file():
                        break
                    time.sleep(0.02)
                self.assertTrue(ready.is_file(), "agent never reached deterministic readiness point")
                pids = json.loads(pids_path.read_text(encoding="utf-8"))
                os.kill(agent_process.pid, stop_signal)
                return_code = agent_process.wait(timeout=30)
                _stdout, stderr = agent_process.communicate(timeout=5)
                self.assertEqual(return_code, 128 + stop_signal, stderr.decode("utf-8", errors="replace"))
                self.assertFalse(second.exists(), "a later Cargo step started after cancellation")
                for pid in pids:
                    self.assertFalse(_pid_is_running(pid), "agent-owned process {} survived signal cleanup".format(pid))
                manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
                summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
                self.assertNotEqual(summary["status"], "passed")
                if mode == "step":
                    self.assertEqual([step["status"] for step in manifest["steps"]], [
                        "interrupted", "not_run_interrupted",
                    ])
                    self.assertEqual(manifest["steps"][0]["signal_number"], stop_signal)
                else:
                    probe = manifest["provenance"]["steps"]["check"]["cargo"]["version_probe"]
                    self.assertEqual(probe["status"], "interrupted")
                    self.assertEqual(probe["signal_number"], stop_signal)
                    self.assertEqual([step["status"] for step in manifest["steps"]], [
                        "not_run_interrupted", "not_run_interrupted",
                    ])
                self.assertFalse(list(probe_temp.glob("cargo-evidence-probe-*")))
                all_evidence = b"".join(
                    path.read_bytes() for path in output.rglob("*") if path.is_file()
                )
                self.assertNotIn(b"stdout.capture", all_evidence)
                archive_path = Path(manifest["archive"]["path"])
                sidecar_path = Path(manifest["archive"]["integrity_sidecar_path"])
                inventory = json.loads((output / "artifact-inventory.json").read_text(encoding="utf-8"))
                agent.verify_archive_snapshot(archive_path, output, inventory)
                sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
                self.assertEqual(sidecar["status"], "created")
                with tarfile.open(archive_path, "r:gz") as archive:
                    members = archive.getnames()
                self.assertFalse(any("stdout.capture" in member or "stderr.capture" in member for member in members))
            finally:
                if agent_process.poll() is None:
                    agent_process.send_signal(getattr(signal, "SIGTERM", signal.SIGINT))
                    try:
                        agent_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        agent_process.kill()
                        agent_process.wait(timeout=5)

        for stop_signal in (signal.SIGTERM, signal.SIGINT) + ((signal.SIGHUP,) if hasattr(signal, "SIGHUP") else ()):
            with self.subTest(mode="step", signal=stop_signal), tempfile.TemporaryDirectory() as temp:
                run_case(Path(temp), "step", stop_signal)
        with tempfile.TemporaryDirectory() as temp:
            run_case(Path(temp), "probe", signal.SIGTERM)

    @unittest.skipIf(os.name == "nt", "POSIX signal delivery is required; Windows SIGTERM cannot be caught")
    def test_agent_signal_during_cargo_version_preflight_finalizes_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            workspace = base / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text("[workspace]\nmembers = []\n", encoding="utf-8")
            fake_cargo = base / "fake-cargo"
            invocations = base / "invocations.jsonl"
            ready = base / "ready"
            pids_path = base / "pids.json"
            probe_temp = base / "probe-temp"
            probe_temp.mkdir()
            script_body = (
                "import json, os, pathlib, subprocess, sys, time\n"
                "args = sys.argv[1:]\n"
                "with open(os.environ['FAKE_INVOCATIONS'], 'a', encoding='utf-8') as stream:\n"
                "    stream.write(json.dumps(args) + '\\n')\n"
                "if '-Vv' in args:\n"
                "    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
                "    pathlib.Path(os.environ['FAKE_PIDS']).write_text(json.dumps([os.getpid(), child.pid]))\n"
                "    pathlib.Path(os.environ['FAKE_READY']).write_text('cargo-version-probe-active')\n"
                "    sys.stdout.buffer.write(b'P' * 20000); sys.stdout.flush()\n"
                "    time.sleep(60)\n"
                "elif 'metadata' in args:\n"
                "    print(json.dumps({'workspace_root': os.getcwd(), 'target_directory': os.path.join(os.getcwd(), 'target'), 'packages': []}))\n"
                "else:\n"
                "    print('configured step ran')\n"
            )
            fake_cargo.write_text("#!{}\n".format(sys.executable) + script_body, encoding="utf-8")
            fake_cargo.chmod(0o755)
            config_path = base / "pipeline.json"
            output = base / "evidence"
            cargo_home = base / "cargo-home"
            cargo_home.mkdir()
            config_path.write_text(json.dumps({
                "schema_version": 1, "workspace_root": str(workspace),
                "execution": {
                    "cargo_executable": str(fake_cargo), "continue_on_error": True,
                    "default_timeout_seconds": 45, "termination_grace_seconds": 1,
                    "environment": {
                        "CARGO_HOME": str(cargo_home), "FAKE_INVOCATIONS": str(invocations),
                        "FAKE_READY": str(ready), "FAKE_PIDS": str(pids_path),
                    },
                    "unset_environment": [],
                },
                "steps": [
                    {"id": "check", "args": ["check"], "parser": "text"},
                    {"id": "later", "args": ["test"], "parser": "text"},
                ],
            }), encoding="utf-8")
            child_env = os.environ.copy()
            child_env["TMPDIR"] = str(probe_temp)
            process = subprocess.Popen(
                [sys.executable, str(SCRIPT), "--config", str(config_path), "--output-dir", str(output), "--archive"],
                cwd=str(workspace), env=child_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline and process.poll() is None:
                    if ready.is_file() and pids_path.is_file():
                        break
                    time.sleep(0.02)
                self.assertTrue(ready.is_file(), "Cargo version probe never reached readiness")
                pids = json.loads(pids_path.read_text(encoding="utf-8"))
                os.kill(process.pid, signal.SIGTERM)
                return_code = process.wait(timeout=30)
                _stdout, stderr = process.communicate(timeout=5)
                self.assertEqual(return_code, 128 + signal.SIGTERM, stderr.decode("utf-8", errors="replace"))
                self.assertEqual(
                    [json.loads(line) for line in invocations.read_text(encoding="utf-8").splitlines()],
                    [["-Vv"]],
                    "a later preflight probe or configured Cargo step started after cancellation",
                )
                for pid in pids:
                    self.assertFalse(_pid_is_running(pid), "agent-owned process {} survived signal cleanup".format(pid))
                self.assertFalse(list(probe_temp.glob("cargo-evidence-probe-*")))

                manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
                summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
                self.assertNotEqual(summary["status"], "passed")
                self.assertEqual([step["status"] for step in manifest["steps"]], [
                    "not_run_interrupted", "not_run_interrupted",
                ])
                interrupted = manifest["provenance"]["steps"]["check"]
                self.assertEqual(interrupted["preflight_status"], "interrupted")
                self.assertEqual(interrupted["cargo"]["version_probe"]["status"], "interrupted")
                self.assertEqual(interrupted["cargo"]["version_probe"]["signal_number"], signal.SIGTERM)
                self.assertEqual(interrupted["cargo"]["version_probe"]["signal_name"], "SIGTERM")
                self.assertIn("process_tree", interrupted["cargo"]["version_probe"])
                later = manifest["provenance"]["steps"]["later"]
                self.assertEqual(later["preflight_status"], "not_run_interrupted")
                self.assertEqual(later["cargo"]["version_probe"]["status"], "not_run_interrupted")
                self.assertIsNone(later["cargo_metadata"])
                status, issues = provenance.complete_provenance_status(manifest["provenance"])
                self.assertEqual(status, "incomplete")
                codes = [item["code"] for item in issues]
                self.assertIn("cargo_version_probe_interrupted", codes)
                self.assertIn("invocation_preflight_interrupted", codes)
                self.assertIn("invocation_preflight_not_run_interrupted", codes)
                self.assertTrue((output / "workspace-inventory.json").is_file())
                self.assertTrue((output / "artifact-inventory.json").is_file())
                archive_path = Path(manifest["archive"]["path"])
                sidecar_path = Path(manifest["archive"]["integrity_sidecar_path"])
                inventory = json.loads((output / "artifact-inventory.json").read_text(encoding="utf-8"))
                agent.verify_archive_snapshot(archive_path, output, inventory)
                self.assertEqual(json.loads(sidecar_path.read_text(encoding="utf-8"))["status"], "created")
                all_evidence = b"".join(path.read_bytes() for path in output.rglob("*") if path.is_file())
                self.assertNotIn(b"stdout.capture", all_evidence)
                self.assertNotIn(b"stderr.capture", all_evidence)
                with tarfile.open(archive_path, "r:gz") as archive:
                    self.assertFalse(any(
                        "stdout.capture" in name or "stderr.capture" in name for name in archive.getnames()
                    ))
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)

    @unittest.skipIf(os.name == "nt", "POSIX ps/getsid fallback is unavailable on Windows")
    def test_ps_fallback_uses_getsid_instead_of_ps_sess_field(self):
        from types import SimpleNamespace
        # macOS prints zero for ps's sess field; getsid(pid) is the reliable
        # per-process session query. The fourth process is a zombie and must
        # not be included even though it belongs to the target session.
        output = """101 101 Ss
102 102 S
103 103 S
104 104 Z
"""
        session_ids = {101: 9001, 102: 9001, 103: 9002, 104: 9001}
        with mock.patch.object(supervision.shutil, "which", return_value="/usr/bin/ps"), \
                mock.patch.object(supervision.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=output)) as run, \
                mock.patch.object(supervision.os, "getsid", side_effect=lambda pid: session_ids[pid]) as getsid:
            groups = supervision._ps_session_groups(9001)
        self.assertEqual(groups, {101, 102})
        self.assertEqual(getsid.call_args_list, [mock.call(101), mock.call(102), mock.call(103)])
        self.assertEqual(
            run.call_args.args[0],
            ["/usr/bin/ps", "-U", str(os.getuid()), "-x", "-o", "pid=,pgid=,stat="],
        )

    @unittest.skipIf(os.name == "nt", "POSIX ps/getsid fallback is unavailable on Windows")
    def test_ps_fallback_marks_permission_errors_as_incomplete(self):
        from types import SimpleNamespace
        output = """101 101 Ss
102 102 S
"""
        with mock.patch.object(supervision.shutil, "which", return_value="/usr/bin/ps"), \
                mock.patch.object(supervision.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=output)), \
                mock.patch.object(supervision.os, "getsid", side_effect=[9001, PermissionError("denied")]):
            self.assertIsNone(supervision._ps_session_groups(9001))

    @unittest.skipIf(os.name == "nt", "POSIX ps/getsid fallback is unavailable on Windows")
    def test_ps_fallback_ignores_processes_that_exit_during_snapshot(self):
        from types import SimpleNamespace
        output = """101 101 Ss
102 102 S
"""
        with mock.patch.object(supervision.shutil, "which", return_value="/usr/bin/ps"), \
                mock.patch.object(supervision.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=output)), \
                mock.patch.object(supervision.os, "getsid", side_effect=[9001, ProcessLookupError()]):
            self.assertEqual(supervision._ps_session_groups(9001), {101})

    @unittest.skipIf(os.name == "nt", "POSIX ps/getsid fallback is unavailable on Windows")
    def test_ps_fallback_rejects_an_empty_process_table(self):
        from types import SimpleNamespace
        with mock.patch.object(supervision.shutil, "which", return_value="/usr/bin/ps"), \
                mock.patch.object(supervision.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="")):
            self.assertIsNone(supervision._ps_session_groups(9001))

    @unittest.skipIf(os.name == "nt", "POSIX process supervision is unavailable on Windows")
    def test_posix_wait_does_not_accept_empty_snapshot_while_direct_child_is_alive(self):
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(
            supervision, "_posix_session_snapshot", return_value=(set(), True),
        ):
            self.assertFalse(supervision._wait_posix_session_empty(43210, process, 0))
        process.poll.assert_called()

    @unittest.skipIf(os.name == "nt", "POSIX process supervision is unavailable on Windows")
    def test_posix_cleanup_signals_initial_group_when_snapshot_is_empty(self):
        process = mock.Mock()
        process.pid = 43210
        process.wait.return_value = 0
        empty_complete = (set(), True)
        with mock.patch.object(
            supervision, "_posix_session_snapshot", side_effect=[empty_complete, empty_complete],
        ), mock.patch.object(
            supervision, "_send_posix_session_signal", return_value=[],
        ) as send_signal, mock.patch.object(
            supervision, "_wait_posix_session_empty", return_value=True,
        ):
            result = supervision._posix_cleanup(process, 43210, 0.1, "timeout")
        send_signal.assert_called_once_with(43210, signal.SIGTERM)
        self.assertTrue(result["term_signal_sent"])
        self.assertTrue(result["cleanup_complete"])
        process.wait.assert_called_once()

    @unittest.skipIf(os.name == "nt", "POSIX killpg fallback is unavailable on Windows")
    def test_posix_session_fallback_is_explicitly_unverified(self):
        with mock.patch.object(supervision, "_procfs_session_groups", return_value=None), \
                mock.patch.object(supervision, "_ps_session_groups", return_value=None), \
                mock.patch.object(supervision.os, "killpg", return_value=None) as killpg:
            groups, complete = supervision._posix_session_snapshot(43210)
        self.assertEqual(groups, {43210})
        self.assertFalse(complete)
        killpg.assert_called_once_with(43210, 0)

    def test_timeout_kills_nested_descendants_even_when_parent_exits_first(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            child = root / "child.py"
            parent = root / "parent.py"
            pids = root / "pids.json"
            child.write_text(
                "import json, os, signal, subprocess, sys, time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "if hasattr(signal, 'SIGBREAK'): signal.signal(signal.SIGBREAK, signal.SIG_IGN)\n"
                "grandchild_code = \"import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); \"\n"
                "grandchild_code += \"getattr(signal, 'SIGBREAK', None) is not None and signal.signal(signal.SIGBREAK, signal.SIG_IGN); time.sleep(120)\"\n"
                "grandchild = subprocess.Popen([sys.executable, '-c', grandchild_code])\n"
                "open(sys.argv[1], 'w').write(json.dumps([os.getpid(), grandchild.pid]))\n"
                "time.sleep(120)\n",
                encoding="utf-8",
            )
            parent.write_text(
                "import signal, subprocess, sys, time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "if hasattr(signal, 'SIGBREAK'): signal.signal(signal.SIGBREAK, signal.SIG_IGN)\n"
                "subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]])\n"
                "deadline = time.time() + 10\n"
                "while not __import__('os').path.exists(sys.argv[2]) and time.time() < deadline: time.sleep(.02)\n"
                "time.sleep(120)\n",
                encoding="utf-8",
            )
            result = agent.run_process(
                [sys.executable, str(parent), str(child), str(pids)],
                root, os.environ.copy(), root / "stdout.bin", root / "stderr.bin", 5.0, 0.2,
            )
            self.assertTrue(pids.exists(), "nested child fixture did not start")
            child_pids = json.loads(pids.read_text(encoding="utf-8"))
            self.assertTrue(result["timed_out"])
            self.assertTrue(result["process_tree"]["cleanup_complete"], result["process_tree"])
            self.assertTrue(result["process_tree"]["kill_signal_sent"], result["process_tree"])
            for pid in child_pids:
                self.assertFalse(_pid_is_running(pid), "descendant {} survived cleanup".format(pid))

    @unittest.skipUnless(sys.platform.startswith("linux"), "/proc session enumeration is Linux-specific")
    def test_descendant_that_changes_process_group_but_not_session_is_killed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            child = root / "child_new_group.py"
            parent = root / "parent.py"
            pids = root / "pids.json"
            child.write_text(
                "import json, os, signal, subprocess, sys, time\n"
                "os.setpgrp()  # new process group, same runner-owned session\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "grandchild = subprocess.Popen([sys.executable, '-c', "
                "'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(120)'])\n"
                "open(sys.argv[1], 'w').write(json.dumps([os.getpid(), grandchild.pid]))\n"
                "time.sleep(120)\n",
                encoding="utf-8",
            )
            parent.write_text(
                "import subprocess, sys, time, os\n"
                "subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]])\n"
                "deadline = time.time() + 10\n"
                "while not os.path.exists(sys.argv[2]) and time.time() < deadline: time.sleep(.02)\n"
                "time.sleep(120)\n",
                encoding="utf-8",
            )
            result = agent.run_process(
                [sys.executable, str(parent), str(child), str(pids)],
                root, os.environ.copy(), root / "stdout.bin", root / "stderr.bin", 5.0, 0.2,
            )
            self.assertTrue(pids.exists(), "changed-process-group child did not start")
            child_pids = json.loads(pids.read_text(encoding="utf-8"))
            self.assertTrue(result["timed_out"])
            self.assertTrue(result["process_tree"]["cleanup_complete"], result["process_tree"])
            self.assertIn(child_pids[0], result["process_tree"]["process_groups_signalled"])
            for pid in child_pids:
                self.assertFalse(_pid_is_running(pid), "session descendant {} survived cleanup".format(pid))

    def test_successful_parent_with_orphan_child_is_failed_and_cleaned(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            child = root / "child.py"
            parent = root / "parent.py"
            pids = root / "pids.json"
            child.write_text(
                "import json, os, signal, subprocess, sys, time\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "if hasattr(signal, 'SIGBREAK'): signal.signal(signal.SIGBREAK, signal.SIG_IGN)\n"
                "grandchild_code = \"import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); \"\n"
                "grandchild_code += \"getattr(signal, 'SIGBREAK', None) is not None and signal.signal(signal.SIGBREAK, signal.SIG_IGN); time.sleep(120)\"\n"
                "grandchild = subprocess.Popen([sys.executable, '-c', grandchild_code])\n"
                "open(sys.argv[1], 'w').write(json.dumps([os.getpid(), grandchild.pid]))\n"
                "time.sleep(120)\n",
                encoding="utf-8",
            )
            parent.write_text(
                "import subprocess, sys, time, os\n"
                "subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]])\n"
                "deadline = time.time() + 10\n"
                "while not os.path.exists(sys.argv[2]) and time.time() < deadline: time.sleep(.02)\n"
                "sys.exit(0)\n",
                encoding="utf-8",
            )
            result = agent.run_process(
                [sys.executable, str(parent), str(child), str(pids)],
                root, os.environ.copy(), root / "stdout.bin", root / "stderr.bin", 15, 0.2,
            )
            self.assertEqual(result["exit_code"], 0)
            self.assertTrue(result["orphan_processes_detected"])
            self.assertEqual(result["process_tree"]["trigger"], "orphaned-descendants")
            self.assertTrue(result["process_tree"]["cleanup_complete"], result["process_tree"])
            self.assertTrue(result["process_tree"]["kill_signal_sent"], result["process_tree"])
            child_pids = json.loads(pids.read_text(encoding="utf-8"))
            for pid in child_pids:
                self.assertFalse(_pid_is_running(pid), "orphan descendant {} survived cleanup".format(pid))

    @unittest.skipIf(os.name == "nt", "POSIX executable shim used by integration test")
    def test_end_to_end_with_fake_cargo_and_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[package]\nname="fake"\nversion="0.1.0"\nedition="2021"\n', encoding="utf-8")
            fake_cargo = root / "fake-cargo"
            fake_cargo.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "cmd = sys.argv[1]\n"
                "if cmd == 'fmt':\n"
                "    sys.stdout.write('fmt check ok\\n')\n"
                "elif cmd == 'check':\n"
                "    sys.stdout.write(json.dumps({'reason':'build-finished','success':True}) + '\\n')\n"
                "elif cmd == 'test':\n"
                "    sys.stdout.write(json.dumps({'reason':'build-finished','success':True}) + '\\n')\n"
                "    sys.stdout.write('test sample::works ... ok\\n')\n"
                "    sys.stdout.write('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\\n')\n"
                "else:\n"
                "    sys.exit(9)\n",
                encoding="utf-8",
            )
            fake_cargo.chmod(0o755)
            config_path = root / "pipeline.json"
            config = {
                "schema_version": 1,
                "workspace_root": str(workspace),
                "execution": {"cargo_executable": str(fake_cargo), "continue_on_error": True},
                "steps": [
                    {"id": "fmt", "args": ["fmt", "--all", "--", "--check"], "parser": "text"},
                    {"id": "check", "args": ["check", "--message-format=json"], "parser": "cargo-json"},
                    {"id": "test", "args": ["test", "--message-format=json"], "parser": "cargo-json+libtest"},
                ],
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            output = root / "evidence"
            code = agent.main(["--config", str(config_path), "--output-dir", str(output), "--archive"])
            self.assertEqual(code, 0)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "passed")
            self.assertEqual(manifest["archive"]["status"], "requested")
            self.assertEqual(manifest["artifact_inventory"], {
                "path": "artifact-inventory.json", "schema_version": 1,
            })
            self.assertEqual(summary["passed_steps"], 3)
            inventory_path = output / "artifact-inventory.json"
            inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["artifact_inventory_status"], inventory["status"])
            self.assertEqual(summary["inventory_digest"], inventory["inventory_digest"])
            self.assertEqual(inventory["inventory_digest"], artifact_inventory.calculate_inventory_digest(inventory))
            self.assertTrue((output / "config.redacted.json").is_file())
            self.assertTrue((output / "check" / "raw.jsonl").is_file())
            self.assertTrue((output / "test" / "test-results.json").is_file())
            python_log = (output / "runner.log").read_text(encoding="utf-8")
            self.assertIn("Supervised subprocess started", python_log)
            self.assertIn("Supervised subprocess completed", python_log)
            self.assertNotIn("fmt check ok", python_log)
            archive_path = Path(manifest["archive"]["path"])
            self.assertTrue(archive_path.is_file())
            sidecar_path = Path(manifest["archive"]["integrity_sidecar_path"])
            self.assertTrue(sidecar_path.is_file())
            sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
            archive_digest, archive_size = artifact_inventory.sha256_file(archive_path)
            inventory_digest, inventory_size = artifact_inventory.sha256_file(inventory_path)
            self.assertEqual(sidecar["archive"]["sha256"], archive_digest)
            self.assertEqual(sidecar["archive"]["size_bytes"], archive_size)
            self.assertEqual(sidecar["artifact_inventory"]["sha256"], inventory_digest)
            self.assertEqual(sidecar["artifact_inventory"]["size_bytes"], inventory_size)
            self.assertEqual(sidecar["artifact_inventory"]["inventory_digest"], inventory["inventory_digest"])
            with tarfile.open(archive_path, "r:gz") as archive:
                self.assertTrue(archive.extractfile(output.name + "/manifest.json").read())
                self.assertTrue(archive.extractfile(output.name + "/runner.log").read())
                for filename in ("manifest.json", "summary.json", "steps.jsonl", "artifact-inventory.json"):
                    self.assertEqual(
                        archive.extractfile(output.name + "/" + filename).read(), (output / filename).read_bytes(),
                    )
                for step_id in ("fmt", "check", "test"):
                    self.assertTrue(archive.extractfile(output.name + "/" + step_id + "/summary.json").read())
            self.assertNotEqual(str(sidecar_path), str(archive_path))
            self.assertEqual(sidecar_path.parent, output.resolve().parent)

    def test_fake_cargo_canaries_are_redacted_from_evidence_and_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text(
                '[package]\nname="redaction-fixture"\nversion="0.1.0"\nedition="2021"\n',
                encoding="utf-8",
            )
            output = root / "evidence"
            captured_args_path = root / "captured-original-args.json"
            canaries = [
                "H01_TOKEN_" + uuid.uuid4().hex,
                "H01_PASSWORD_" + uuid.uuid4().hex,
                "H01_CONFIG_TOKEN_" + uuid.uuid4().hex,
                "H01_CONFIG_PASSWORD_" + uuid.uuid4().hex,
                "H01_URL_QUERY_" + uuid.uuid4().hex,
                "H01_URL_FRAGMENT_" + uuid.uuid4().hex,
                "H01_CONFIG_URL_QUERY_" + uuid.uuid4().hex,
                "H01_CONFIG_URL_FRAGMENT_" + uuid.uuid4().hex,
                "H01_ENV_TOKEN_" + uuid.uuid4().hex,
                "H01_ENV_PASSWORD_" + uuid.uuid4().hex,
                "H01_NESTED_TOKEN_" + uuid.uuid4().hex,
                "H01_ARRAY_TOKEN_" + uuid.uuid4().hex,
                "H01_ARRAY_CREDENTIAL_" + uuid.uuid4().hex,
            ]
            additional_canaries = {
                "COMMENT_PASSWORD": "H01_COMMENT_PASSWORD_" + uuid.uuid4().hex,
                "COMMENT_TOKEN": "H01_COMMENT_TOKEN_" + uuid.uuid4().hex,
                "COMMENT_URL_USER": "H01_COMMENT_URL_USER_" + uuid.uuid4().hex,
                "COMMENT_URL": "H01_COMMENT_URL_" + uuid.uuid4().hex,
                "COMMENT_QUERY": "H01_COMMENT_QUERY_" + uuid.uuid4().hex,
                "ARRAY_COMMENT": "H01_ARRAY_COMMENT_" + uuid.uuid4().hex,
                "INVALID_ATOM": "H01_INVALID_ATOM_" + uuid.uuid4().hex,
                "INVALID_KEY": "H01_INVALID_KEY_" + uuid.uuid4().hex,
                "INVALID_ESCAPE": "H01_INVALID_ESCAPE_" + uuid.uuid4().hex,
                "INVALID_NO_SPACE": "H01_INVALID_NO_SPACE_" + uuid.uuid4().hex,
            }
            canaries.extend(additional_canaries.values())
            fake_code = (
                "import json,os,sys; "
                "open(os.environ['H01_ARG_CAPTURE'], 'w', encoding='utf-8').write(json.dumps(sys.argv)); "
                "sys.stdout.write('fake cargo completed\\n')"
            )
            (workspace / "check").write_text(fake_code, encoding="utf-8")
            original_step_args = [
                "check",
                "--token", canaries[0],
                "--password=" + canaries[1],
                "--config", "registry.token=" + canaries[2],
                "--config=registries.private.password=" + canaries[3],
                "--index",
                "sparse+https://registry-user:registry-password@example.invalid/index"
                "?token={}&channel=stable#{}".format(canaries[4], canaries[5]),
                "--config=registries.private.index="
                '"sparse+https://registry-user:registry-password@example.invalid/index'
                '?password={}&channel=stable#{}"'.format(canaries[6], canaries[7]),
                "--config",
                'registries.private = { token = "' + canaries[10] + '", protocol = "sparse" }',
                "--config=registries.private.mirrors = ["
                '{ url = "https://example.invalid/one", token = "' + canaries[11] + '" }, '
                '{ url = "https://example.invalid/two", credential = "' + canaries[12] + '" }]',
                "--config",
                'registry.comment = 1 # password={}'.format(additional_canaries["COMMENT_PASSWORD"]),
                "--config",
                'registry.comment_label = 1 # token = "{}"'.format(additional_canaries["COMMENT_TOKEN"]),
                "--config",
                'registry.comment_url = "https://example.invalid/index" '
                '# https://{}:{}@example.invalid/path'.format(
                    additional_canaries["COMMENT_URL_USER"], additional_canaries["COMMENT_URL"]
                ),
                "--config",
                'registry.comment_query = "https://example.invalid/index" '
                '# ?password={}&channel=stable'.format(additional_canaries["COMMENT_QUERY"]),
                "--config",
                'registry.comment_array = [\n  "first", # token={}\n  "second"\n]'.format(
                    additional_canaries["ARRAY_COMMENT"]
                ),
                "--config",
                'registry.invalid_atom=garbage={}'.format(additional_canaries["INVALID_ATOM"]),
                "--config",
                'registry.invalid_key={{ foo bar = "{}" }}'.format(additional_canaries["INVALID_KEY"]),
                "--config",
                'registry.invalid_escape="bad\\q{}"'.format(additional_canaries["INVALID_ESCAPE"]),
                "--config",
                'registry.invalid_no_space=1#password={}'.format(additional_canaries["INVALID_NO_SPACE"]),
                "--config",
                'registry.label="literal # stays in string"',
            ]
            raw_cargo_argv = original_step_args
            config = {
                "schema_version": 1,
                "workspace_root": str(workspace),
                "execution": {
                    "cargo_executable": sys.executable,
                    "continue_on_error": True,
                    "environment": {"H01_ARG_CAPTURE": str(captured_args_path)},
                },
                "steps": [{
                    "id": "check",
                    "args": original_step_args,
                    "parser": "text",
                    "environment": {
                        "CARGO_REGISTRIES_PRIVATE_URL": (
                            "sparse+https://registry-user:{}@example.invalid/index"
                            "?token={}&channel=stable#{}"
                        ).format(canaries[9], canaries[8], canaries[5]),
                        "CARGO_REGISTRIES_PRIVATE_TOKEN": canaries[8],
                    },
                    "redact_arg_indexes": [1, 4, 7],
                }],
            }
            config_path = root / "pipeline.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")

            dry_run_output = io.StringIO()
            with mock.patch.object(sys, "stdout", dry_run_output):
                dry_run_code = agent.main(["--config", str(config_path), "--dry-run"])
            self.assertEqual(dry_run_code, 0)
            for canary in canaries:
                self.assertNotIn(canary, dry_run_output.getvalue())

            exit_code = agent.main([
                "--config", str(config_path),
                "--output-dir", str(output),
                "--archive",
            ])
            self.assertEqual(exit_code, 0)
            self.assertEqual(json.loads(captured_args_path.read_text(encoding="utf-8")), raw_cargo_argv)

            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            redacted_config = json.loads((output / "config.redacted.json").read_text(encoding="utf-8"))
            self.assertNotIn(canaries[0], json.dumps(redacted_config))
            redacted_step_args = redacted_config["steps"][0]["args"]
            self.assertIn(
                'registries.private = { token = <REDACTED>, protocol = "sparse" }',
                redacted_step_args,
            )
            self.assertIn(
                '--config=registries.private.mirrors = ['
                '{ url = "https://example.invalid/one", token = <REDACTED> }, '
                '{ url = "https://example.invalid/two", credential = <REDACTED> }]',
                redacted_step_args,
            )
            self.assertIn(
                'registry.comment = 1 #<REDACTED_COMMENT>', redacted_step_args,
            )
            self.assertIn(
                'registry.comment_array = [\n  "first", #<REDACTED_COMMENT>\n  "second"\n]',
                redacted_step_args,
            )
            self.assertIn('registry.label="literal # stays in string"', redacted_step_args)
            self.assertIn(
                "registry.invalid_atom=<REDACTED>", redacted_step_args,
            )
            self.assertIn(
                "registry.invalid_key=<REDACTED>", redacted_step_args,
            )
            step_record = manifest["steps"][0]
            self.assertEqual(step_record["args"][1:10], [
                "<REDACTED>",
                "<REDACTED>",
                "--password=<REDACTED>",
                "<REDACTED>",
                "registry.token=<REDACTED>",
                "--config=registries.private.password=<REDACTED>",
                "<REDACTED>",
                "sparse+https://<REDACTED>@example.invalid/index?token=%3CREDACTED%3E&channel=stable#<REDACTED>",
                '--config=registries.private.index="sparse+https://<REDACTED>@example.invalid/index?password=%3CREDACTED%3E&channel=stable#<REDACTED>"',
            ])
            self.assertNotIn(canaries[4], json.dumps(step_record))
            self.assertNotIn(canaries[6], json.dumps(step_record))
            provenance_file = json.loads((output / "provenance.json").read_text(encoding="utf-8"))
            provenance_step = provenance_file["steps"]["check"]
            probe_argv = provenance_step["cargo_metadata_probe"]["argv"]
            self.assertIn("<REDACTED>", probe_argv)
            self.assertIn("registry.token=<REDACTED>", probe_argv)
            self.assertIn(
                "--config=registries.private.password=<REDACTED>",
                probe_argv,
            )
            observed_environment = provenance_step["cargo_configuration"]["environment"]["values"]
            self.assertEqual(
                observed_environment["CARGO_REGISTRIES_PRIVATE_URL"],
                "sparse+https://<REDACTED>@example.invalid/index"
                "?token=%3CREDACTED%3E&channel=stable#<REDACTED>",
            )
            self.assertEqual(observed_environment["CARGO_REGISTRIES_PRIVATE_TOKEN"], "<REDACTED>")

            expected_runtime_paths = list(self.EXPECTED_RUNTIME_SOURCE_FILES)
            manifest_provenance = manifest["provenance"]
            manifest_runtime = manifest_provenance["agent"]["runtime_source_files"]
            provenance_runtime = provenance_file["agent"]["runtime_source_files"]
            self.assertEqual([item["path"] for item in manifest_runtime], expected_runtime_paths)
            self.assertEqual([item["path"] for item in provenance_runtime], expected_runtime_paths)
            for rows in (manifest_runtime, provenance_runtime):
                self.assertTrue(all(item["status"] == "hashed" for item in rows))
            runtime_digest = manifest_provenance["agent"]["runtime_source_digest"]
            self.assertTrue(runtime_digest.startswith("sha256:"))
            self.assertEqual(provenance_file["agent"]["runtime_source_digest"], runtime_digest)
            self.assertEqual(provenance_file["agent"], manifest_provenance["agent"])
            self.assertEqual(provenance_file["status"], manifest_provenance["status"])
            observed_status, _observed_issues = provenance.complete_provenance_status(manifest_provenance)
            self.assertEqual(manifest_provenance["status"], observed_status)
            self.assertEqual(manifest["status"], "passed")
            self.assertEqual(manifest_provenance["workspace"]["inventory_status"], "complete")
            self.assertEqual(manifest_provenance["workspace"]["change_status"], "unchanged")
            path_record = provenance_file["steps"]["check"]["cargo_configuration"]["environment"]["PATH"]
            path_value = os.environ.get("PATH", "")
            self.assertEqual(path_record["sha256"], provenance.sha256_bytes(os.fsencode(path_value)))
            self.assertEqual(
                path_record["entry_count"], len(path_value.split(os.pathsep)) if path_value else 0,
            )

            persisted_files = [
                path.read_bytes() for path in output.rglob("*") if path.is_file()
            ]
            persisted_text = b"\n".join(persisted_files)
            for canary in canaries:
                self.assertNotIn(canary.encode("utf-8"), persisted_text, canary)

            archive_path = Path(manifest["archive"]["path"])
            with tarfile.open(archive_path, "r:gz") as archive:
                archived_contents = b"\n".join(
                    archive.extractfile(member).read()
                    for member in archive.getmembers()
                    if member.isfile()
                )
            for canary in canaries:
                self.assertNotIn(canary.encode("utf-8"), archived_contents, canary)

    def test_archive_failure_updates_inventory_without_success_sidecar(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[workspace]\nmembers = []\n', encoding="utf-8")
            config_path = root / "pipeline.json"
            config = {
                "schema_version": 1,
                "workspace_root": str(workspace),
                "execution": {"cargo_executable": sys.executable},
                "steps": [{"id": "check", "args": ["check"], "parser": "text"}],
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            output = root / "evidence"
            with mock.patch.object(agent, "create_archive", side_effect=OSError("archive denied")):
                code = agent.main(["--config", str(config_path), "--output-dir", str(output), "--archive"])
            self.assertEqual(code, 2)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
            inventory = json.loads((output / "artifact-inventory.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["archive"]["status"], "failed")
            self.assertFalse(Path(manifest["archive"]["integrity_sidecar_path"]).exists())
            self.assertEqual(summary["status"], "error")
            self.assertEqual(summary["inventory_digest"], inventory["inventory_digest"])
            self.assertEqual(inventory["inventory_digest"], artifact_inventory.calculate_inventory_digest(inventory))

    def test_finalize_archives_the_closed_log_and_final_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[workspace]\nmembers = []\n', encoding="utf-8")
            output = root / "evidence"
            output.mkdir()
            config = {
                "schema_version": 1,
                "workspace_root": str(workspace),
                "execution": {
                    "cargo_executable": "cargo", "continue_on_error": True,
                    "default_timeout_seconds": None, "termination_grace_seconds": 0,
                    "environment": {}, "unset_environment": [],
                },
                "steps": [{
                    "id": "check", "enabled": True, "args": ["check"], "parser": "text",
                    "cwd": ".", "timeout_seconds": None, "environment": {},
                    "unset_environment": [], "redact_arg_indexes": [],
                }],
                "_config_path": str(root / "pipeline.json"), "_config_sha256": "test-hash",
            }
            agent.configure_logging("ERROR")
            try:
                agent.attach_file_logging(output / "runner.log")
                runner = agent.Runner(config, workspace, output, True)
                runner.finalize()
            finally:
                agent.close_logging()
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            archive_path = Path(manifest["archive"]["path"])
            sidecar_path = Path(manifest["archive"]["integrity_sidecar_path"])
            self.assertEqual(manifest["archive"]["status"], "requested")
            self.assertTrue(archive_path.is_file())
            self.assertTrue(sidecar_path.is_file())
            log_bytes = (output / "runner.log").read_bytes()
            self.assertIn(b"Python agent run finalized", log_bytes)
            with tarfile.open(archive_path, "r:gz") as archive:
                for filename in ("runner.log", "manifest.json", "summary.json", "steps.jsonl", "artifact-inventory.json"):
                    member = archive.getmember(output.name + "/" + filename)
                    expected = log_bytes if filename == "runner.log" else (output / filename).read_bytes()
                    self.assertEqual(archive.extractfile(member).read(), expected)

    def test_finalize_retry_keeps_archive_path_and_leaves_one_verified_pair(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runner, output = self.make_finalization_runner(root)
            real_create = agent.create_archive
            create_calls = []

            def fail_after_publication(evidence, destination=None):
                path = real_create(evidence, destination)
                create_calls.append(path)
                if len(create_calls) == 1:
                    raise OSError("injected after archive publication")
                return path

            with mock.patch.object(agent, "create_archive", side_effect=fail_after_publication):
                runner.finalize()
                chosen_path = runner.archive_path
                self.assertIsNotNone(runner.archive_error)
                self.assertFalse(chosen_path.exists(), "failed attempt left an invalid orphan archive")
                self.assertFalse(list(root.glob("*.integrity.json")), "failed attempt left a sidecar placeholder")
                runner.finalize()

            self.assertEqual(runner.archive_path, chosen_path)
            self.assertTrue(chosen_path.is_file())
            sidecars = list(root.glob("*.integrity.json"))
            self.assertEqual(sidecars, [runner.archive_sidecar_path])
            inventory = json.loads((output / "artifact-inventory.json").read_text(encoding="utf-8"))
            agent.verify_archive_snapshot(chosen_path, output, inventory)
            runner._verify_integrity_sidecar(runner.archive_sidecar_path, chosen_path, inventory)
            sidecar_bytes = runner.archive_sidecar_path.read_bytes()
            archive_bytes = chosen_path.read_bytes()
            evidence_names = sorted(str(path.relative_to(root)) for path in root.rglob("*") if path.is_file())
            runner.finalize()
            self.assertEqual(chosen_path.read_bytes(), archive_bytes)
            self.assertEqual(runner.archive_sidecar_path.read_bytes(), sidecar_bytes)
            self.assertEqual(
                sorted(str(path.relative_to(root)) for path in root.rglob("*") if path.is_file()),
                evidence_names,
            )

    def test_evidence_tree_sync_failure_blocks_finalization_until_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runner, _output = self.make_finalization_runner(root)
            real_sync = agent.sync_evidence_tree
            attempts = []

            def fail_once(path):
                if not attempts:
                    attempts.append(True)
                    raise OSError("injected evidence file sync failure")
                return real_sync(path)

            with mock.patch.object(agent, "sync_evidence_tree", side_effect=fail_once):
                runner.finalize()
                self.assertFalse(runner._finalization_state["complete"])
                self.assertIsNotNone(runner.archive_error)
                self.assertFalse(runner.archive_path.exists())
                runner.finalize()
            self.assertTrue(runner._finalization_state["complete"], runner._finalization_errors)
            self.assertTrue(runner.archive_path.is_file())
            self.assertTrue(runner.archive_sidecar_path.is_file())

    def test_sidecar_file_sync_failure_does_not_claim_complete_and_reuses_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runner, output = self.make_finalization_runner(root)
            real_sync_file = agent.sync_file
            injected = []

            def fail_sidecar_once(path):
                if Path(path) == runner.archive_sidecar_path and not injected:
                    injected.append(True)
                    error = OSError("injected sidecar file sync failure")
                    error.durability_sync_failed = True
                    raise error
                return real_sync_file(path)

            with mock.patch.object(agent, "sync_file", side_effect=fail_sidecar_once):
                runner.finalize()
                archive_path = runner.archive_path
                sidecar_path = runner.archive_sidecar_path
                self.assertFalse(runner._finalization_state["complete"])
                self.assertFalse(archive_path.exists())
                self.assertFalse(sidecar_path.exists())
                runner.finalize()
            self.assertTrue(runner._finalization_state["complete"], runner._finalization_errors)
            self.assertEqual(runner.archive_path, archive_path)
            self.assertEqual(runner.archive_sidecar_path, sidecar_path)
            inventory = json.loads((output / "artifact-inventory.json").read_text(encoding="utf-8"))
            agent.verify_archive_snapshot(archive_path, output, inventory)
            runner._verify_integrity_sidecar(sidecar_path, archive_path, inventory)

    @unittest.skipUnless(os.name != "nt", "requires POSIX directory fsync semantics")
    def test_evidence_directory_sync_failure_blocks_finalization_until_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runner, _output = self.make_finalization_runner(root)
            real_sync_fd = artifact_inventory.sync_fd
            injected = []

            def fail_directory_once(fd, error_code="file_sync_failed"):
                if error_code == "directory_sync_failed" and not injected:
                    injected.append(True)
                    error = OSError("injected evidence directory sync failure")
                    error.durability_sync_failed = True
                    error.error_code = error_code
                    raise error
                return real_sync_fd(fd, error_code)

            with mock.patch.object(artifact_inventory, "sync_fd", side_effect=fail_directory_once):
                runner.finalize()
                self.assertFalse(runner._finalization_state["complete"])
                self.assertIsNotNone(runner.archive_error)
                self.assertFalse(runner.archive_path.exists())
                runner.finalize()
            self.assertTrue(runner._finalization_state["complete"], runner._finalization_errors)

    @unittest.skipUnless(os.name != "nt", "requires POSIX directory fsync semantics")
    def test_sidecar_directory_sync_failure_preserves_and_rechecks_same_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runner, output = self.make_finalization_runner(root)
            real_sync_parent = agent.sync_parent_directory
            injected = []

            def fail_sidecar_parent_once(path):
                if Path(path) == runner.archive_sidecar_path and not injected:
                    injected.append(True)
                    error = OSError("injected sidecar parent directory sync failure")
                    error.namespace_sync_failed = True
                    error.durability_sync_failed = True
                    error.published_path = str(path)
                    error.error_code = "directory_sync_failed_after_replace"
                    raise error
                return real_sync_parent(path)

            with mock.patch.object(agent, "sync_parent_directory", side_effect=fail_sidecar_parent_once):
                runner.finalize()
                archive_path = runner.archive_path
                sidecar_path = runner.archive_sidecar_path
                self.assertFalse(runner._finalization_state["complete"])
                self.assertTrue(archive_path.is_file())
                self.assertTrue(sidecar_path.is_file())
                runner.finalize()
            self.assertTrue(runner._finalization_state["complete"], runner._finalization_errors)
            self.assertEqual(runner.archive_path, archive_path)
            self.assertEqual(runner.archive_sidecar_path, sidecar_path)
            inventory = json.loads((output / "artifact-inventory.json").read_text(encoding="utf-8"))
            agent.verify_archive_snapshot(archive_path, output, inventory)
            runner._verify_integrity_sidecar(sidecar_path, archive_path, inventory)

    def test_tar_partial_file_sync_failure_does_not_publish_archive_or_sidecar(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runner, _output = self.make_finalization_runner(root)
            real_sync_file = agent.sync_file
            injected = []

            def fail_partial_once(path):
                if Path(path).name.endswith(".partial") and not injected:
                    injected.append(True)
                    error = OSError("injected TAR partial file sync failure")
                    error.durability_sync_failed = True
                    error.error_code = "file_sync_failed"
                    raise error
                return real_sync_file(path)

            with mock.patch.object(agent, "sync_file", side_effect=fail_partial_once):
                runner.finalize()
            self.assertFalse(runner._finalization_state["complete"])
            self.assertIsNotNone(runner.archive_error)
            self.assertFalse(runner.archive_path.exists())
            self.assertFalse(runner.archive_sidecar_path.exists())
            runner.finalize()
            self.assertTrue(runner._finalization_state["complete"], runner._finalization_errors)

    def test_finalize_retries_owned_sidecar_placeholder_and_verifies_published_sidecar(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runner, output = self.make_finalization_runner(root)
            real_build = runner._build_integrity_sidecar
            attempts = []

            def fail_after_reservation(archive_path, inventory):
                attempts.append("reserved")
                if len(attempts) == 1:
                    self.assertTrue(runner.archive_sidecar_path.exists())
                    self.assertEqual(runner.archive_sidecar_path.stat().st_size, 0)
                    raise OSError("injected after sidecar reservation")
                return real_build(archive_path, inventory)

            with mock.patch.object(runner, "_build_integrity_sidecar", side_effect=fail_after_reservation):
                runner.finalize()
                stable_path = runner.archive_path
                self.assertFalse(runner.archive_sidecar_path.exists())
                runner.finalize()
            self.assertEqual(runner.archive_path, stable_path)
            inventory = json.loads((output / "artifact-inventory.json").read_text(encoding="utf-8"))
            agent.verify_archive_snapshot(runner.archive_path, output, inventory)
            runner._verify_integrity_sidecar(runner.archive_sidecar_path, runner.archive_path, inventory)

    def test_finalize_retries_provenance_inventory_and_archive_verification_failures(self):
        for failure_phase in ("provenance", "inventory", "archive_verification"):
            with self.subTest(failure_phase=failure_phase), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                runner, output = self.make_finalization_runner(root)
                if failure_phase == "provenance":
                    original = runner._finish_provenance
                    attempts = []

                    def fail_provenance_once():
                        if not attempts:
                            attempts.append(True)
                            raise OSError("injected provenance failure")
                        return original()

                    patcher = mock.patch.object(runner, "_finish_provenance", side_effect=fail_provenance_once)
                elif failure_phase == "inventory":
                    original = runner._write_artifact_inventory
                    attempts = []

                    def fail_inventory_once():
                        if not attempts:
                            attempts.append(True)
                            raise OSError("injected inventory failure")
                        return original()

                    patcher = mock.patch.object(runner, "_write_artifact_inventory", side_effect=fail_inventory_once)
                else:
                    original = agent.verify_archive_snapshot
                    attempts = []

                    def fail_verification_once(*args):
                        if not attempts:
                            attempts.append(True)
                            raise OSError("injected verification failure")
                        return original(*args)

                    patcher = mock.patch.object(agent, "verify_archive_snapshot", side_effect=fail_verification_once)
                with patcher:
                    runner.finalize()
                    self.assertIsNotNone(runner.archive_error)
                    self.assertFalse(runner.archive_sidecar_path.exists())
                    runner.finalize()
                inventory = json.loads((output / "artifact-inventory.json").read_text(encoding="utf-8"))
                agent.verify_archive_snapshot(runner.archive_path, output, inventory)
                runner._verify_integrity_sidecar(runner.archive_sidecar_path, runner.archive_path, inventory)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            runner, output = self.make_finalization_runner(root)
            original_write = agent.write_json_atomic
            injected = []

            def publish_then_raise(path, value):
                original_write(path, value)
                if Path(path) == runner.archive_sidecar_path and not injected:
                    injected.append(True)
                    raise OSError("injected after sidecar publication")

            with mock.patch.object(agent, "write_json_atomic", side_effect=publish_then_raise):
                runner.finalize()
            self.assertTrue(runner._finalization_state["complete"])
            self.assertIsNone(runner.archive_error)
            inventory = json.loads((output / "artifact-inventory.json").read_text(encoding="utf-8"))
            agent.verify_archive_snapshot(runner.archive_path, output, inventory)
            runner._verify_integrity_sidecar(runner.archive_sidecar_path, runner.archive_path, inventory)

    def test_changed_symlink_target_prevents_success_sidecar(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[workspace]\nmembers = []\n', encoding="utf-8")
            output = root / "evidence"
            output.mkdir()
            config = {
                "schema_version": 1,
                "workspace_root": str(workspace),
                "execution": {
                    "cargo_executable": "cargo", "continue_on_error": True,
                    "default_timeout_seconds": None, "termination_grace_seconds": 0,
                    "environment": {}, "unset_environment": [],
                },
                "steps": [{
                    "id": "check", "enabled": True, "args": ["check"], "parser": "text",
                    "cwd": ".", "timeout_seconds": None, "environment": {},
                    "unset_environment": [], "redact_arg_indexes": [],
                }],
                "_config_path": str(root / "pipeline.json"), "_config_sha256": "test-hash",
            }
            agent.configure_logging("ERROR")
            try:
                agent.attach_file_logging(output / "runner.log")
                runner = agent.Runner(config, workspace, output, True)
                (output / "data.bin").write_bytes(b"data")
                (output / "other.bin").write_bytes(b"other")
                link = output / "link"
                try:
                    link.symlink_to("data.bin")
                except (OSError, NotImplementedError):
                    self.skipTest("symlink creation is unavailable")
                original_create = agent.create_archive

                def mutate_link_then_archive(evidence, destination=None):
                    link.unlink()
                    link.symlink_to("other.bin")
                    return original_create(evidence, destination)

                with mock.patch.object(agent, "create_archive", side_effect=mutate_link_then_archive):
                    runner.finalize()
            finally:
                agent.close_logging()
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["archive"]["status"], "failed")
            self.assertFalse(Path(manifest["archive"]["integrity_sidecar_path"]).exists())
            self.assertFalse(Path(manifest["archive"]["path"]).exists())


    def test_python_agent_logging_creates_runner_log_and_keeps_agent_events_separate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "Cargo.toml").write_text('[workspace]\nmembers = []\n', encoding="utf-8")
            config_path = root / "pipeline.json"
            config = {
                "schema_version": 1,
                "workspace_root": str(workspace),
                "execution": {"cargo_executable": "cargo"},
                "steps": [{
                    "id": "check",
                    "args": ["check", "--token", "DO_NOT_WRITE_THIS_SECRET"],
                    "parser": "text",
                }],
            }
            config_path.write_text(json.dumps(config), encoding="utf-8")
            output = root / "evidence"
            fake_record = {
                "id": "check", "enabled": True, "status": "passed", "exit_code": 0,
                "duration_ms": 7, "timed_out": False, "interrupted": False,
                "process_tree": {
                    "supervision": "unit-test", "cleanup_complete": True,
                    "process_groups_signalled": [], "active_members_after_cleanup": 0,
                },
            }
            try:
                def unavailable_probe(name, command, cwd, env, keep_stdout=True, include_raw_stdout=False, **kwargs):
                    return {"name": name, "status": "unavailable", "exit_code": None}

                with mock.patch.object(agent, "process_step", return_value=fake_record), \
                        mock.patch.object(provenance, "run_probe", side_effect=unavailable_probe):
                    code = agent.main([
                        "--config", str(config_path), "--output-dir", str(output),
                        "--log-level", "ERROR",
                    ])
                self.assertEqual(code, 0)
                logfile = output / "runner.log"
                self.assertTrue(logfile.is_file())
                content = logfile.read_text(encoding="utf-8")
                self.assertIn("Python agent logfile opened", content)
                self.assertIn("Python agent run started", content)
                self.assertIn("Step started", content)
                self.assertIn("Step finished", content)
                self.assertIn("Overall Python agent status: PASSED", content)
                self.assertIn("DEBUG", content)
                self.assertIn("INFO", content)
                self.assertNotIn("DO_NOT_WRITE_THIS_SECRET", content)
                self.assertRegex(content, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")
                manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(manifest["logging"]["python_log"], "runner.log")
                self.assertEqual(manifest["logging"]["file_level"], "DEBUG")
                self.assertEqual(manifest["status"], "passed")
                self.assertEqual(manifest["provenance"]["status"], "incomplete")
            finally:
                agent.configure_logging("ERROR")

    def test_agent_source_has_no_builtin_print_call(self):
        import ast
        source = SCRIPT.read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "print"
        ]
        self.assertEqual(calls, [])

    def test_runtime_provenance_records_sources_and_is_deterministic(self):
        first = agent.runtime_provenance("1.4.0", SCRIPT.parent)
        second = agent.runtime_provenance("1.4.0", SCRIPT.parent)
        self.assertEqual(first["agent"]["runtime_source_digest"], second["agent"]["runtime_source_digest"])
        self.assertEqual(first["python"]["version"], sys.version)
        self.assertTrue(first["platform"]["system"])
        self.assertTrue(first["python"]["process_bits"].endswith("bit"))
        self.assertEqual(provenance.RUNTIME_SOURCE_FILES, self.EXPECTED_RUNTIME_SOURCE_FILES)
        records = first["agent"]["runtime_source_files"]
        self.assertEqual([item["path"] for item in records], list(self.EXPECTED_RUNTIME_SOURCE_FILES))
        for item in first["agent"]["runtime_source_files"]:
            content = (SCRIPT.parent / item["path"]).read_bytes()
            self.assertEqual(item["status"], "hashed")
            self.assertEqual(item["size_bytes"], len(content))
            self.assertEqual(item["sha256"], agent.provenance_sha256_bytes(content))

        composite = [
            {"path": item["path"], "sha256": item.get("sha256"), "status": item["status"]}
            for item in records
        ]
        self.assertTrue(all(set(item) == {"path", "sha256", "status"} for item in composite))
        expected_digest = "sha256:" + provenance.sha256_bytes(provenance.canonical_json_bytes(composite))
        self.assertEqual(first["agent"]["runtime_source_digest"], expected_digest)
        # size_bytes is reported per source but remains outside the digest payload.
        records[0]["size_bytes"] += 1
        resized_composite = [
            {"path": item["path"], "sha256": item.get("sha256"), "status": item["status"]}
            for item in records
        ]
        self.assertEqual(
            "sha256:" + provenance.sha256_bytes(provenance.canonical_json_bytes(resized_composite)),
            expected_digest,
        )

    def test_each_runtime_source_file_changes_the_composite_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            source_directory = Path(temp)
            self.write_runtime_source_fixture(source_directory)
            baseline = agent.runtime_provenance("1.5.0", source_directory)["agent"]["runtime_source_digest"]
            for name in self.EXPECTED_RUNTIME_SOURCE_FILES:
                with self.subTest(runtime_source=name):
                    path = source_directory / name
                    original = path.read_bytes()
                    path.write_bytes(original + b"changed content\n")
                    changed = agent.runtime_provenance("1.5.0", source_directory)["agent"]["runtime_source_digest"]
                    self.assertNotEqual(changed, baseline)
                    path.write_bytes(original)

    def test_missing_runtime_source_is_retained_and_marks_provenance_incomplete(self):
        for missing_name in self.EXPECTED_RUNTIME_SOURCE_FILES:
            with self.subTest(missing_runtime_source=missing_name), tempfile.TemporaryDirectory() as temp:
                source_directory = Path(temp)
                self.write_runtime_source_fixture(source_directory)
                complete = agent.runtime_provenance("1.5.0", source_directory)
                complete_provenance = {"agent": complete["agent"], "steps": {}, "issues": []}
                self.assertEqual(provenance.complete_provenance_status(complete_provenance)[0], "complete")

                (source_directory / missing_name).unlink()
                observed = agent.runtime_provenance("1.5.0", source_directory)
                records = observed["agent"]["runtime_source_files"]
                self.assertEqual([item["path"] for item in records], list(self.EXPECTED_RUNTIME_SOURCE_FILES))
                missing = next(item for item in records if item["path"] == missing_name)
                self.assertEqual(missing["status"], "unavailable")
                self.assertEqual(missing["error_type"], "FileNotFoundError")
                self.assertIn(missing_name, observed["source_errors"])
                observed_provenance = {"agent": observed["agent"], "steps": {}, "issues": []}
                status, issues = provenance.complete_provenance_status(observed_provenance)
                self.assertEqual(status, "incomplete")
                self.assertIn(
                    {"code": "runtime_source_unavailable", "path": missing_name},
                    issues,
                )

    def test_unreadable_runtime_source_is_retained_and_marks_provenance_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            source_directory = Path(temp)
            self.write_runtime_source_fixture(source_directory)
            original_open = artifact_inventory.open_file_no_follow
            for unreadable_name in self.EXPECTED_RUNTIME_SOURCE_FILES:
                with self.subTest(unreadable_runtime_source=unreadable_name):
                    unreadable_path = source_directory / unreadable_name

                    def open_with_one_error(path, *args, **kwargs):
                        if Path(path) == unreadable_path:
                            raise PermissionError("injected deterministic read error")
                        return original_open(path, *args, **kwargs)

                    with mock.patch.object(artifact_inventory, "open_file_no_follow", side_effect=open_with_one_error):
                        observed = agent.runtime_provenance("1.5.0", source_directory)
                    records = observed["agent"]["runtime_source_files"]
                    self.assertEqual([item["path"] for item in records], list(self.EXPECTED_RUNTIME_SOURCE_FILES))
                    unreadable = next(item for item in records if item["path"] == unreadable_name)
                    self.assertEqual(unreadable["status"], "unavailable")
                    self.assertEqual(unreadable["error_type"], "PermissionError")
                    self.assertIn(unreadable_name, observed["source_errors"])
                    status, issues = provenance.complete_provenance_status({
                        "agent": observed["agent"], "steps": {}, "issues": [],
                    })
                    self.assertEqual(status, "incomplete")
                    self.assertIn(
                        {"code": "runtime_source_unavailable", "path": unreadable_name},
                        issues,
                    )

    def test_unlisted_files_do_not_enter_or_change_runtime_source_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            source_directory = Path(temp)
            self.write_runtime_source_fixture(source_directory)
            baseline = agent.runtime_provenance("1.5.0", source_directory)["agent"]["runtime_source_digest"]
            extras = {
                "README.md": b"documentation\n",
                "CHANGELOG.md": b"release notes\n",
                "test_helper.py": b"test helper\n",
                "unlisted_runtime.py": b"helper module\n",
            }
            cache = source_directory / "__pycache__"
            cache.mkdir()
            extras["__pycache__/ignored.pyc"] = b"generated cache\n"
            for name, content in extras.items():
                path = source_directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            observed = agent.runtime_provenance("1.5.0", source_directory)["agent"]
            self.assertEqual([item["path"] for item in observed["runtime_source_files"]], list(self.EXPECTED_RUNTIME_SOURCE_FILES))
            self.assertEqual(observed["runtime_source_digest"], baseline)

    def test_workspace_inventory_is_order_independent_and_detects_content_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            left, right = base / "left", base / "right"
            (left / "src").mkdir(parents=True)
            (right / "src").mkdir(parents=True)
            (left / "z.txt").write_text("z", encoding="utf-8")
            (left / "src" / "lib.rs").write_text("pub fn value() -> u8 { 1 }\n", encoding="utf-8")
            (right / "src" / "lib.rs").write_text("pub fn value() -> u8 { 1 }\n", encoding="utf-8")
            (right / "z.txt").write_text("z", encoding="utf-8")
            first = agent.inventory_workspace(left, [])
            same = agent.inventory_workspace(right, [])
            self.assertEqual(first["digest"], same["digest"])
            (right / "src" / "lib.rs").write_text("pub fn value() -> u8 { 2 }\n", encoding="utf-8")
            changed = agent.inventory_workspace(right, [])
            self.assertNotEqual(first["digest"], changed["digest"])
            diff = agent.diff_inventories(first, changed)
            self.assertEqual(diff["counts"]["modified"], 1)
            self.assertIn({"relative_path": "src/lib.rs", "status": "modified"}, diff["entries"])

    def test_workspace_inventory_excludes_target_and_evidence_paths_explicitly(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "workspace"
            target = root / "target"
            build = root / "intermediate"
            evidence = root / "evidence"
            target.mkdir(parents=True)
            build.mkdir()
            evidence.mkdir()
            (root / "Cargo.toml").write_text('[package]\nname="x"\nversion="0.1.0"\n', encoding="utf-8")
            (target / "generated.bin").write_bytes(b"generated")
            (build / "rustc.bin").write_bytes(b"generated")
            (evidence / "manifest.json").write_text("{}", encoding="utf-8")
            outside_build = Path(temp) / "outside-build"
            outside_build.mkdir()
            exclusions = agent.prepare_exclusions(
                root, evidence, [(target, "metadata:step")], [(build, "config:step"), (outside_build, "env:step")],
            )
            inventory = agent.inventory_workspace(root, exclusions)
            paths = {item["relative_path"] for item in inventory["entries"]}
            self.assertIn("Cargo.toml", paths)
            self.assertNotIn("target", paths)
            self.assertNotIn("target/generated.bin", paths)
            self.assertNotIn("intermediate/rustc.bin", paths)
            self.assertNotIn("evidence", paths)
            self.assertEqual({item["reason"] for item in exclusions}, {
                "cargo_target_directory", "cargo_build_directory", "evidence_directory",
            })
            self.assertFalse(next(item for item in exclusions if item["source"] == "env:step")["applied"])
            self.assertTrue(all(item["applied"] for item in exclusions if item["source"] != "env:step"))
            fingerprints = agent.manifest_file_fingerprints(root, inventory, inventory)
            self.assertEqual(fingerprints["Cargo.lock"]["before"]["status"], "not_present")

    def _inventory_paths_excluding_lowercase_target(self, case_insensitive):
        # Only "Target" exists on disk, so the result does not depend on whether the
        # test file system is case-sensitive: matching is done on listed entry names.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "workspace"
            (root / "Target").mkdir(parents=True)
            (root / "Target" / "source.rs").write_bytes(b"source")
            inventory = agent.inventory_workspace(
                root, [{"path": "target", "applied": True}], case_insensitive=case_insensitive,
            )
            return {item["relative_path"] for item in inventory["entries"]}

    def test_workspace_inventory_exclusion_is_case_sensitive_when_requested(self):
        paths = self._inventory_paths_excluding_lowercase_target(case_insensitive=False)
        self.assertIn("Target", paths)
        self.assertIn("Target/source.rs", paths)

    def test_workspace_inventory_exclusion_ignores_case_when_requested(self):
        paths = self._inventory_paths_excluding_lowercase_target(case_insensitive=True)
        self.assertNotIn("Target", paths)
        self.assertNotIn("Target/source.rs", paths)

    def test_workspace_inventory_default_case_sensitivity_follows_platform(self):
        for platform_default in (False, True):
            with self.subTest(platform_default=platform_default), \
                    mock.patch.object(provenance, "_DEFAULT_CASE_INSENSITIVE_PATHS", platform_default):
                paths = self._inventory_paths_excluding_lowercase_target(case_insensitive=None)
                self.assertEqual("Target/source.rs" in paths, not platform_default)

    def test_workspace_inventory_exclusion_does_not_hide_differently_cased_directory(self):
        if provenance._DEFAULT_CASE_INSENSITIVE_PATHS:
            self.skipTest("the platform default matches paths case-insensitively")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "workspace"
            (root / "target").mkdir(parents=True)
            if (root / "Target").exists():
                self.skipTest("filesystem is case-insensitive")
            (root / "Target").mkdir()
            (root / "target" / "generated.bin").write_bytes(b"generated")
            (root / "Target" / "source.rs").write_bytes(b"source")
            inventory = agent.inventory_workspace(root, [{"path": "target", "applied": True}])
            paths = {item["relative_path"] for item in inventory["entries"]}
            self.assertNotIn("target/generated.bin", paths)
            self.assertIn("Target", paths)
            self.assertIn("Target/source.rs", paths)

    def test_workspace_inventory_exclusion_matches_whole_path_components(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "workspace"
            (root / "out" / "nested").mkdir(parents=True)
            (root / "out2").mkdir()
            (root / "out" / "nested" / "generated.bin").write_bytes(b"generated")
            (root / "out2" / "source.rs").write_bytes(b"source")
            for exclusion, hidden in (("out", True), ("out/nested", True), ("out/nes", False)):
                with self.subTest(exclusion=exclusion):
                    inventory = agent.inventory_workspace(
                        root, [{"path": exclusion, "applied": True}], case_insensitive=False,
                    )
                    paths = {item["relative_path"] for item in inventory["entries"]}
                    self.assertEqual("out/nested/generated.bin" not in paths, hidden)
                    self.assertIn("out2/source.rs", paths)

    def test_workspace_inventory_dot_exclusion_hides_every_entry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "workspace"
            root.mkdir()
            (root / "Cargo.toml").write_text("[package]\n", encoding="utf-8")
            inventory = agent.inventory_workspace(root, [{"path": ".", "applied": True}])
            self.assertEqual(inventory["entries"], [])

    def test_workspace_inventory_records_but_does_not_follow_external_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "workspace"
            root.mkdir()
            external = base / "external.txt"
            external.write_text("outside", encoding="utf-8")
            try:
                (root / "external-link").symlink_to(external)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is unavailable on this platform")
            inventory = agent.inventory_workspace(root, [])
            link = next(item for item in inventory["entries"] if item["relative_path"] == "external-link")
            self.assertEqual(link["file_type"], "symlink")
            self.assertEqual(link["target_scope"], "external_not_inventoried")
            self.assertNotIn("external.txt", [item["relative_path"] for item in inventory["entries"]])
            fingerprint = provenance._fingerprint_path(str(root / "external-link"), root, inventory)
            self.assertEqual(fingerprint["status"], "not_regular_file")
            self.assertIsNone(fingerprint["sha256"])
            self.assertIn("external_symlink_target_not_inventoried", [item["code"] for item in inventory["issues"]])

    def test_workspace_manifest_fingerprint_does_not_follow_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "workspace"
            external = base / "external"
            root.mkdir()
            external.mkdir()
            (external / "Cargo.toml").write_text("outside manifest", encoding="utf-8")
            try:
                (root / "linked").symlink_to(external, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlink creation is unavailable on this platform")
            inventory = provenance.inventory_workspace(root, [])
            fingerprint = provenance._fingerprint_path(str(root / "linked" / "Cargo.toml"), root, inventory)
            self.assertEqual(fingerprint["status"], "not_present")
            self.assertIsNone(fingerprint["sha256"])
            without_inventory = provenance._fingerprint_path(
                str(root / "linked" / "Cargo.toml"), root, None,
            )
            self.assertNotEqual(without_inventory["status"], "present")
            self.assertIsNone(without_inventory["sha256"])

    def _canonicalize_cargo_path_with_fake_windows_api(self, path, responses):
        import ctypes
        import ntpath
        from pathlib import PureWindowsPath

        calls = []

        def fake_get_long_path_name(candidate, buffer, buffer_length):
            calls.append(candidate)
            result = responses.get(candidate)
            if result is None:
                return 0
            buffer.value = result
            return len(result)

        fake_kernel32 = type("FakeKernel32", (), {})()
        fake_kernel32.GetLongPathNameW = fake_get_long_path_name
        fake_windows_os = type("WindowsOS", (), {"name": "nt", "path": ntpath})()

        with mock.patch.object(provenance, "os", fake_windows_os), \
                mock.patch.object(provenance, "Path", PureWindowsPath), \
                mock.patch.object(ctypes, "WinDLL", return_value=fake_kernel32, create=True):
            canonical = provenance._canonical_cargo_config_path(path)
        return canonical, calls

    def test_windows_cargo_config_path_uses_full_get_long_path_name_result(self):
        import ntpath
        from pathlib import PureWindowsPath

        requested = PureWindowsPath(r"C:\CargoTrail\short-parent\cargo-config.toml")
        absolute = PureWindowsPath(ntpath.abspath(str(requested)))
        expected = PureWindowsPath(r"C:\CargoTrail\Long Parent Name\Cargo-Config.toml")
        canonical, calls = self._canonicalize_cargo_path_with_fake_windows_api(
            requested, {str(absolute): str(expected)},
        )
        self.assertEqual(canonical, expected)
        self.assertEqual(calls, [str(absolute)])

    def test_windows_cargo_config_path_falls_back_to_long_parent_and_preserves_name(self):
        import ntpath
        from pathlib import PureWindowsPath

        requested = PureWindowsPath(r"C:\CargoTrail\short-parent\linked-config.toml")
        absolute = PureWindowsPath(ntpath.abspath(str(requested)))
        expected_parent = PureWindowsPath(r"C:\CargoTrail\Long Parent Name")
        canonical, calls = self._canonicalize_cargo_path_with_fake_windows_api(
            requested,
            {
                str(absolute): None,
                str(absolute.parent): str(expected_parent),
            },
        )
        self.assertEqual(canonical, expected_parent / absolute.name)
        self.assertEqual(calls, [str(absolute), str(absolute.parent)])

    @unittest.skipUnless(os.name == "nt", "Requires the native Windows GetLongPathNameW API")
    def test_windows_cargo_config_path_matches_native_get_long_path_name(self):
        import ctypes
        from ctypes import wintypes

        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "Mixed Case Cargo Config Directory"
            parent.mkdir()
            config_path = parent / "CargoConfig.TOML"
            config_path.write_text("[build]\ntarget = 'x86_64-pc-windows-msvc'\n", encoding="utf-8")

            # Windows resolves paths case-insensitively on the runner's default
            # filesystem. Supplying deliberately altered casing proves that the
            # canonicalizer returns the stored long-path spelling rather than
            # merely returning its input unchanged.
            requested_path = Path(str(config_path).swapcase())
            get_long_path_name = ctypes.WinDLL("kernel32", use_last_error=True).GetLongPathNameW
            get_long_path_name.argtypes = (wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD)
            get_long_path_name.restype = wintypes.DWORD
            buffer = ctypes.create_unicode_buffer(32768)
            length = get_long_path_name(str(requested_path), buffer, len(buffer))
            self.assertGreater(length, 0, "GetLongPathNameW failed for an existing Cargo config file")
            self.assertNotEqual(str(requested_path), buffer.value)

            canonical = provenance._canonical_cargo_config_path(requested_path)
            self.assertEqual(str(canonical), buffer.value)
            self.assertTrue(canonical.is_file())

    @unittest.skipIf(os.name == "nt", "POSIX parent-symlink canonicalization is not used on Windows")
    def test_cargo_config_path_resolves_symlinked_parent_but_not_final_component(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            real_parent = base / "real"
            real_parent.mkdir()
            alias_parent = base / "alias"
            try:
                alias_parent.symlink_to(real_parent, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("directory symlink creation is unavailable on this platform")
            config_path = alias_parent / "config.toml"
            config_path.write_text("[build]\ntarget = 'x'\n", encoding="utf-8")
            canonical = provenance._canonical_cargo_config_path(config_path)
            self.assertEqual(canonical, real_parent.resolve() / "config.toml")

            link_path = alias_parent / "linked-config.toml"
            link_path.symlink_to(config_path)
            canonical_link = provenance._canonical_cargo_config_path(link_path)
            self.assertEqual(canonical_link, real_parent.resolve() / "linked-config.toml")
            self.assertTrue(canonical_link.is_symlink())

    def test_cargo_config_layers_are_fingerprinted_and_secret_environment_is_redacted(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "workspace"
            cwd = root / "nested"
            cargo_home = base / "cargo-home"
            explicit = base / "explicit.toml"
            (cwd).mkdir(parents=True)
            (root / ".cargo").mkdir()
            (base / ".cargo").mkdir()
            (cargo_home).mkdir()
            (root / "Cargo.toml").write_text('[package]\nname="config-probe"\nversion="0.1.0"\n', encoding="utf-8")
            (root / ".cargo" / "config.toml").write_text(
                '[build]\ntarget="workspace-target"\ntarget-dir="configured-target"\n', encoding="utf-8",
            )
            (base / ".cargo" / "config").write_text('[build]\ntarget="parent-target"\n', encoding="utf-8")
            (cargo_home / "config.toml").write_text('[build]\ntarget="home-target"\n', encoding="utf-8")
            explicit.write_text(
                '[build]\ntarget="explicit-target"\nrustc-wrapper="sccache"\n',
                encoding="utf-8",
            )
            step = {
                "id": "config", "args": ["+stable", "check", "--config", str(explicit)], "cwd": "nested",
                "environment": {
                    "CARGO_BUILD_TARGET": "step-target",
                    "CARGO_BUILD_TARGET_DIR": "build-target-dir",
                    "CARGO_TARGET_DIR": "target-dir-lower-priority",
                    "CARGO_REGISTRY_TOKEN": "never-persist-this",
                    "CARGO_REGISTRIES_PRIVATE_TOKEN": "dynamic-registry-secret",
                    "CARGO_REGISTRIES_PRIVATE_INDEX": "sparse+https://registry.invalid/",
                    "CARGO_REGISTRIES_PRIVATE_URL": (
                        "sparse+https://registry-user:registry-password@registry.invalid/index"
                        "?token=query-token&channel=stable"
                    ),
                    "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER": "lld-link",
                    "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS": "-C opt-level=2",
                    "CARGO_PROFILE_RELEASE_LTO": "thin",
                    "CARGO_RESOLVER_LOCKFILE_PATH": "custom.lock",
                    "CARGO_BUILD_BUILD_DIR": "build-output",
                    "RUSTC_BOOTSTRAP": "1",
                },
                "unset_environment": [],
            }
            execution = {"environment": {}, "unset_environment": []}
            base_env = {"PATH": os.environ.get("PATH", ""), "CARGO_HOME": str(cargo_home)}
            probe_commands = []

            def fake_probe(name, command, probe_cwd, env, keep_stdout=True, include_raw_stdout=False, **kwargs):
                probe_commands.append((name, list(command)))
                if name == "cargo_metadata":
                    configured_target = env.get("CARGO_TARGET_DIR") or env.get("CARGO_BUILD_TARGET_DIR") or "target"
                    resolved_target = Path(configured_target)
                    if not resolved_target.is_absolute():
                        resolved_target = probe_cwd / resolved_target
                    raw = json.dumps({"workspace_root": str(root), "target_directory": str(resolved_target.resolve())}).encode()
                    return {"name": name, "status": "succeeded", "exit_code": 0, "stdout_sha256": "metadata",
                            "_raw_stdout": raw}
                excerpt = "release: 1.0.0\nhost: fake-host\n" if name in ("cargo_version", "rustc_version") else "stable-x86_64\n"
                return {"name": name, "status": "succeeded", "exit_code": 0, "stdout_excerpt": excerpt}

            with mock.patch.object(provenance, "run_probe", side_effect=fake_probe):
                record, _target_dir, unreadable = agent.collect_step_provenance(
                    "cargo", step, root, base_env, execution, agent.prepare_step_environment, agent.resolve_cwd,
                )
            self.assertEqual(unreadable, [])
            files = record["cargo_configuration"]["files"]
            explicit_record = next(item for item in files if item["path"] == str(explicit.resolve()))
            self.assertEqual(explicit_record["source"], "explicit_--config_file")
            paths = {item["path"] for item in files}
            self.assertIn(str((root / ".cargo" / "config.toml").resolve()), paths)
            self.assertIn(str((base / ".cargo" / "config").resolve()), paths)
            self.assertIn(str((cargo_home / "config.toml").resolve()), paths)
            selected_build_target = record["target"]["selected_build_target"]
            self.assertEqual(selected_build_target["value"], "explicit-target")
            self.assertEqual(selected_build_target["source"], "explicit_--config_file")
            self.assertEqual(selected_build_target["status"], "resolved")
            self.assertEqual(record["output"]["target_directory"]["source"], "CARGO_TARGET_DIR")
            self.assertEqual(record["output"]["target_directory"]["path"], str((root / "nested" / "target-dir-lower-priority").resolve()))
            self.assertEqual(record["output"]["build_directory"]["source"], "CARGO_BUILD_BUILD_DIR")
            self.assertEqual(record["output"]["build_directory"]["path"], str((root / "nested" / "build-output").resolve()))
            metadata_argv = next(command for name, command in probe_commands if name == "cargo_metadata")
            self.assertIn("--config", metadata_argv)
            self.assertIn(str(explicit), metadata_argv)
            cargo_version_argv = next(command for name, command in probe_commands if name == "cargo_version")
            self.assertEqual(cargo_version_argv[:3], ["cargo", "+stable", "-Vv"])
            self.assertEqual(record["toolchain"]["explicit_selector"], "stable")
            self.assertEqual(record["rustc"]["wrapper"], "sccache")
            self.assertEqual(record["rustc"]["selection_certainty"], "inferred_with_wrapper")
            environment_values = record["cargo_configuration"]["environment"]["values"]
            for name, expected in {
                "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER": "lld-link",
                "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS": "-C opt-level=2",
                "CARGO_PROFILE_RELEASE_LTO": "thin",
                "CARGO_RESOLVER_LOCKFILE_PATH": "custom.lock",
                "CARGO_BUILD_BUILD_DIR": "build-output",
                "CARGO_REGISTRIES_PRIVATE_INDEX": "sparse+https://registry.invalid/",
                "CARGO_REGISTRIES_PRIVATE_URL": (
                    "sparse+https://<REDACTED>@registry.invalid/index?token=%3CREDACTED%3E&channel=stable"
                ),
                "RUSTC_BOOTSTRAP": "1",
            }.items():
                self.assertEqual(environment_values[name], expected)
            self.assertEqual(environment_values["CARGO_REGISTRY_TOKEN"], "<REDACTED>")
            self.assertEqual(environment_values["CARGO_REGISTRIES_PRIVATE_TOKEN"], "<REDACTED>")
            encoded = json.dumps(record)
            self.assertNotIn("never-persist-this", encoded)
            self.assertNotIn(agent.provenance_sha256_bytes(b"never-persist-this"), encoded)
            self.assertNotIn("dynamic-registry-secret", encoded)
            self.assertNotIn(agent.provenance_sha256_bytes(b"dynamic-registry-secret"), encoded)
            for secret_value in ("registry-user:registry-password", "registry-password", "query-token"):
                self.assertNotIn(secret_value, encoded)
            registry_value = (
                "sparse+https://registry-user:registry-password@registry.invalid/index"
                "?token=query-token&channel=stable"
            )
            self.assertNotIn(agent.provenance_sha256_bytes(registry_value.encode()), encoded)
            self.assertEqual(record["cargo_configuration"]["environment"]["values"]["CARGO_REGISTRY_TOKEN"], "<REDACTED>")

    def test_cargo_config_includes_are_recursively_fingerprinted_and_issues_are_visible(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "workspace"
            config_dir = root / ".cargo"
            nested = config_dir / "nested"
            nested.mkdir(parents=True)
            cargo_home = base / "cargo-home"
            cargo_home.mkdir()
            (root / "Cargo.toml").write_text('[package]\nname="include-probe"\nversion="0.1.0"\n', encoding="utf-8")
            (config_dir / "config.toml").write_text(
                'include = ["one.toml", { path = "optional-missing.toml", optional = true }, '
                '{ path = "required-missing.toml", optional = false }, "two.toml", "credentials.toml"]\n',
                encoding="utf-8",
            )
            (config_dir / "one.toml").write_text('include = "nested/leaf.toml"\n', encoding="utf-8")
            leaf = nested / "leaf.toml"
            leaf.write_text('include = "../config.toml"\n[build]\ntarget-dir = "target-a"\n', encoding="utf-8")
            (config_dir / "two.toml").write_text('include = "one.toml"\n', encoding="utf-8")
            (config_dir / "credentials.toml").write_text('token = "include-file-secret-value"\n', encoding="utf-8")

            records = provenance._cargo_config_files(root, {"CARGO_HOME": str(cargo_home)}, [])
            by_name = {Path(item["path"]).name: item for item in records}
            self.assertIn(str((config_dir / "one.toml").resolve()), {item["path"] for item in records})
            self.assertIn(str(leaf.resolve()), {item["path"] for item in records})
            self.assertEqual(sum(item["path"] == str((config_dir / "one.toml").resolve()) for item in records), 1)
            self.assertEqual(by_name["optional-missing.toml"]["status"], "not_present_optional")
            self.assertEqual(by_name["required-missing.toml"]["status"], "not_present_required")
            self.assertEqual(by_name["credentials.toml"]["status"], "fingerprinted")
            self.assertEqual(by_name["credentials.toml"]["content_parse_status"], "skipped_sensitive_file")
            issues = [issue["code"] for item in records for issue in item.get("_include_issues", [])]
            self.assertIn("cargo_config_include_cycle", issues)
            self.assertIn("cargo_config_include_required_file_missing", issues)
            self.assertIn("cargo_config_sensitive_include_not_parsed", issues)
            before_digest = by_name["leaf.toml"]["sha256"]
            leaf.write_text('include = "../config.toml"\n[build]\ntarget-dir = "target-b"\n', encoding="utf-8")
            changed = provenance._cargo_config_files(root, {"CARGO_HOME": str(cargo_home)}, [])
            changed_leaf = next(item for item in changed if item["path"] == str(leaf.resolve()))
            self.assertNotEqual(before_digest, changed_leaf["sha256"])
            step_record = {
                "cwd": str(root),
                "cargo_metadata_probe": {"argv": ["cargo", "metadata"]},
                "cargo_configuration": {
                    "files": [{key: value for key, value in item.items() if not key.startswith("_")} for item in records],
                    "cargo_home_search_path": str(cargo_home.resolve()),
                    "cargo_home_source": "CARGO_HOME",
                    "include_issues": [issue for item in records for issue in item.get("_include_issues", [])],
                },
            }
            refresh_issues = provenance.refresh_step_cargo_configuration(step_record)
            refreshed_leaf = next(
                item for item in step_record["cargo_configuration"]["files"] if item["path"] == str(leaf.resolve())
            )
            self.assertNotEqual(refreshed_leaf["before"]["sha256"], refreshed_leaf["after"]["sha256"])
            self.assertEqual(refreshed_leaf["change_status"], "changed")
            self.assertIn("cargo_configuration_changed_during_agent_run", [item["code"] for item in refresh_issues])
            encoded = json.dumps([
                {key: value for key, value in item.items() if not key.startswith("_")}
                for item in records
            ])
            self.assertNotIn("include-file-secret-value", encoded)

    def test_cargo_config_effective_precedence_and_include_merge_order(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "workspace"
            nested = root / "member"
            cargo_home = base / "cargo-home"
            (root / ".cargo").mkdir(parents=True)
            (nested / ".cargo").mkdir(parents=True)
            cargo_home.mkdir()
            (root / "Cargo.toml").write_text('[workspace]\nmembers=["member"]\n', encoding="utf-8")
            (nested / "Cargo.toml").write_text('[package]\nname="member"\nversion="0.1.0"\n', encoding="utf-8")
            (cargo_home / "config.toml").write_text('[build]\nrustc="home-rustc"\n', encoding="utf-8")
            (root / ".cargo" / "config").write_text(
                'include = ["first.toml", "second.toml"]\n[build]\ntarget="root-target"\ntarget-dir="root-target-dir"\nbuild-dir="root-build"\n',
                encoding="utf-8",
            )
            (root / ".cargo" / "config.toml").write_text('[build]\ntarget-dir="inactive-target"\n', encoding="utf-8")
            (root / ".cargo" / "first.toml").write_text('[build]\nrustc="first-rustc"\nrustc-wrapper="first-wrapper"\n', encoding="utf-8")
            (root / ".cargo" / "second.toml").write_text('[build]\nrustc="second-rustc"\nrustc-wrapper="second-wrapper"\n', encoding="utf-8")
            (nested / ".cargo" / "config.toml").write_text(
                '[build]\ntarget-dir="near-target"\nbuild-dir="near-build"\n', encoding="utf-8",
            )
            env = {"CARGO_HOME": str(cargo_home), "CARGO_BUILD_TARGET": "environment-target"}

            records, files, inline, discoveries = provenance._collect_cargo_configuration(
                nested, env, [], include_supported=True, include_active=True,
            )
            settings, issues = provenance._resolve_cargo_config_settings(files, inline, env, nested)
            self.assertEqual(issues, [])
            self.assertEqual(settings["build.target-dir"]["value"], "near-target")
            self.assertEqual(settings["build.build-dir"]["value"], "near-build")
            self.assertEqual(settings["build.rustc"]["value"], "second-rustc")
            self.assertEqual(settings["build.rustc-wrapper"]["value"], "second-wrapper")
            self.assertEqual(settings["build.target"]["value"], "environment-target")
            self.assertTrue(any(item.get("configuration_role") == "inactive_legacy_extension" for item in records))
            self.assertEqual([item["path"] for item in discoveries], [
                str((root / ".cargo" / "first.toml").resolve()),
                str((root / ".cargo" / "second.toml").resolve()),
            ])

            (root / ".cargo" / "config").write_text(
                'include = ["first.toml", "second.toml"]\n[build]\ntarget="root-target"\ntarget-dir="root-target-dir"\nbuild-dir="root-build"\nrustc="root-rustc"\n',
                encoding="utf-8",
            )
            _rows, own_files, own_inline, _edges = provenance._collect_cargo_configuration(
                nested, env, [], include_supported=True, include_active=True,
            )
            own_settings, _issues = provenance._resolve_cargo_config_settings(own_files, own_inline, env, nested)
            self.assertEqual(own_settings["build.rustc"]["value"], "root-rustc")

            env_with_build_dir = dict(env, CARGO_BUILD_BUILD_DIR="environment-build")
            _rows, env_build_files, env_build_inline, _edges = provenance._collect_cargo_configuration(
                nested, env_with_build_dir, [], include_supported=True, include_active=True,
            )
            env_build_settings, _issues = provenance._resolve_cargo_config_settings(
                env_build_files, env_build_inline, env_with_build_dir, nested,
            )
            self.assertEqual(env_build_settings["build.build-dir"]["value"], "environment-build")
            self.assertEqual(env_build_settings["build.build-dir"]["source"], "CARGO_BUILD_BUILD_DIR")

            cli_file = base / "cli.toml"
            cli_file.write_text('[build]\ntarget="file-cli-target"\nrustc="file-cli-rustc"\nrustc-wrapper="file-cli-wrapper"\nbuild-dir="file-cli-build"\n', encoding="utf-8")
            _rows, cli_files, cli_inline, _edges = provenance._collect_cargo_configuration(
                nested, env_with_build_dir, ["check", "--config", str(cli_file)], include_supported=True, include_active=True,
            )
            cli_settings, _issues = provenance._resolve_cargo_config_settings(cli_files, cli_inline, env_with_build_dir, nested)
            self.assertEqual(cli_settings["build.target"]["value"], "file-cli-target")
            self.assertEqual(cli_settings["build.rustc"]["value"], "file-cli-rustc")
            self.assertEqual(cli_settings["build.rustc-wrapper"]["value"], "file-cli-wrapper")
            self.assertEqual(cli_settings["build.build-dir"]["value"], "file-cli-build")

            _rows, inline_files, inline_values, _edges = provenance._collect_cargo_configuration(
                nested, dict(env_with_build_dir, RUSTC="environment-rustc", RUSTC_WRAPPER="environment-wrapper"),
                [
                    "check", "--config", 'build.target="inline-cli-target"',
                    "--config", 'build.build-dir="inline-build"',
                    "--config", 'build.rustc="inline-rustc"',
                    "--config", 'build.rustc-wrapper="inline-wrapper"',
                ],
                include_supported=True, include_active=True,
            )
            inline_env = dict(env_with_build_dir, RUSTC="environment-rustc", RUSTC_WRAPPER="environment-wrapper")
            inline_settings, _issues = provenance._resolve_cargo_config_settings(inline_files, inline_values, inline_env, nested)
            self.assertEqual(inline_settings["build.target"]["value"], "inline-cli-target")
            self.assertEqual(inline_settings["build.build-dir"]["value"], "inline-build")
            self.assertEqual(inline_settings["build.rustc"]["value"], "inline-rustc")
            self.assertEqual(inline_settings["build.rustc-wrapper"]["value"], "inline-wrapper")

            no_env = {"CARGO_HOME": str(cargo_home)}
            home_rows, home_files, home_inline, _edges = provenance._collect_cargo_configuration(
                nested, no_env, [], include_supported=True, include_active=True,
            )
            home_settings, _issues = provenance._resolve_cargo_config_settings(home_files, home_inline, no_env, nested)
            self.assertEqual(home_settings["build.rustc"]["value"], "root-rustc")
            self.assertEqual(home_settings["build.rustc"]["source"], "cwd_or_parent")
            self.assertIn(str((cargo_home / "config.toml").resolve()), {item["path"] for item in home_rows})

    def test_cargo_config_include_array_tables_and_feature_availability(self):
        content = '''[[include]]
path = "first.toml"

[[include]]
path = "missing.toml"
optional = true
'''
        specs, issues = provenance._top_level_include_specs(content)
        self.assertEqual(issues, [])
        self.assertEqual(specs, [
            {"path": "first.toml", "optional": False},
            {"path": "missing.toml", "optional": True},
        ])
        legacy = provenance._cargo_config_include_capability(
            {"parsed": {"release": "1.91.1", "channel": "stable"}}, [], {},
        )
        self.assertEqual((legacy["supported"], legacy["active"]), (False, False))
        stable_193 = provenance._cargo_config_include_capability(
            {"parsed": {"release": "1.93.0", "channel": "stable"}}, [], {},
        )
        self.assertEqual((stable_193["supported"], stable_193["active"]), (False, False))
        stable_193_config = provenance._cargo_config_include_capability(
            {"parsed": {"release": "1.93.0", "channel": "stable"}}, [],
            {"unstable.config-include": {"status": "resolved", "value": True}},
        )
        self.assertEqual((stable_193_config["supported"], stable_193_config["active"]), (False, False))
        nightly_on = provenance._cargo_config_include_capability(
            {"parsed": {"release": "1.93.0-nightly", "channel": "nightly"}},
            ["check", "-Zconfig-include"], {},
        )
        self.assertEqual((nightly_on["supported"], nightly_on["active"]), (True, True))
        nightly_off = provenance._cargo_config_include_capability(
            {"parsed": {"release": "1.93.0-nightly", "channel": "nightly"}}, [], {},
        )
        self.assertEqual((nightly_off["supported"], nightly_off["active"]), (True, False))
        nightly_config_on = provenance._cargo_config_include_capability(
            {"parsed": {"release": "1.93.0-nightly", "channel": "nightly"}}, [],
            {"unstable.config-include": {"status": "resolved", "value": True}},
        )
        self.assertEqual((nightly_config_on["supported"], nightly_config_on["active"]), (True, True))
        stable_194 = provenance._cargo_config_include_capability(
            {"parsed": {"release": "1.94.0", "channel": "stable"}}, [], {},
        )
        self.assertEqual((stable_194["supported"], stable_194["active"]), (True, True))
        self.assertEqual(stable_194["stable_since"], "1.94.0")
        stable_194_z_unnecessary = provenance._cargo_config_include_capability(
            {"parsed": {"release": "1.94.0", "channel": "stable"}},
            ["check", "-Zconfig-include"], {},
        )
        self.assertEqual((stable_194_z_unnecessary["supported"], stable_194_z_unnecessary["active"]), (True, True))
        beta_before_stabilization = provenance._cargo_config_include_capability(
            {"parsed": {"release": "1.94.0-beta.1", "channel": "beta", "commit_date": "2025-12-11"}},
            [], {},
        )
        self.assertEqual((beta_before_stabilization["support_status"], beta_before_stabilization["active"]), ("unsupported", False))
        beta_194_release_branch = provenance._cargo_config_include_capability(
            {"parsed": {"release": "1.94.0-beta.1", "channel": "beta", "commit_date": "2026-01-22"}},
            [], {},
        )
        self.assertEqual((beta_194_release_branch["supported"], beta_194_release_branch["active"]), (True, True))
        beta_without_commit_date = provenance._cargo_config_include_capability(
            {"parsed": {"release": "1.94.0-beta.1", "channel": "beta"}}, [], {},
        )
        self.assertEqual((beta_without_commit_date["support_status"], beta_without_commit_date["active"]), ("unknown", None))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config_dir = root / ".cargo"
            config_dir.mkdir()
            (root / "Cargo.toml").write_text('[package]\nname="include"\nversion="0.1.0"\n', encoding="utf-8")
            (config_dir / "config.toml").write_text(
                '[[include]]\npath="base.toml"\n\n[[include]]\npath="optional.toml"\noptional=true\n',
                encoding="utf-8",
            )
            (config_dir / "base.toml").write_text('include = "nested.toml"\n', encoding="utf-8")
            nested = config_dir / "nested.toml"
            nested.write_text('[build]\ntarget-dir="from-nested"\n', encoding="utf-8")
            rows, layers, inline, edges = provenance._collect_cargo_configuration(
                root, {}, [], include_supported=stable_194["supported"], include_active=stable_194["active"],
            )
            effective, _issues = provenance._resolve_cargo_config_settings(layers, inline, {}, root)
            by_path = {item["path"]: item for item in rows}
            self.assertEqual(by_path[str((config_dir / "base.toml").resolve())]["status"], "fingerprinted")
            self.assertEqual(by_path[str(nested.resolve())]["status"], "fingerprinted")
            self.assertEqual(effective["build.target-dir"]["value"], "from-nested")
            self.assertTrue(all(edge["supported"] and edge["active"] for edge in edges))
            self.assertTrue(all(edge["fingerprinted"] for edge in edges if not edge["optional"]))
            nested.write_text('[build]\ntarget-dir="changed-nested"\n', encoding="utf-8")
            changed_rows = provenance._cargo_config_files(
                root, {}, [], stable_194["supported"], stable_194["active"],
            )
            changed = next(item for item in changed_rows if item["path"] == str(nested.resolve()))
            self.assertNotEqual(by_path[str(nested.resolve())]["sha256"], changed["sha256"])

    def test_build_directory_templates_require_confident_expansion(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "workspace"
            cwd = root / "member"
            cargo_home = base / "cargo-home"
            cwd.mkdir(parents=True)
            cargo_home.mkdir()
            workspace_setting = {
                "value": "{workspace-root}/build-cache", "source": "cargo_--config", "status": "resolved",
            }
            resolved = provenance._config_setting_path(workspace_setting, cwd, root, cargo_home)
            self.assertEqual(Path(resolved["path"]), (root / "build-cache").resolve())
            cache_setting = {
                "value": "{cargo-cache-home}/build-cache", "source": "cargo_--config", "status": "resolved",
            }
            cached = provenance._config_setting_path(cache_setting, cwd, root, cargo_home)
            self.assertEqual(Path(cached["path"]), (cargo_home / "build-cache").resolve())
            hash_setting = {
                "value": "{workspace-root}/{workspace-path-hash}", "source": "cargo_--config", "status": "resolved",
            }
            self.assertEqual(provenance._config_setting_path(hash_setting, cwd, root, cargo_home)["status"], "unresolved")
            metadata_path = root / ".cargo-cache" / "hash-from-cargo"
            hashed = provenance._config_setting_path(hash_setting, cwd, root, cargo_home, metadata_path)
            self.assertEqual(Path(hashed["path"]), metadata_path)

    def test_step_manifest_selection_and_target_directories_follow_each_step_context(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "workspace"
            nested = root / "nested"
            member = root / "member"
            nested.mkdir(parents=True)
            member.mkdir()
            cargo_home = base / "cargo-home"
            cargo_home.mkdir()
            manifest = member / "Cargo.toml"
            (root / "Cargo.toml").write_text('[workspace]\nmembers=["member"]\n', encoding="utf-8")
            manifest.write_text('[package]\nname="member-probe"\nversion="0.1.0"\n', encoding="utf-8")
            steps = [
                {
                    "id": "space-manifest", "args": ["check", "--manifest-path", "../member/Cargo.toml", "--target-dir", "target-a"],
                    "cwd": "nested", "environment": {"CARGO_PROFILE_RELEASE_LTO": "thin"}, "unset_environment": [],
                },
                {
                    "id": "equals-manifest", "args": ["check", "--manifest-path=member/Cargo.toml"],
                    "cwd": ".", "environment": {
                        "CARGO_BUILD_TARGET_DIR": "target-b", "CARGO_TARGET_DIR": "lower-priority",
                        "CARGO_PROFILE_RELEASE_LTO": "fat", "CARGO_REGISTRIES_PRIVATE_TOKEN": "step-two-secret",
                    },
                    "unset_environment": [],
                },
                {
                    "id": "cargo-target-dir", "args": ["check"], "cwd": ".",
                    "environment": {"CARGO_TARGET_DIR": "target-c", "CARGO_RESOLVER_LOCKFILE_PATH": "lock-c"},
                    "unset_environment": [],
                },
                {
                    "id": "cargo-build-target-dir", "args": ["check"], "cwd": ".",
                    "environment": {"CARGO_BUILD_TARGET_DIR": "target-d", "CARGO_RESOLVER_LOCKFILE_PATH": "lock-d"},
                    "unset_environment": [],
                },
            ]
            execution = {"environment": {}, "unset_environment": []}
            base_env = {"PATH": os.environ.get("PATH", ""), "CARGO_HOME": str(cargo_home)}
            captured = {}

            def fake_probe(name, command, probe_cwd, env, keep_stdout=True, include_raw_stdout=False, **kwargs):
                if name == "cargo_metadata":
                    configured_target = env.get("CARGO_TARGET_DIR") or env.get("CARGO_BUILD_TARGET_DIR") or "metadata-target"
                    captured[configured_target] = list(command)
                    target = Path(configured_target)
                    if not target.is_absolute():
                        target = probe_cwd / target
                    raw = json.dumps({"workspace_root": str(root), "target_directory": str(target.resolve())}).encode()
                    return {"name": name, "status": "succeeded", "exit_code": 0, "stdout_sha256": "metadata",
                            "argv": list(command), "_raw_stdout": raw}
                excerpt = "release: 1.0.0\nhost: fake-host\n" if name in ("cargo_version", "rustc_version") else "stable-x86_64\n"
                return {"name": name, "status": "succeeded", "exit_code": 0, "stdout_excerpt": excerpt}

            observed = {}
            with mock.patch.object(provenance, "run_probe", side_effect=fake_probe):
                for step in steps:
                    record, target_dir, _unreadable = agent.collect_step_provenance(
                        "cargo", step, root, base_env, execution, agent.prepare_step_environment, agent.resolve_cwd,
                    )
                    observed[step["id"]] = (record, target_dir)
            for step_id in ("space-manifest", "equals-manifest"):
                record, _target = observed[step_id]
                self.assertEqual(record["manifest"]["selected_manifest_path"], str(manifest.resolve()))
                command = record["cargo_metadata_probe"]["argv"]
                self.assertIn("--manifest-path", command)
                self.assertIn(str(manifest.resolve()), command)
                self.assertNotIn("--target-dir", command)
            self.assertEqual(observed["space-manifest"][1], (root / "nested" / "target-a").resolve())
            self.assertEqual(observed["equals-manifest"][1], (root / "lower-priority").resolve())
            self.assertEqual(observed["cargo-target-dir"][1], (root / "target-c").resolve())
            self.assertEqual(observed["cargo-build-target-dir"][1], (root / "target-d").resolve())
            self.assertEqual(len({str(pair[1]) for pair in observed.values()}), 4)
            env_values = {key: pair[0]["cargo_configuration"]["environment"]["values"]
                          for key, pair in observed.items()}
            self.assertEqual(env_values["space-manifest"]["CARGO_PROFILE_RELEASE_LTO"], "thin")
            self.assertEqual(env_values["equals-manifest"]["CARGO_PROFILE_RELEASE_LTO"], "fat")
            self.assertEqual(env_values["cargo-target-dir"]["CARGO_RESOLVER_LOCKFILE_PATH"], "lock-c")
            self.assertEqual(env_values["cargo-build-target-dir"]["CARGO_RESOLVER_LOCKFILE_PATH"], "lock-d")
            self.assertEqual(env_values["equals-manifest"]["CARGO_REGISTRIES_PRIVATE_TOKEN"], "<REDACTED>")
            self.assertNotIn("CARGO_REGISTRIES_PRIVATE_TOKEN", env_values["space-manifest"])
            self.assertNotIn("step-two-secret", json.dumps([pair[0] for pair in observed.values()]))
            self.assertNotIn(agent.provenance_sha256_bytes(b"step-two-secret"), json.dumps([pair[0] for pair in observed.values()]))
            fingerprints = agent.step_manifest_fingerprints(root, {
                key: {"selected_manifest_path": str(manifest), "lockfile_path": str(root / "Cargo.lock")}
                for key in observed
            }, None, None)
            for item in fingerprints.values():
                self.assertEqual(item["manifest"]["before"]["sha256"], agent.provenance_sha256_bytes(manifest.read_bytes()))
                self.assertEqual(item["manifest"]["path"], str(manifest))

    def test_inventory_hashing_uses_bounded_blocks_and_omits_unstable_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            content = b"abc123" * (provenance.HASH_BLOCK_SIZE // 6 + 10)
            path = root / "large.bin"
            path.write_bytes(content)
            digest, size, stable = provenance._hash_regular_file(path, path.stat())
            self.assertTrue(stable)
            self.assertEqual(size, len(content))
            self.assertEqual(digest, agent.provenance_sha256_bytes(content))
            original_same_file_state = artifact_inventory._same_file_state

            def changed_file_state(left, right):
                if stat.S_ISREG(left.st_mode):
                    return False
                return original_same_file_state(left, right)

            with mock.patch.object(artifact_inventory, "_same_file_state", side_effect=changed_file_state):
                inventory = agent.inventory_workspace(root, [])
            entry = next(item for item in inventory["entries"] if item["relative_path"] == "large.bin")
            self.assertEqual(entry["inclusion_status"], "unstable")
            self.assertIsNone(entry["sha256"])
            self.assertIsNotNone(entry["observed_sha256"])

    def test_semantic_config_fingerprint_normalizes_format_and_defaults(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            compact = base / "compact.json"
            expanded = base / "expanded.json"
            compact.write_text(
                '{"schema_version":1,"workspace_root":".","execution":{"environment":{"API_TOKEN":"first-secret"}},"steps":[{"id":"check","args":["check"],"parser":"text","environment":{"PASSWORD":"second-secret"}}]}',
                encoding="utf-8",
            )
            expanded.write_text(json.dumps({
                "schema_version": 1,
                "workspace_root": ".",
                "execution": {
                    "cargo_executable": "cargo", "continue_on_error": True,
                    "default_timeout_seconds": None, "termination_grace_seconds": 5,
                    "environment": {"API_TOKEN": "first-secret"}, "unset_environment": [],
                },
                "steps": [{
                    "id": "check", "args": ["check"], "parser": "text", "enabled": True,
                    "cwd": ".", "timeout_seconds": None, "environment": {"PASSWORD": "second-secret"},
                    "unset_environment": [], "redact_arg_indexes": [],
                }],
            }, indent=4), encoding="utf-8")
            first, raw_first, _ = agent.load_config(compact)
            second, raw_second, _ = agent.load_config(expanded)
            self.assertNotEqual(agent.provenance_sha256_bytes(raw_first), agent.provenance_sha256_bytes(raw_second))
            semantic_first = agent.provenance_sha256_bytes(agent.canonical_json_bytes(agent.redacted_config(first)))
            semantic_second = agent.provenance_sha256_bytes(agent.canonical_json_bytes(agent.redacted_config(second)))
            self.assertEqual(semantic_first, semantic_second)
            encoded = json.dumps(agent.redacted_config(second))
            self.assertNotIn("first-secret", encoded)
            self.assertNotIn("second-secret", encoded)



class FileDescriptorCleanupTests(unittest.TestCase):
    def _track_open_regular_descriptors(self, expected_size: int):
        original_fstat = os.fstat
        opened_fds = set()

        def tracked_fstat(fd):
            details = original_fstat(fd)
            if stat.S_ISREG(details.st_mode) and details.st_size == expected_size:
                opened_fds.add(fd)
            return details

        return tracked_fstat, opened_fds

    def _assert_closed(self, fd: int):
        with self.assertRaises(OSError):
            os.fstat(fd)

    def _failing_parent_context(self):
        original_secure_directory = artifact_inventory.secure_directory

        @contextlib.contextmanager
        def fail_after_yield(path, verify_names=True):
            with original_secure_directory(path, verify_names=verify_names) as held:
                yield held
                raise artifact_inventory.FileVerificationError("injected_parent_reverification_failure", path)

        return fail_after_yield

    def test_open_file_closes_leaf_fd_when_parent_reverification_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "input.bin"
            target.write_bytes(b"payload")
            tracked_fstat, opened_fds = self._track_open_regular_descriptors(len(b"payload"))

            with mock.patch.object(artifact_inventory, "secure_directory", side_effect=self._failing_parent_context()):
                with mock.patch.object(artifact_inventory.os, "fstat", side_effect=tracked_fstat):
                    with self.assertRaises(artifact_inventory.FileVerificationError):
                        artifact_inventory.open_file_no_follow(target)

            self.assertTrue(opened_fds)
            for fd in opened_fds:
                self._assert_closed(fd)

    def test_regular_writer_closes_leaf_fd_when_parent_reverification_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "output.bin"
            target.write_bytes(b"old-content")
            tracked_fstat, opened_fds = self._track_open_regular_descriptors(len(b"old-content"))

            with mock.patch.object(artifact_inventory, "secure_directory", side_effect=self._failing_parent_context()):
                with mock.patch.object(artifact_inventory.os, "fstat", side_effect=tracked_fstat):
                    with self.assertRaises(artifact_inventory.FileVerificationError):
                        artifact_inventory.open_regular_writer(target)

            self.assertTrue(opened_fds)
            for fd in opened_fds:
                self._assert_closed(fd)

    def test_regular_writer_closes_leaf_fd_when_truncate_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "output.bin"
            target.write_bytes(b"old-content")
            tracked_fstat, opened_fds = self._track_open_regular_descriptors(len(b"old-content"))

            with mock.patch.object(artifact_inventory.os, "fstat", side_effect=tracked_fstat):
                with mock.patch.object(artifact_inventory.os, "ftruncate", side_effect=OSError("injected truncate failure")):
                    with self.assertRaisesRegex(OSError, "injected truncate failure"):
                        artifact_inventory.open_regular_writer(target)

            self.assertTrue(opened_fds)
            for fd in opened_fds:
                self._assert_closed(fd)

    def test_secure_directory_closes_handle_once_after_identity_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            original_fstat = os.fstat
            original_close = os.close
            directory_fds = []
            close_counts = {}

            def tracked_fstat(fd):
                details = original_fstat(fd)
                if stat.S_ISDIR(details.st_mode):
                    directory_fds.append(fd)
                return details

            def tracked_close(fd):
                close_counts[fd] = close_counts.get(fd, 0) + 1
                return original_close(fd)

            with mock.patch.object(artifact_inventory.os, "fstat", side_effect=tracked_fstat):
                with mock.patch.object(artifact_inventory.os, "close", side_effect=tracked_close):
                    with mock.patch.object(artifact_inventory, "_cross_source_identity", return_value=False):
                        with self.assertRaises(artifact_inventory.FileVerificationError):
                            with artifact_inventory.secure_directory(directory, verify_names=False):
                                pass

            self.assertTrue(directory_fds)
            directory_fd = directory_fds[0]
            self.assertEqual(close_counts.get(directory_fd), 1)
            self._assert_closed(directory_fd)


class ExecutionProfileTests(unittest.TestCase):
    def base_config(self):
        return {
            "schema_version": 1,
            "workspace_root": ".",
            "execution": {},
            "steps": [{"id": "check", "args": ["check"], "parser": "text"}],
        }

    def load_config(self, directory: Path, source: dict, name: str = "pipeline.json"):
        path = directory / ("profile-{}-{}".format(uuid.uuid4().hex, name))
        path.write_text(json.dumps(source), encoding="utf-8")
        try:
            return agent.load_config(path)
        finally:
            path.unlink(missing_ok=True)

    def definition_digest(self, directory: Path, source: dict, name: str = "pipeline.json") -> str:
        config, _raw, _digest = self.load_config(directory, source, name)
        return agent.profile_definition_sha256(config)

    def clone(self, source: dict) -> dict:
        return json.loads(json.dumps(source))

    def test_config_byte_and_semantic_digest_contracts(self):
        directory = Path.cwd()
        compact = self.base_config()
        compact["execution"]["environment"] = {"PASSWORD": "first-secret"}
        loaded_compact, compact_raw, compact_byte_digest = self.load_config(
            directory, compact, "digest-compact.json",
        )
        pretty_path = directory / ("profile-{}-digest-pretty.json".format(uuid.uuid4().hex))
        pretty_path.write_text(json.dumps(compact, indent=2), encoding="utf-8")
        try:
            loaded_pretty, pretty_raw, pretty_byte_digest = agent.load_config(pretty_path)
        finally:
            pretty_path.unlink(missing_ok=True)

        self.assertNotEqual(compact_raw, pretty_raw)
        self.assertEqual(compact_byte_digest, agent.sha256_bytes(compact_raw))
        self.assertEqual(pretty_byte_digest, agent.sha256_bytes(pretty_raw))
        self.assertNotEqual(compact_byte_digest, pretty_byte_digest)
        compact_semantic = agent.sha256_bytes(
            agent.canonical_json_bytes(agent.redacted_config(loaded_compact))
        )
        pretty_semantic = agent.sha256_bytes(
            agent.canonical_json_bytes(agent.redacted_config(loaded_pretty))
        )
        self.assertEqual(compact_semantic, pretty_semantic)

        changed_secret = self.clone(compact)
        changed_secret["execution"]["environment"]["PASSWORD"] = "second-secret"
        loaded_secret, secret_raw, secret_byte_digest = self.load_config(
            directory, changed_secret, "digest-secret.json",
        )
        self.assertNotEqual(compact_raw, secret_raw)
        self.assertNotEqual(compact_byte_digest, secret_byte_digest)
        self.assertEqual(
            compact_semantic,
            agent.sha256_bytes(agent.canonical_json_bytes(agent.redacted_config(loaded_secret))),
        )

    def test_profile_validation_and_profile_free_compatibility(self):
        directory = Path.cwd()
        source = self.base_config()
        loaded, _raw, _digest = self.load_config(directory, source)
        self.assertNotIn("profile", loaded)
        self.assertEqual(agent.execution_profile_report(loaded), {"status": "not_declared"})
        self.assertEqual(agent.execution_profile_summary({"status": "not_declared"}), {"status": "not_declared"})

        source["profile"] = {
            "id": "rust.workspace-validation_v1",
            "version": 2,
            "description": "NUL-free description",
        }
        loaded, _raw, _digest = self.load_config(directory, source)
        self.assertEqual(loaded["profile"], source["profile"])

        invalid_profiles = [
                {},
                {"version": 1},
                {"id": "", "version": 1},
                {"id": "Uppercase", "version": 1},
                {"id": "has space", "version": 1},
                {"id": "../profile", "version": 1},
                {"id": "bad\\path", "version": 1},
                {"id": "a" * 65, "version": 1},
                {"id": "valid"},
                {"id": "valid", "version": "1"},
                {"id": "valid", "version": True},
                {"id": "valid", "version": 0},
                {"id": "valid", "version": -1},
                {"id": "valid", "version": 1, "description": 5},
                {"id": "valid", "version": 1, "description": "x\x00y"},
                {"id": "valid", "version": 1, "description": "x" * 513},
                {"id": "valid", "version": 1, "extra": "unknown"},
        ]
        for index, profile in enumerate(invalid_profiles):
            with self.subTest(profile=profile):
                invalid = self.base_config()
                invalid["profile"] = profile
                with self.assertRaises(agent.ConfigError):
                    self.load_config(directory, invalid, "invalid-{}.json".format(index))

    def test_profile_definition_canonicalization_defaults_and_exclusions(self):
        directory = Path.cwd()
        compact = self.base_config()
        compact["profile"] = {"id": "sample", "version": 1}
        compact["execution"] = {"environment": {"TOKEN": "first-secret"}}
        compact["steps"][0]["redact_arg_indexes"] = [1]
        compact["steps"][0]["args"] = ["check", "private-value"]
        loaded_compact, raw_compact, _ = self.load_config(directory, compact, "compact.json")

        explicit = {
            "steps": [{
                "redact_arg_indexes": [1],
                "unset_environment": [],
                "environment": {},
                "timeout_seconds": None,
                "cwd": ".",
                "parser": "text",
                "enabled": True,
                "args": ["check", "private-value"],
                "id": "check",
            }],
            "execution": {
                "unset_environment": [],
                "environment": {"TOKEN": "first-secret"},
                "termination_grace_seconds": 5,
                "default_timeout_seconds": None,
                "continue_on_error": True,
                "cargo_executable": "cargo",
            },
            "workspace_root": ".",
            "profile": {"version": 1, "id": "sample"},
            "schema_version": 1,
        }
        encoded_reordered = json.dumps(explicit, indent=3)
        expanded_path = directory / ("profile-{}-expanded.json".format(uuid.uuid4().hex))
        expanded_path.write_text(encoded_reordered, encoding="utf-8")
        try:
            loaded_expanded, raw_expanded, _ = agent.load_config(expanded_path)
        finally:
            expanded_path.unlink(missing_ok=True)
        self.assertNotEqual(raw_compact, raw_expanded)
        digest = agent.profile_definition_sha256(loaded_compact)
        self.assertEqual(digest, agent.profile_definition_sha256(loaded_expanded))

        variants = []
        for key, value in (("id", "another-name"), ("version", 3), ("description", "new description")):
            changed = self.clone(compact)
            changed["profile"][key] = value
            variants.append(changed)
        changed_root = self.clone(compact)
        changed_root["workspace_root"] = "elsewhere"
        variants.append(changed_root)
        for index, variant in enumerate(variants):
            self.assertEqual(
                digest,
                self.definition_digest(directory, variant, "excluded-{}.json".format(index)),
            )

        changed_secret = self.clone(compact)
        changed_secret["execution"]["environment"]["TOKEN"] = "second-secret"
        loaded_secret, raw_secret, _ = self.load_config(directory, changed_secret, "secret.json")
        self.assertNotEqual(agent.sha256_bytes(raw_compact), agent.sha256_bytes(raw_secret))
        self.assertEqual(digest, agent.profile_definition_sha256(loaded_secret))
        self.assertEqual(
            agent.redacted_config(loaded_compact)["execution"]["environment"],
            agent.redacted_config(loaded_secret)["execution"]["environment"],
        )
        serialized = json.dumps(agent.profile_definition(loaded_compact))
        self.assertNotIn("first-secret", serialized)
        self.assertNotIn("private-value", serialized)

    def test_profile_definition_changes_with_execution_definition(self):
        directory = Path.cwd()
        base = self.base_config()
        base["execution"]["environment"] = {"BUILD_MODE": "fast"}
        base["steps"].append({
            "id": "test", "args": ["test", "--message-format=json"],
            "parser": "cargo-json+libtest",
        })
        baseline = self.definition_digest(directory, base, "baseline.json")

        mutations = []
        changed = self.clone(base)
        changed["steps"][0]["args"].append("--locked")
        mutations.append(changed)
        changed = self.clone(base)
        changed["steps"].reverse()
        mutations.append(changed)
        changed = self.clone(base)
        changed["steps"][0]["enabled"] = False
        mutations.append(changed)
        changed = self.clone(base)
        changed["steps"][0] = {
            "id": "check", "args": ["check", "--message-format=json"], "parser": "cargo-json",
        }
        mutations.append(changed)
        changed = self.clone(base)
        changed["steps"][0]["timeout_seconds"] = 10
        mutations.append(changed)
        changed = self.clone(base)
        changed["steps"][1]["evidence_requirements"] = {"allow_zero_tests": True}
        mutations.append(changed)
        changed = self.clone(base)
        changed["execution"]["cargo_executable"] = "cargo-custom"
        mutations.append(changed)
        changed = self.clone(base)
        changed["steps"].append({"id": "fmt", "args": ["fmt"], "parser": "text"})
        mutations.append(changed)
        changed = self.clone(base)
        changed["steps"].pop()
        mutations.append(changed)
        changed = self.clone(base)
        changed["execution"]["environment"] = {"BUILD_TARGET": "fast"}
        mutations.append(changed)

        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assertNotEqual(
                    baseline,
                    self.definition_digest(directory, mutation, "changed-{}.json".format(index)),
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
