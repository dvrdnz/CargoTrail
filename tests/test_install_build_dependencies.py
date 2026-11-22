# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install_build_dependencies.py"
SPEC = importlib.util.spec_from_file_location("install_build_dependencies", SCRIPT)
install_build_dependencies = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(install_build_dependencies)


class InstallEnvironmentTests(unittest.TestCase):
    def test_android_appends_option_to_existing_cflags(self):
        original_flags = "-O2 -Wall"

        with mock.patch.dict(os.environ, {"CFLAGS": original_flags}, clear=True), \
                mock.patch.object(install_build_dependencies.sys, "platform", "android"):
            environment = install_build_dependencies.install_environment()

            self.assertEqual(
                environment["CFLAGS"],
                original_flags + " " + install_build_dependencies.TERMUX_CFLAGS_OPTION,
            )
            self.assertEqual(os.environ["CFLAGS"], original_flags)

    def test_android_sets_cflags_when_missing(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(install_build_dependencies.sys, "platform", "android"):
            environment = install_build_dependencies.install_environment()

            self.assertEqual(
                environment["CFLAGS"],
                install_build_dependencies.TERMUX_CFLAGS_OPTION,
            )
            self.assertNotIn("CFLAGS", os.environ)

    def test_non_android_preserves_existing_cflags(self):
        original_flags = "-O2 -Wall"

        with mock.patch.dict(os.environ, {"CFLAGS": original_flags}, clear=True), \
                mock.patch.object(install_build_dependencies.sys, "platform", "linux"):
            environment = install_build_dependencies.install_environment()

            self.assertEqual(environment, dict(os.environ))
            self.assertEqual(environment["CFLAGS"], original_flags)

    def test_non_android_does_not_add_cflags(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(install_build_dependencies.sys, "platform", "linux"):
            environment = install_build_dependencies.install_environment()

            self.assertNotIn("CFLAGS", environment)


class InstallBuildDependenciesTests(unittest.TestCase):
    def test_installs_requirements_with_current_interpreter(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            child_environment = {"PATH": "/test/bin"}
            completed = mock.Mock(returncode=0)

            with mock.patch.object(install_build_dependencies, "ROOT", root), \
                    mock.patch.object(install_build_dependencies.sys, "executable", "/test/python"), \
                    mock.patch.object(
                        install_build_dependencies,
                        "install_environment",
                        return_value=child_environment,
                    ), \
                    mock.patch.object(
                        install_build_dependencies.subprocess,
                        "run",
                        return_value=completed,
                    ) as run:
                status = install_build_dependencies.main()

            self.assertEqual(status, 0)
            run.assert_called_once_with(
                [
                    "/test/python",
                    "-m",
                    "pip",
                    "install",
                    "-r",
                    str(root / "requirements-build.txt"),
                ],
                cwd=str(root),
                env=child_environment,
                check=False,
            )

    def test_propagates_pip_failure_status(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(install_build_dependencies, "ROOT", Path(temp)), \
                    mock.patch.object(install_build_dependencies.subprocess, "run", return_value=mock.Mock(returncode=23)):
                self.assertEqual(install_build_dependencies.main(), 23)

    def test_reports_process_start_failure(self):
        stderr = io.StringIO()

        with mock.patch.object(
            install_build_dependencies.subprocess,
            "run",
            side_effect=OSError("spawn failed"),
        ), contextlib.redirect_stderr(stderr):
            status = install_build_dependencies.main()

        self.assertEqual(status, 1)
        self.assertIn("Could not start build dependency installation", stderr.getvalue())
        self.assertIn("spawn failed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
