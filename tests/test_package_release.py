# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
import contextlib
import importlib.util
import io
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "package_release.py"
SPEC = importlib.util.spec_from_file_location("package_release", SCRIPT)
package_release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package_release)

LICENSE_TEXT = "PYTHON LICENSE TEXT\n"
DOCUMENT_NAMES = {"LICENSE", "README.md", "THIRD_PARTY_NOTICES.md", "PYTHON-LICENSE.txt", "SOURCE-CODE.txt"}


class PythonLicenseDiscoveryTests(unittest.TestCase):
    def _discover(self, stdlib, base_prefix):
        with mock.patch.object(package_release, "sysconfig", mock.Mock(get_path=lambda name: str(stdlib))), \
                mock.patch.object(package_release, "sys", mock.Mock(base_prefix=str(base_prefix))):
            return package_release.python_license_path()

    def test_prefers_the_standard_library_license(self):
        with tempfile.TemporaryDirectory() as temp:
            stdlib = Path(temp) / "lib"
            prefix = Path(temp) / "prefix"
            stdlib.mkdir()
            prefix.mkdir()
            (stdlib / "LICENSE.txt").write_text("stdlib", encoding="utf-8")
            (prefix / "LICENSE.txt").write_text("prefix", encoding="utf-8")
            self.assertEqual(self._discover(stdlib, prefix), stdlib / "LICENSE.txt")

    def test_falls_back_to_the_installation_prefix(self):
        for name in ("LICENSE.txt", "LICENSE"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                stdlib = Path(temp) / "lib"
                prefix = Path(temp) / "prefix"
                stdlib.mkdir()
                prefix.mkdir()
                (prefix / name).write_text("prefix", encoding="utf-8")
                self.assertEqual(self._discover(stdlib, prefix), prefix / name)

    def test_reports_every_searched_location_when_no_license_exists(self):
        with tempfile.TemporaryDirectory() as temp:
            stdlib = Path(temp) / "lib"
            prefix = Path(temp) / "prefix"
            stdlib.mkdir()
            prefix.mkdir()
            with self.assertRaises(FileNotFoundError) as caught:
                self._discover(stdlib, prefix)
            message = str(caught.exception)
            for searched in (stdlib / "LICENSE.txt", prefix / "LICENSE.txt", prefix / "LICENSE"):
                self.assertIn(str(searched), message)


class PackageReleaseArchiveTests(unittest.TestCase):
    def _prepare_root(self, temp, windows):
        root = Path(temp) / "repo"
        (root / "dist").mkdir(parents=True)
        (root / "cargotrail.py").write_text('VERSION = "9.9.9"\n', encoding="utf-8")
        for name in ("LICENSE", "README.md", "THIRD_PARTY_NOTICES.md"):
            (root / name).write_text(name + "\n", encoding="utf-8")
        (root / "dist" / ("cargotrail.exe" if windows else "cargotrail")).write_bytes(b"binary")
        license_file = Path(temp) / "python-license.txt"
        # Write bytes: text mode would turn "\n" into "\r\n" on Windows and the archive
        # content comparison below would no longer match.
        license_file.write_bytes(LICENSE_TEXT.encode("utf-8"))
        return root, license_file

    def _package(self, root, target, license_lookup):
        argv = [
            "package_release.py", "--target", target, "--version", "9.9.9",
            "--source-url", "https://example.invalid/tree/v9.9.9",
        ]
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(package_release, "ROOT", root), \
                mock.patch.object(package_release, "python_license_path", license_lookup), \
                mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                status = package_release.main()
            except SystemExit as exc:
                status = exc.code
        return status, stderr.getvalue()

    def test_tar_archive_contains_the_python_license(self):
        with tempfile.TemporaryDirectory() as temp:
            root, license_file = self._prepare_root(temp, windows=False)
            status, _ = self._package(root, "linux-x86_64", lambda: license_file)
            self.assertEqual(status, 0)
            with tarfile.open(str(root / "release" / "cargotrail-v9.9.9-linux-x86_64.tar.gz")) as archive:
                self.assertEqual(set(archive.getnames()), DOCUMENT_NAMES | {"cargotrail"})
                self.assertEqual(archive.extractfile("PYTHON-LICENSE.txt").read().decode("utf-8"), LICENSE_TEXT)

    def test_zip_archive_contains_the_python_license(self):
        with tempfile.TemporaryDirectory() as temp:
            root, license_file = self._prepare_root(temp, windows=True)
            status, _ = self._package(root, "windows-x86_64", lambda: license_file)
            self.assertEqual(status, 0)
            with zipfile.ZipFile(str(root / "release" / "cargotrail-v9.9.9-windows-x86_64.zip")) as archive:
                self.assertEqual(set(archive.namelist()), DOCUMENT_NAMES | {"cargotrail.exe"})
                self.assertEqual(archive.read("PYTHON-LICENSE.txt").decode("utf-8"), LICENSE_TEXT)

    def test_missing_python_license_fails_without_creating_an_archive(self):
        def missing():
            raise FileNotFoundError("Could not find the Python license file; searched: nowhere")

        with tempfile.TemporaryDirectory() as temp:
            root, _ = self._prepare_root(temp, windows=False)
            status, stderr = self._package(root, "linux-x86_64", missing)
            self.assertEqual(status, 2)
            self.assertIn("Could not find the Python license file", stderr)
            self.assertEqual(list((root / "release").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
