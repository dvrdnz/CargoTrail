#!/usr/bin/env python3
"""Build a native one-file executable with the pinned PyInstaller toolchain."""

# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean", action="store_true", help="Remove PyInstaller work files before building")
    args = parser.parse_args()

    if importlib.util.find_spec("PyInstaller") is None:
        parser.error("PyInstaller is not installed; run: python -m pip install -r requirements-build.txt")

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--distpath",
        str(ROOT / "dist"),
        "--workpath",
        str(ROOT / "build" / "pyinstaller"),
    ]
    if args.clean:
        command.append("--clean")
    command.append(str(ROOT / "cargotrail.spec"))

    try:
        subprocess.run(command, cwd=str(ROOT), check=True)
    except subprocess.CalledProcessError as exc:
        return exc.returncode or 1

    executable = ROOT / "dist" / ("cargotrail.exe" if sys.platform == "win32" else "cargotrail")
    if not executable.is_file():
        parser.error("PyInstaller completed without producing the expected executable: {}".format(executable))
    if sys.platform != "win32":
        executable.chmod(0o755)
    print("Built: {}".format(executable))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
