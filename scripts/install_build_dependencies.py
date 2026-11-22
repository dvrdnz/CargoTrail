#!/usr/bin/env python3
"""Install the pinned dependencies required to build the standalone executable."""

# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TERMUX_CFLAGS_OPTION = "-Wno-error=deprecated-declarations"


def install_environment() -> dict[str, str]:
    """Return the child environment, applying the Termux compiler exception."""
    environment = os.environ.copy()

    if sys.platform == "android":
        existing_flags = environment.get("CFLAGS", "")
        separator = " " if existing_flags else ""
        environment["CFLAGS"] = "{}{}{}".format(
            existing_flags,
            separator,
            TERMUX_CFLAGS_OPTION,
        )

    return environment


def main() -> int:
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "-r",
        str(ROOT / "requirements-build.txt"),
    ]

    try:
        result = subprocess.run(
            command,
            cwd=str(ROOT),
            env=install_environment(),
            check=False,
        )
    except OSError as exc:
        print(
            "Could not start build dependency installation: {}".format(exc),
            file=sys.stderr,
        )
        return 1

    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
