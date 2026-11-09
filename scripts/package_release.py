#!/usr/bin/env python3
"""Package a native executable as a platform-specific release archive."""

# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
from __future__ import annotations

import argparse
import io
import re
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_PATTERN = re.compile(r'^VERSION\s*=\s*["\']([^"\']+)["\']\s*$', re.MULTILINE)
VALID_TARGETS = {
    "linux-x86_64",
    "linux-aarch64",
    "windows-x86_64",
    "macos-x86_64",
    "macos-arm64",
}


def project_version() -> str:
    source = (ROOT / "cargotrail.py").read_text(encoding="utf-8")
    match = VERSION_PATTERN.search(source)
    if not match:
        raise RuntimeError("Could not determine VERSION from the application entry point")
    return match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=sorted(VALID_TARGETS))
    parser.add_argument("--version", required=True, help="Version without a leading v")
    parser.add_argument("--source-url", required=True, help="URL of the exact source tree for this release tag")
    args = parser.parse_args()

    current_version = project_version()
    if args.version != current_version:
        parser.error("tag version {} does not match application version {}".format(args.version, current_version))

    is_windows = args.target.startswith("windows-")
    executable = ROOT / "dist" / ("cargotrail.exe" if is_windows else "cargotrail")
    if not executable.is_file():
        parser.error("Expected executable not found: {}".format(executable))

    output_dir = ROOT / "release"
    output_dir.mkdir(exist_ok=True)
    base_name = "cargotrail-v{}-{}".format(args.version, args.target)
    release_documents = ("LICENSE", "README.md", "THIRD_PARTY_NOTICES.md")
    source_notice = (
        "Source code for this executable is available at:\n"
        "{}\n\n"
        "Release: v{}\n"
        "License: MPL-2.0\n"
    ).format(args.source_url, args.version).encode("utf-8")
    missing_documents = [name for name in release_documents if not (ROOT / name).is_file()]
    if missing_documents:
        parser.error("Required release document(s) missing: {}".format(", ".join(missing_documents)))

    if is_windows:
        output = output_dir / (base_name + ".zip")
        with zipfile.ZipFile(str(output), "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            archive.write(str(executable), arcname="cargotrail.exe")
            for name in release_documents:
                archive.write(str(ROOT / name), arcname=name)
            archive.writestr("SOURCE-CODE.txt", source_notice)
    else:
        output = output_dir / (base_name + ".tar.gz")
        with tarfile.open(str(output), "w:gz", compresslevel=9) as archive:
            info = archive.gettarinfo(str(executable), arcname="cargotrail")
            info.mode = 0o755
            with executable.open("rb") as stream:
                archive.addfile(info, stream)
            for name in release_documents:
                archive.add(str(ROOT / name), arcname=name, recursive=False)
            source_info = tarfile.TarInfo("SOURCE-CODE.txt")
            source_info.size = len(source_notice)
            source_info.mode = 0o644
            archive.addfile(source_info, io.BytesIO(source_notice))

    print("Packaged: {}".format(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
