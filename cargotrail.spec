# SPDX-License-Identifier: MPL-2.0
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

# PyInstaller one-file build specification.
# The source files are bundled as data as well as Python modules because the
# runtime provenance report hashes the original source files at execution time.
from pathlib import Path

project_root = Path(SPECPATH).resolve()
runtime_sources = (
    "cargotrail.py",
    "process_supervision.py",
    "provenance.py",
    "artifact_inventory.py",
)
source_data = [(str(project_root / name), ".") for name in runtime_sources]

analysis = Analysis(
    [str(project_root / "cargotrail.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=source_data,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(analysis.pure)

executable = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="cargotrail",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
)
