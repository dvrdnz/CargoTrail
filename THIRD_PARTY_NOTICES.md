# Third-Party Notices

This file records the third-party software identified in the source repository and the standalone-binary build configuration. It is not a substitute for checking the exact contents of each platform-specific binary.

## Application runtime

The application source imports only Python standard-library modules. It has no third-party Python runtime package dependency. Cargo and Rustc are external tools invoked from the user's environment; they are not bundled by this project.

When a standalone executable is built, it contains a CPython runtime. Python and its standard library are distributed under the Python Software Foundation (PSF) License Version 2, while some components included with Python may carry separate notices. The release process must preserve the license and notices supplied with the exact Python distribution used by each native build. See the [Python license documentation](https://docs.python.org/3/license.html).

## Build-time dependency

- **PyInstaller 6.22.3** — build-time only; pinned in `requirements-build.txt`. PyInstaller is distributed under GPL-2.0-or-later with a Bootloader Exception, with certain files under Apache-2.0. The PyInstaller license documentation states that generated executables may be distributed under the application's own license, subject to the licenses of the application's dependencies, and that PyInstaller's own license file or credit is not required for those generated executables. See the [PyInstaller license documentation](https://pyinstaller.org/en/v6.22.3/license.html).

PyInstaller itself is not imported or required when running the source application. Do not modify PyInstaller or its bootloader as part of this project without separately reviewing the applicable license obligations.

## CI actions

GitHub Actions and the Rust toolchain setup action are used by hosted CI workflows. They are not vendored into the application source or bundled into the standalone executable. Their upstream terms remain applicable to those services and components.

## Scope and review status

No third-party application source files are vendored in this repository. This inventory is based on the checked-in source and declared build requirements. A final binary-level software bill of materials and platform-specific notice review remain part of the binary release validation, because the exact Python distribution and frozen contents are determined by each native build runner.
