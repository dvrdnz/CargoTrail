# Building and releasing

## Build a standalone executable locally

The source application has no third-party runtime dependencies. PyInstaller is used only to package the Python interpreter and application into a native single-file executable.

```bash
python -m pip install -r requirements-build.txt
python scripts/build_binary.py --clean
```

The output is written to `dist/`:

- Linux/macOS: `dist/cargotrail`
- Windows: `dist/cargotrail.exe`

The PyInstaller specification includes the four runtime source files as bundle data. This is required because the provenance report hashes these source files at runtime; a frozen binary must not report them as missing.

A PyInstaller build is native to the operating system and architecture on which it runs. Do not build a Windows executable on Linux or a macOS executable on Windows. Use native runners or machines for each release target.

## Release targets

A version tag triggers native builds for Linux x86-64, Linux ARM64, Windows x86-64, macOS Intel x86-64, and macOS Apple Silicon ARM64. Unix binaries are distributed in `.tar.gz` archives to preserve executable mode. The Windows executable is distributed in a `.zip` archive. A `SHA256SUMS.txt` file covers the release archives. Linux binaries are built on Ubuntu 24.04 and may not run on older distributions with an older glibc.

The release workflow verifies that the pushed tag version matches the `VERSION` constant in `cargotrail.py`. It runs only after the platform test matrix, the minimum-Python jobs, and both Windows linker lanes succeed.

Each build job runs `scripts/smoke_test_binary.py` against the frozen executable. The script runs a real Cargo pipeline on a minimal crate, creates an evidence archive, and fails if the executable does not report all four runtime source files as hashed. A plain `--version` check would not catch missing bundled sources.

The same build-and-package chain can be started by hand with **Actions → CI and Release → Run workflow**. A manual run builds, smoke-tests, and packages all five targets but does not create a release, so it is the recommended dry run before tagging.

The release is created as a **draft**. Nothing is public until a maintainer reviews and publishes it (see below).

The workflow does not code-sign or notarize the binaries. Windows may display an unknown-publisher warning, and macOS may require the user to approve an unsigned download. Add platform signing and macOS notarization credentials to repository secrets before distributing binaries to users who require trusted publisher identity.

## Publish a release

1. Update `VERSION` in `cargotrail.py`.
2. Add a user-facing entry to `CHANGELOG.md`.
3. Run the tests locally and review the diff.
4. Commit and push to the default branch. Wait until the full test matrix, including the Python 3.8 jobs and both Windows linker lanes, is green.
5. Start the dry run: **Actions → CI and Release → Run workflow** on the default branch. All five build jobs must succeed.
6. Create and push an annotated version tag matching the application version, for example:

```bash
git tag -a v1.5.1 -m "Release v1.5.1"
git push origin v1.5.1
```

GitHub Actions runs the native test matrix, builds and smoke-tests each executable, creates checksums, and creates a **draft** GitHub Release with the assets and generated release notes.

7. Review the draft before publishing it:
   - Complete the binary-level notice review described in `THIRD_PARTY_NOTICES.md` for every platform archive. Each archive already contains `PYTHON-LICENSE.txt`; the review covers the native libraries bundled next to the runtime. List them by running `python -m PyInstaller.utils.cliutils.archive_viewer -l -r <executable>` on the executable from the archive, with PyInstaller installed from `requirements-build.txt`.
   - Download at least one archive per platform family, run `--version`, and compare the checksum with `SHA256SUMS.txt`.
   - Check the generated release notes against `CHANGELOG.md`.
8. Publish the draft in the GitHub UI (**Edit → Publish release**).

The workflow only uploads assets to the draft. Do not delete or move a version tag after its release has been published. If a build fails before the draft exists, fix the problem and re-run the failed jobs; a re-run reuses an existing draft for the same tag and replaces its assets.

## License and source availability

The project source is licensed under the Mozilla Public License 2.0 (MPL-2.0); see the root `LICENSE` file. Release archives include `LICENSE`, `README.md`, `THIRD_PARTY_NOTICES.md`, `PYTHON-LICENSE.txt`, and `SOURCE-CODE.txt`. The latter points recipients to the exact source tree at the matching Git tag. Keep that tag and its source archive available for as long as the corresponding binaries are distributed. The MPL-2.0 executable-form requirements are described in Section 3.2 of the license.

Do not publish a binary until its bundled Python runtime and platform-specific notices have been reviewed. The draft release exists to enforce this. See `THIRD_PARTY_NOTICES.md` for the current dependency inventory and the remaining binary-level notice check.
