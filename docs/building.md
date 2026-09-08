# Building and distributing

No build script or GitHub workflow publishes a release. CI has read-only repository
permissions and uploads temporary build artifacts only, including for version tags.
A maintainer must review and approve distribution separately.

## Portable folders

Use Python 3.12 with Tk available, ideally in a clean virtual environment:

```sh
python -m pip install -r requirements-build.txt
python -m pip install --no-build-isolation --no-deps -e .
python scripts/build.py --gui-smoke
```

Windows users can run `build_exe.bat`. It uses its own environment and stops on failures.
Linux headless builders should use `xvfb-run -a python scripts/build.py --gui-smoke`.
Omit `--gui-smoke` only when a display is unavailable and record that missing verification.

The tracked PyInstaller spec creates `dist/CSR-Generator/` with separate GUI and CLI
executables sharing their runtime. **Keep the entire folder together**, including
`_internal`; the EXE alone is not a portable application. Tk and cryptographic libraries
are bundled. External OpenSSL is deliberately not bundled or needed for generation.
The build smoke test exercises the frozen CLI in an unrelated working directory.

The ZIP name includes version, OS, and architecture. A SHA-256 sidecar detects
accidental changes; it is not an authenticated signature. `BUILD-INFO.json` records
the build environment, and `licenses/` includes installed dependency license texts.
This inventory is not a complete binary-level SBOM or proof of reproducibility.
Pinned tools reduce drift; do not claim byte-for-byte reproducibility across platforms.

## Linux AppImage

The old placeholder AppDir has been removed. Build it from the real frozen application:

```sh
python scripts/build.py --appdir --gui-smoke
```

This creates `dist/CSR-Generator.AppDir` with an executable `AppRun`, valid desktop
metadata, PNG icon, and complete frozen runtime. A pre-existing AppDir is refused;
move it aside before another AppDir build. Regular portable-folder builds may be repeated.

Obtain appimagetool from its official AppImage/appimagetool GitHub release. Verify
its digest against trusted release metadata, retain the version/digest with your
build records, and make it executable. Then:

```sh
python scripts/make_appimage.py --tool /path/to/appimagetool-x86_64.AppImage \
  --sha256 TRUSTED_SHA256 --runtime /path/to/runtime-x86_64 \
  --runtime-sha256 TRUSTED_RUNTIME_SHA256 --output dist/CSR-Generator-2.0.0-x86_64.AppImage
```

The script verifies the digest before execution and refuses output replacement.
Download the matching runtime from AppImage/type2-runtime and verify its published
digest too. The script requires a verified local runtime so packaging does not fetch
a mutable runtime implicitly. Test the final AppImage on
clean target distributions, with FUSE and extract-and-run modes as appropriate.
Linux binaries inherit the build host's glibc baseline. CI uses Ubuntu 22.04 to avoid
advertising portability based on a newer developer workstation alone.

## Desktop installation

`packaging/csr-generator.desktop` assumes `csr-generator-gui` is installed on PATH.
For a portable folder, install a launcher whose `Exec` points to the absolute GUI path
and install the icon under the matching desktop icon name. The repository's root
launcher follows the same PATH contract; it does not depend on the current directory.

## Source packages

`python -m build` creates a wheel and source distribution. Runtime requirements live
in `pyproject.toml`; `requirements-build.txt` pins the tested build tools. Refresh the
pins intentionally with tests and artifact smoke checks. Version is defined once in
`csr_generator/__init__.py` and read by package metadata and the build scripts.

## Before an approved release

Review CI for the exact commit, test on clean Windows/Linux installations, verify
bundled licenses, scan dependencies, and confirm no private material is present.
Signing Windows binaries, macOS signing/notarization, authenticated provenance, and
publishing release assets require maintainer-controlled credentials. None is performed
by this modernization branch. No updater or automatic certificate installation is included.
