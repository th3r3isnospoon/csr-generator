"""Wrap a prepared AppDir using a separately downloaded, SHA-256 verified appimagetool."""

import argparse
import hashlib
import os
import platform
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", type=Path, required=True)
    parser.add_argument("--sha256", required=True, help="Expected trusted appimagetool SHA-256")
    parser.add_argument("--appdir", type=Path, default=Path("dist/CSR-Generator.AppDir"))
    parser.add_argument("--output", type=Path, default=Path("dist/CSR-Generator.AppImage"))
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--runtime-sha256", required=True)
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("AppImage packaging requires Linux")
    if hashlib.sha256(args.tool.read_bytes()).hexdigest() != args.sha256.lower():
        parser.error("appimagetool checksum mismatch")
    if hashlib.sha256(args.runtime.read_bytes()).hexdigest() != args.runtime_sha256.lower():
        parser.error("AppImage runtime checksum mismatch")
    if args.output.exists():
        parser.error("Output exists; choose a new filename")
    for name in (
        "AppRun",
        "csr-generator.desktop",
        "csr-generator.png",
        "usr/bin/csr-generator-gui",
    ):
        if not (args.appdir / name).is_file():
            parser.error(f"AppDir is missing {name}")
    env = {**os.environ, "ARCH": platform.machine(), "APPIMAGE_EXTRACT_AND_RUN": "1"}
    subprocess.run(
        [
            str(args.tool.resolve()),
            "--runtime-file",
            str(args.runtime.resolve()),
            str(args.appdir.resolve()),
            str(args.output.resolve()),
        ],
        env=env,
        check=True,
    )
    args.output.with_suffix(".AppImage.sha256").write_text(
        hashlib.sha256(args.output.read_bytes()).hexdigest() + "  " + args.output.name + "\n"
    )


if __name__ == "__main__":
    main()
