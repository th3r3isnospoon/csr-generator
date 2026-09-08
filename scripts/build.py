"""Build from the current checkout. Never uploads or creates a release."""

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
from importlib.metadata import distributions
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from csr_generator import __version__  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--appdir", action="store_true", help="Also prepare Linux AppDir")
    parser.add_argument(
        "--gui-smoke", action="store_true", help="Also test frozen GUI; needs a display"
    )
    args = parser.parse_args()
    if args.appdir and sys.platform != "linux":
        parser.error("AppDir must be built on Linux")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            str(ROOT / "packaging" / "csr-generator.spec"),
        ],
        cwd=ROOT,
        check=True,
    )
    dist = ROOT / "dist" / "CSR-Generator"
    # Include license texts for the dependencies actually installed in the build environment.
    licenses = dist / "licenses"
    licenses.mkdir(exist_ok=True)
    packages = []
    for package in distributions():
        name = package.metadata["Name"]
        packages.append({"name": name, "version": package.version})
        for file in package.files or []:
            if file.name.lower().startswith(("license", "copying", "notice")):
                source = Path(package.locate_file(file))
                if source.is_file():
                    target = licenses / name / file.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, target)
    source_commit = None
    source_dirty = None
    if shutil.which("git"):
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False
        )
        if revision.returncode == 0:
            source_commit = revision.stdout.strip()
            status = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
            source_dirty = bool(status.stdout.strip())
    manifest = {
        "source_commit": source_commit,
        "source_dirty": source_dirty,
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "build_environment": sorted(packages, key=lambda v: v["name"]),
    }
    (dist / "BUILD-INFO.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    shutil.copy2(ROOT / "README.md", dist)
    shutil.copy2(ROOT / "LICENSE", dist)
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "smoke_frozen.py"), str(dist)], check=True
    )
    if args.gui_smoke:
        gui = dist / ("csr-generator-gui.exe" if sys.platform == "win32" else "csr-generator-gui")
        subprocess.run([str(gui), "--smoke-test"], check=True, timeout=30)
    archive_name = f"CSR-Generator-{__version__}-{platform.system()}-{platform.machine()}"
    archive = Path(
        shutil.make_archive(str(ROOT / "dist" / archive_name), "zip", ROOT / "dist", dist.name)
    )
    archive.with_suffix(".zip.sha256").write_text(
        hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n",
        encoding="ascii",
    )
    if args.appdir:
        appdir = ROOT / "dist" / "CSR-Generator.AppDir"
        if appdir.exists():
            raise SystemExit("AppDir already exists. Move it aside before rebuilding.")
        shutil.copytree(dist, appdir / "usr" / "bin")
        for source, name in (
            ("AppRun", "AppRun"),
            ("csr-generator.desktop", "csr-generator.desktop"),
            ("csr-generator.png", "csr-generator.png"),
        ):
            shutil.copy2(ROOT / "packaging" / source, appdir / name)
        (appdir / "AppRun").chmod(0o755)
        shutil.copy2(appdir / "csr-generator.png", appdir / ".DirIcon")
        print(f"AppDir ready: {appdir}")
    print(f"Built and CLI smoke-tested: {archive}")


if __name__ == "__main__":
    main()
