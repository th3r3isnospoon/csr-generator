"""Exercise the actual frozen CLI, including its bundled crypto backend."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    executable = Path(sys.argv[1]).resolve() / (
        "csr-generator.exe" if os.name == "nt" else "csr-generator"
    )
    with tempfile.TemporaryDirectory(prefix="csr-frozen-") as tmp:
        for args in (
            ["--version"],
            [
                "generate",
                "--cn",
                "smoke.example",
                "--dns",
                "smoke.example",
                "--self-signed",
                "--unencrypted",
                "--output",
                tmp,
            ],
        ):
            subprocess.run([str(executable), *args], check=True, timeout=45, cwd=tmp)
        folder = next(Path(tmp).iterdir())
        subprocess.run(
            [str(executable), "inspect", "csr", str(folder / "request.csr")],
            check=True,
            timeout=15,
            cwd=tmp,
        )
        subprocess.run(
            [
                str(executable),
                "bundle",
                "--certificates",
                str(folder / "certificate.crt"),
                "--output",
                str(Path(tmp) / "chain.pem"),
            ],
            check=True,
            timeout=15,
            cwd=tmp,
        )


if __name__ == "__main__":
    main()
