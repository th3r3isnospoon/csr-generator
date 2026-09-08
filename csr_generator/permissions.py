"""Restrict new Windows objects before writing secrets; POSIX modes are set at creation."""

import csv
import io
import os
import re
import subprocess
import sys
from pathlib import Path

from .errors import ApplicationError


def restrict_windows(path: Path) -> None:
    if sys.platform != "win32":
        return
    system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
    try:
        identity = subprocess.run(
            [str(system / "whoami.exe"), "/user", "/fo", "csv", "/nh"],
            capture_output=True,
            check=True,
            timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        row = next(csv.reader(io.StringIO(identity.stdout.decode("utf-8", errors="replace"))))
        sid = row[-1].strip()
        if not re.fullmatch(r"S-1-\d+(?:-\d+)+", sid):
            raise ValueError("Invalid user SID")
        rights = "(OI)(CI)F" if path.is_dir() else "F"
        subprocess.run(
            [
                str(system / "icacls.exe"),
                str(path),
                "/inheritance:r",
                "/grant:r",
                f"*{sid}:{rights}",
            ],
            capture_output=True,
            check=True,
            timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, ValueError, StopIteration, subprocess.SubprocessError) as exc:
        raise ApplicationError(
            "Could not restrict Windows file permissions; output was not saved."
        ) from exc
