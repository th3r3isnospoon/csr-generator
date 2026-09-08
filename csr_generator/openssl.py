"""Optional OpenSSL text decoder. Secrets never enter command arguments."""

import os
import shutil
import subprocess

from .errors import ApplicationError, ValidationError
from .pem import MAX_INPUT, inspect_pem


class OpenSSL:
    def __init__(self, executable: str | None = None, timeout: float = 15):
        self.executable = shutil.which(executable or "openssl")
        if not self.executable:
            raise ApplicationError(
                "OpenSSL was not found on PATH. Built-in inspection is available."
            )
        self.timeout = timeout

    def run(self, args: list[str], data: bytes = b"") -> str:
        try:
            result = subprocess.run(
                [self.executable, *args],
                input=data,
                capture_output=True,
                timeout=self.timeout,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        except subprocess.TimeoutExpired as exc:
            raise ApplicationError("OpenSSL timed out.") from exc
        except OSError as exc:
            raise ApplicationError("OpenSSL could not be started.") from exc
        if result.returncode:
            # Raw parser errors may echo input. Do not expose them in logs or dialogs.
            raise ApplicationError("OpenSSL rejected the input or operation.")
        return result.stdout.decode("utf-8", errors="replace")

    def version(self) -> str:
        return self.run(["version"]).strip()

    def decode(self, data: bytes, kind: str) -> str:
        if len(data) > MAX_INPUT:
            raise ValidationError("Input exceeds 2 MiB.")
        inspect_pem(data, kind)
        from .pem import pem_blocks

        command = "req" if kind == "csr" else "x509"
        return "\n".join(
            self.run([command, "-noout", "-text"], block) for _, block in pem_blocks(data)
        )
