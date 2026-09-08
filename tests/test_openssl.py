"""Independent checks using an actual OpenSSL executable, not mocked crypto."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from csr_generator.crypto import create_artifacts, generate
from csr_generator.errors import ApplicationError
from csr_generator.models import ALGORITHMS
from csr_generator.openssl import OpenSSL
from csr_generator.pem import bundle
from tests.test_core import request


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL executable unavailable")
class OpenSSLIntegrationTests(unittest.TestCase):
    def run_openssl(self, args, password=b"", success=True):
        result = subprocess.run(
            [shutil.which("openssl"), *args], input=password, capture_output=True, timeout=30
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        else:
            self.assertNotEqual(result.returncode, 0)
        return result.stdout

    def test_all_algorithms_with_real_openssl(self):
        with tempfile.TemporaryDirectory() as tmp:
            for algorithm in ALGORITHMS:
                with self.subTest(algorithm=algorithm):
                    req = request(algorithm=algorithm)
                    result = generate(req, Path(tmp))
                    csr = str(result.directory / "request.csr")
                    key = str(result.directory / "private-key.pem")
                    crt = str(result.directory / "certificate.crt")
                    self.run_openssl(["req", "-in", csr, "-verify", "-noout"])
                    decoded = self.run_openssl(["req", "-in", csr, "-text", "-noout"])
                    self.assertIn(b"Example", decoded)
                    self.assertIn(b"DNS:example.test", decoded)
                    self.run_openssl(
                        ["pkey", "-in", key, "-passin", "stdin", "-check", "-noout"],
                        req.passphrase.encode() + b"\n",
                    )
                    self.run_openssl(
                        ["pkey", "-in", key, "-passin", "stdin", "-noout"],
                        b"wrong\n",
                        success=False,
                    )
                    self.run_openssl(
                        [
                            "verify",
                            "-CAfile",
                            crt,
                            "-check_ss_sig",
                            "-purpose",
                            "sslserver",
                            "-verify_hostname",
                            "example.test",
                            crt,
                        ]
                    )

    def test_optional_decoder_and_pkcs12(self):
        artifacts = create_artifacts(request())
        self.assertIn("Certificate Request", OpenSSL().decode(artifacts.csr, "csr"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bundle.p12"
            path.write_bytes(
                bundle(
                    artifacts.certificate,
                    artifacts.key,
                    request().passphrase,
                    mode="pkcs12",
                    export_passphrase="p12 secret",
                )
            )
            self.run_openssl(
                ["pkcs12", "-in", str(path), "-passin", "stdin", "-info", "-noout"], b"p12 secret\n"
            )


class OpenSSLErrorTests(unittest.TestCase):
    def test_missing_executable(self):
        with patch("csr_generator.openssl.shutil.which", return_value=None):
            with self.assertRaises(ApplicationError):
                OpenSSL()

    def test_timeout_and_redacted_failure(self):
        with patch("csr_generator.openssl.shutil.which", return_value="/fake/openssl"):
            backend = OpenSSL()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("openssl", 15)):
            with self.assertRaisesRegex(ApplicationError, "timed out"):
                backend.version()
        with patch(
            "subprocess.run", return_value=subprocess.CompletedProcess([], 1, b"", b"SECRET")
        ):
            with self.assertRaises(ApplicationError) as failure:
                backend.version()
            self.assertNotIn("SECRET", str(failure.exception))
