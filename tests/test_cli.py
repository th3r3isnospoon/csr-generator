import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "csr_generator", *args],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_generate_inspect_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_cli(
                "generate",
                "--cn",
                "test.example",
                "--dns",
                "test.example",
                "--unencrypted",
                "--self-signed",
                "--output",
                tmp,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            folder = next(Path(tmp).iterdir())
            result = self.run_cli("inspect", "csr", str(folder / "request.csr"))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("self-signature: valid", result.stdout)
            output = Path(tmp) / "chain.pem"
            args = (
                "bundle",
                "--certificates",
                str(folder / "certificate.crt"),
                "--output",
                str(output),
            )
            self.assertEqual(self.run_cli(*args).returncode, 0)
            self.assertNotEqual(self.run_cli(*args).returncode, 0)

    def test_invalid_input_is_nonzero_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.run_cli("generate", "--cn", "test", "--unencrypted", "--output", tmp)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_import_has_no_io_or_tk(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; import csr_generator.crypto; assert 'tkinter' not in sys.modules",
            ],
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
