import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from csr_generator.errors import ApplicationError
from csr_generator.permissions import restrict_windows


class PermissionTests(unittest.TestCase):
    def test_windows_acl_arguments_use_sid_and_no_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            with (
                patch("csr_generator.permissions.sys.platform", "win32"),
                patch("csr_generator.permissions.subprocess.run") as run,
            ):
                run.return_value = subprocess.CompletedProcess(
                    [], 0, b'"HOST\\user","S-1-5-21-123"\r\n'
                )
                restrict_windows(path)
                args = run.call_args.args[0]
                self.assertEqual(
                    args[1:], [str(path), "/inheritance:r", "/grant:r", "*S-1-5-21-123:(OI)(CI)F"]
                )
                self.assertFalse(run.call_args.kwargs.get("shell", False))

    def test_acl_failure_is_closed(self):
        with (
            patch("csr_generator.permissions.sys.platform", "win32"),
            patch(
                "csr_generator.permissions.subprocess.run",
                side_effect=subprocess.CalledProcessError(1, "whoami"),
            ),
        ):
            with self.assertRaises(ApplicationError):
                restrict_windows(Path("unused"))
