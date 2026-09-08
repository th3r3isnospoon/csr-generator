"""Opt-in actual Tk widget tests. Run with CSR_GUI_TESTS=1 and a display/Xvfb."""

import os
import time
import unittest
from unittest.mock import patch


@unittest.skipUnless(os.environ.get("CSR_GUI_TESTS") == "1", "Set CSR_GUI_TESTS=1 with a display")
class GUITests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk

        from csr_generator.gui import Application

        self.root = tk.Tk()
        self.root.withdraw()
        self.app = Application(self.root)
        self.root.update()

    def tearDown(self):
        self.app.close()

    def test_tabs_theme_does_not_mutate_text_and_sans(self):
        self.assertEqual(len(self.app.notebook.tabs()), 5)
        self.app.set_text(self.app.dns, "example.test\n")
        before = self.app.dns.get("1.0", "end")
        self.app.toggle_theme()
        self.app.toggle_theme()
        self.assertEqual(self.app.dns.get("1.0", "end"), before)
        self.app.subject_vars["common_name"].set("2001:db8::1")
        self.app.add_cn()
        self.assertIn("2001:db8::1", self.app.ips.get("1.0", "end"))

    def test_form_matches_service_and_preserves_password(self):
        self.app.subject_vars["common_name"].set("example.test")
        self.app.add_cn()
        self.app.password.set(" exact spaces ")
        self.app.confirm.set(" exact spaces ")
        self.assertEqual(self.app.request().passphrase, " exact spaces ")
        self.app.encrypted.set(False)
        self.app.encryption_changed()
        self.assertEqual(self.app.password.get(), "")
        self.assertFalse(self.app.request().encrypt_key)

    def test_background_delivery(self):
        values = []
        self.app.start(lambda: "result", values.append)
        deadline = time.monotonic() + 3
        while self.app.busy and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.01)
        self.assertFalse(self.app.busy)
        self.assertEqual(values, ["result"])

    def test_browse_cancel_preserves_destination(self):
        previous = self.app.destination.get()
        with patch("csr_generator.gui.filedialog.askdirectory", return_value=""):
            self.app.choose_destination()
        self.assertEqual(self.app.destination.get(), previous)

    def test_bundle_controls_visible_at_minimum_size(self):
        self.root.deiconify()
        self.root.geometry("680x560")
        self.app.notebook.select(3)
        self.root.update()
        button = next(b for b in self.app.action_buttons if b.cget("text") == "Validate and export")
        self.assertTrue(button.winfo_ismapped())
        self.assertLessEqual(
            button.winfo_rooty() + button.winfo_height(),
            self.root.winfo_rooty() + self.root.winfo_height(),
        )

    def test_cancel_discards_pending_inspection_result(self):
        import threading

        gate = threading.Event()
        values = []
        self.app.start(lambda: gate.wait(2), values.append)
        self.app.cancel()
        gate.set()
        deadline = time.monotonic() + 3
        while self.app.busy and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.01)
        self.assertFalse(self.app.busy)
        self.assertEqual(values, [])
