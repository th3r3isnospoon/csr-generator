"""A small Tk interface; workers receive immutable values, never Tk objects."""

import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

from . import __version__
from .crypto import generate
from .errors import ApplicationError, Cancelled, ValidationError
from .io import read_input
from .models import ALGORITHMS, DIGESTS, PROFILES, Request, Subject
from .pem import bundle, inspect_pem
from .profiles import load_profile, save_profile
from .storage import save_exclusive
from .validation import validate_request


class Application:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title(f"CSR Generator {__version__}")
        root.geometry("920x820")
        root.minsize(680, 560)
        self.events = queue.Queue()
        self.cancelled = threading.Event()
        self.busy = False
        self.closing = False
        self.dark = False
        self.last_directory = None
        self.fields = {}
        self.text_widgets = []
        self.action_buttons = []
        self.style = ttk.Style(root)
        self.style.theme_use("clam")
        self.status = tk.StringVar(value="Ready. Keys and certificates stay on this computer.")
        header = ttk.Frame(root, padding=(12, 8))
        header.pack(fill="x")
        ttk.Label(header, text="CSR Generator", font=("TkDefaultFont", 16, "bold")).pack(
            side="left"
        )
        self.theme = ttk.Button(header, text="Dark theme", command=self.toggle_theme)
        self.theme.pack(side="right")
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=12)
        self.build_generate()
        self.build_inspector("CSR Viewer", "csr")
        self.build_inspector("Certificate Decoder", "certificate")
        self.build_bundle()
        about = ttk.Frame(self.notebook, padding=20)
        self.notebook.add(about, text="About")
        ttk.Label(
            about,
            text=f"CSR Generator {__version__}\n\n"
            "Created by Mike Binkowski • MIT License\n"
            "https://github.com/th3r3isnospoon/csr-generator\n\n"
            "Cryptography runs locally. OpenSSL is optional for detailed inspection.\n"
            "Self-signed certificates are not automatically trusted.\n"
            "Keep private keys and secret-bearing bundles private.",
            wraplength=580,
            justify="left",
        ).pack(anchor="w")
        footer = ttk.Frame(root, padding=12)
        footer.pack(fill="x")
        self.progress = ttk.Progressbar(footer, mode="indeterminate", length=100)
        self.progress.pack(side="left", padx=(0, 10))
        ttk.Label(footer, textvariable=self.status, wraplength=560).pack(
            side="left", fill="x", expand=True
        )
        self.cancel_button = ttk.Button(
            footer, text="Cancel", command=self.cancel, state="disabled"
        )
        self.cancel_button.pack(side="right")
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.apply_theme()
        self.poll_id = root.after(100, self.poll)

    def action(self, parent, text, command):
        button = ttk.Button(parent, text=text, command=command)
        self.action_buttons.append(button)
        return button

    def text(self, parent, height=5, readonly=False):
        widget = scrolledtext.ScrolledText(
            parent, height=height, width=60, wrap="word", undo=not readonly
        )
        if readonly:
            widget.configure(state="disabled")
        self.text_widgets.append(widget)
        return widget

    def set_text(self, widget, value):
        state = str(widget.cget("state"))
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state=state)

    def group(self, parent, title):
        group = ttk.LabelFrame(parent, text=title, padding=10)
        group.pack(fill="x", padx=10, pady=6)
        group.columnconfigure(1, weight=1)
        return group

    def entry(self, parent, row, label, name, default="", secret=False):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 12), pady=3)
        variable = tk.StringVar(value=default)
        entry = ttk.Entry(parent, textvariable=variable, show="*" if secret else "")
        entry.grid(row=row, column=1, sticky="ew", pady=3)
        self.fields[name] = entry
        return variable

    def build_generate(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Generate CSR")
        canvas = tk.Canvas(tab, highlightthickness=0)
        scrollbar = ttk.Scrollbar(tab, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        content = ttk.Frame(canvas)
        window = canvas.create_window(0, 0, window=content, anchor="nw")
        content.bind("<Configure>", lambda _: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(window, width=event.width))
        self.form_canvas = canvas
        self.form_content = content
        for event_name in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            root = self.root
            root.bind_all(event_name, self.scroll_form, add="+")
        # Focus navigation also scrolls fields into view on small screens.
        content.bind_all("<FocusIn>", self.ensure_visible, add="+")
        profile_bar = ttk.Frame(content, padding=10)
        profile_bar.pack(fill="x")
        self.action(profile_bar, "Load profile", self.load_profile).pack(side="left")
        self.action(profile_bar, "Save profile (no secrets)", self.save_profile).pack(
            side="left", padx=8
        )
        identity = self.group(content, "Identity")
        labels = {
            "common_name": "Common name *",
            "country": "Country (2 letters)",
            "state": "State / province",
            "locality": "City / locality",
            "organization": "Organization",
            "organizational_unit": "Organizational unit",
            "email": "Email (optional)",
        }
        self.subject_vars = {
            name: self.entry(identity, row, label, name)
            for row, (name, label) in enumerate(labels.items())
        }
        sans = self.group(content, "Subject alternative names — one per line")
        ttk.Label(sans, text="DNS names (wildcards allowed)").grid(row=0, column=0, sticky="w")
        self.dns = self.text(sans, 3)
        self.dns.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.action(sans, "Add common name as SAN", self.add_cn).grid(
            row=2, column=0, sticky="w", pady=4
        )
        ttk.Label(sans, text="IP addresses (IPv4 or IPv6)").grid(row=3, column=0, sticky="w")
        self.ips = self.text(sans, 2)
        self.ips.grid(row=4, column=0, columnspan=2, sticky="ew")
        self.fields.update(dns_names=self.dns, ip_addresses=self.ips)
        options = self.group(content, "Key and certificate options")
        self.algorithm = tk.StringVar(value=ALGORITHMS["ec-p256"])
        self.digest = tk.StringVar(value="auto")
        self.profile = tk.StringVar(value="tls-server")
        for row, (label, variable, choices) in enumerate(
            [
                ("Key algorithm", self.algorithm, tuple(ALGORITHMS.values())),
                ("Signature digest", self.digest, DIGESTS),
                ("Purpose", self.profile, PROFILES),
            ]
        ):
            ttk.Label(options, text=label).grid(row=row, column=0, sticky="w")
            box = ttk.Combobox(options, textvariable=variable, values=choices, state="readonly")
            box.grid(row=row, column=1, sticky="ew", pady=3)
            if row == 1:
                self.digest_box = box
        self.algorithm.trace_add("write", self.algorithm_changed)
        self.encrypted = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            options,
            text="Encrypt output private key",
            variable=self.encrypted,
            command=self.encryption_changed,
        ).grid(row=3, column=0, columnspan=2, sticky="w")
        self.password = self.entry(options, 4, "Output passphrase", "passphrase", secret=True)
        self.confirm = self.entry(options, 5, "Confirm passphrase", "confirm", secret=True)
        self.show_password = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options,
            text="Show passphrases",
            variable=self.show_password,
            command=self.password_visibility,
        ).grid(row=6, column=1, sticky="w")
        self.existing = self.entry(options, 7, "Existing key (optional)", "existing_key")
        self.action(options, "Choose existing key…", self.choose_key).grid(
            row=8, column=1, sticky="w"
        )
        self.input_password = self.entry(
            options, 9, "Existing key passphrase", "existing_passphrase", secret=True
        )
        ttk.Label(
            options,
            text="For renewal, the existing key determines the algorithm.\n"
            "Output encryption is independent; the original key is never overwritten.",
            wraplength=500,
        ).grid(row=10, column=0, columnspan=2, sticky="w", pady=4)
        self.self_signed = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options, text="Also create self-signed certificate", variable=self.self_signed
        ).grid(row=11, column=0, columnspan=2, sticky="w")
        self.days = self.entry(options, 12, "Certificate validity (days)", "validity_days", "365")
        output = self.group(content, "Output")
        self.destination = self.entry(output, 0, "Folder", "destination", str(Path.home() / "csrs"))
        self.action(output, "Browse…", self.choose_destination).grid(row=1, column=1, sticky="w")
        buttons = ttk.Frame(content, padding=12)
        buttons.pack(fill="x")
        self.action(buttons, "Generate key and CSR", self.generate).pack(side="left")
        self.action(buttons, "Open last output folder", self.open_folder).pack(side="left", padx=8)

    def scroll_form(self, event):
        if isinstance(event.widget, tk.Text):
            return
        parent = event.widget
        while parent is not None and parent not in (self.form_content, self.form_canvas):
            parent = getattr(parent, "master", None)
        if parent is None:
            return
        direction = -1 if getattr(event, "num", None) == 4 or getattr(event, "delta", 0) > 0 else 1
        self.form_canvas.yview_scroll(direction * 3, "units")

    def ensure_visible(self, event):
        widget = event.widget
        parent = widget
        while parent is not None and parent is not self.form_content:
            parent = getattr(parent, "master", None)
        if parent is None:
            return
        self.root.update_idletasks()
        y = widget.winfo_rooty() - self.form_content.winfo_rooty()
        height = max(self.form_content.winfo_height(), 1)
        top = self.form_canvas.canvasy(0)
        if y < top or y + widget.winfo_height() > top + self.form_canvas.winfo_height():
            self.form_canvas.yview_moveto(max(0, y - 20) / height)

    def algorithm_changed(self, *_):
        ed = self.algorithm.get() == ALGORITHMS["ed25519"]
        if ed:
            self.digest.set("auto")
        self.digest_box.configure(state="disabled" if ed else "readonly")

    def encryption_changed(self):
        if not self.encrypted.get():
            self.password.set("")
            self.confirm.set("")
        for name in ("passphrase", "confirm"):
            self.fields[name].configure(state="normal" if self.encrypted.get() else "disabled")

    def password_visibility(self):
        for name in ("passphrase", "confirm", "existing_passphrase"):
            self.fields[name].configure(show="" if self.show_password.get() else "*")

    def choose_key(self):
        path = filedialog.askopenfilename(title="Existing PEM private key")
        if path:
            self.existing.set(path)
            self.digest.set("auto")

    def choose_destination(self):
        path = filedialog.askdirectory(title="Output folder")
        if path:
            self.destination.set(path)

    def add_cn(self):
        import ipaddress

        value = self.subject_vars["common_name"].get().strip()
        if not value:
            return
        try:
            ipaddress.ip_address(value)
            target = self.ips
        except ValueError:
            target = self.dns
        values = target.get("1.0", "end-1c").splitlines()
        if value not in values:
            self.set_text(target, "\n".join([*filter(None, values), value]))

    def request(self, metadata_only=False):
        if not metadata_only and self.password.get() != self.confirm.get():
            raise ValidationError("Passphrases do not match.", "confirm")
        try:
            days = int(self.days.get())
        except ValueError as exc:
            raise ValidationError(
                "Validity must be a whole number of days.", "validity_days"
            ) from exc
        algorithm = next(key for key, label in ALGORITHMS.items() if label == self.algorithm.get())
        request = Request(
            subject=Subject(**{name: value.get() for name, value in self.subject_vars.items()}),
            dns_names=tuple(
                v.strip() for v in self.dns.get("1.0", "end-1c").splitlines() if v.strip()
            ),
            ip_addresses=tuple(
                v.strip() for v in self.ips.get("1.0", "end-1c").splitlines() if v.strip()
            ),
            algorithm=algorithm,
            digest=self.digest.get(),
            profile=self.profile.get(),
            self_signed=self.self_signed.get(),
            validity_days=days,
            encrypt_key=self.encrypted.get() if not metadata_only else False,
            passphrase=self.password.get() if not metadata_only else "",
            existing_key=(
                read_input(self.existing.get())
                if self.existing.get() and not metadata_only
                else None
            ),
            existing_passphrase=self.input_password.get() if not metadata_only else "",
        )
        return validate_request(request)

    def generate(self):
        try:
            request = self.request()
            if not self.destination.get().strip():
                raise ValidationError("Choose an output folder.", "destination")
            destination = Path(self.destination.get())
            if not request.encrypt_key and not messagebox.askyesno(
                "Unencrypted private key", "Anyone who can read this key file can use it. Continue?"
            ):
                return
            self.start(
                lambda: generate(request, destination, self.cancelled.is_set), self.generated
            )
        except ApplicationError as exc:
            self.error(exc)

    def generated(self, result):
        self.last_directory = result.directory
        self.password.set("")
        self.confirm.set("")
        self.input_password.set("")
        self.status.set(f"Created {len(result.files)} files in {result.directory.name}")
        messagebox.showinfo(
            "Generation complete", "Verified and saved:\n\n" + "\n".join(map(str, result.files))
        )

    def open_folder(self):
        if self.last_directory is None:
            self.status.set("Generate a CSR first.")
            return
        try:
            path = str(self.last_directory)
            if sys.platform == "win32":
                os.startfile(path)
            else:
                subprocess.Popen(
                    ["open" if sys.platform == "darwin" else "xdg-open", path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        except OSError:
            self.error(ApplicationError(f"Open this folder manually: {self.last_directory}"))

    def save_profile(self):
        try:
            request = self.request(metadata_only=True)
            path = filedialog.asksaveasfilename(
                defaultextension=".json", title="Save profile to a new file"
            )
            if path:
                save_profile(Path(path), request)
                self.status.set("Saved profile without secrets or key paths.")
        except ApplicationError as exc:
            self.error(exc)

    def load_profile(self):
        path = filedialog.askopenfilename(filetypes=[("JSON profiles", "*.json")])
        if not path:
            return
        try:
            request = load_profile(read_input(path, 65536))
            for name, variable in self.subject_vars.items():
                variable.set(getattr(request.subject, name))
            self.set_text(self.dns, "\n".join(request.dns_names))
            self.set_text(self.ips, "\n".join(request.ip_addresses))
            self.algorithm.set(ALGORITHMS[request.algorithm])
            self.digest.set(request.digest)
            self.profile.set(request.profile)
            self.days.set(str(request.validity_days))
            self.self_signed.set(request.self_signed)
            for variable in (self.password, self.confirm, self.input_password, self.existing):
                variable.set("")
            self.encrypted.set(True)
            self.encryption_changed()
            self.status.set("Profile loaded. Enter a fresh passphrase.")
        except ApplicationError as exc:
            self.error(exc)

    def load_text(self, widget):
        path = filedialog.askopenfilename(title="Load PEM file")
        if path:
            try:
                self.set_text(widget, read_input(path).decode("utf-8"))
            except UnicodeError:
                self.error(ApplicationError("Use a UTF-8 / ASCII PEM file, not binary DER."))
            except ApplicationError as exc:
                self.error(exc)

    def copy_text(self, widget):
        self.root.clipboard_clear()
        self.root.clipboard_append(widget.get("1.0", "end-1c"))

    def build_inspector(self, title, kind):
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text=title)
        ttk.Label(tab, text="Paste PEM or load a file. Inspection does not establish trust.").pack(
            anchor="w"
        )
        source = self.text(tab, 9)
        source.pack(fill="both", expand=True, pady=8)
        bar = ttk.Frame(tab)
        bar.pack(fill="x")
        self.action(bar, "Load file", lambda: self.load_text(source)).pack(side="left")
        output = self.text(tab, 16, readonly=True)

        def decode(openssl=False):
            data = source.get("1.0", "end-1c").encode("utf-8")
            self.set_text(output, "")

            def work():
                if openssl:
                    from .openssl import OpenSSL

                    backend = OpenSSL()
                    return backend.version() + "\n\n" + backend.decode(data, kind)
                return inspect_pem(data, kind)

            self.start(work, lambda value: self.set_text(output, value))

        self.action(bar, "Inspect", decode).pack(side="left", padx=6)
        self.action(bar, "OpenSSL details", lambda: decode(True)).pack(side="left")
        self.action(
            bar, "Clear", lambda: (self.set_text(source, ""), self.set_text(output, ""))
        ).pack(side="left", padx=6)
        self.action(bar, "Copy result", lambda: self.copy_text(output)).pack(side="left")
        output.pack(fill="both", expand=True, pady=8)

    def build_bundle(self):
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="PEM / PKCS#12")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        tab.rowconfigure(4, weight=1)
        ttk.Label(
            tab, text="Certificates: leaf first, then intermediates, then optional root."
        ).grid(row=0, column=0, sticky="w")
        certs = self.text(tab, 7)
        certs.grid(row=1, column=0, sticky="nsew", pady=5)
        self.action(tab, "Load certificates", lambda: self.load_text(certs)).grid(
            row=2, column=0, sticky="w"
        )
        ttk.Label(tab, text="Private key (required for key, combined, or PKCS#12 exports)").grid(
            row=3, column=0, sticky="w", pady=(8, 0)
        )
        key = self.text(tab, 5)
        key.grid(row=4, column=0, sticky="nsew", pady=5)
        self.action(tab, "Load private key", lambda: self.load_text(key)).grid(
            row=5, column=0, sticky="w"
        )
        options = ttk.Frame(tab)
        options.grid(row=6, column=0, sticky="ew", pady=8)
        options.columnconfigure(1, weight=1)
        key_password = self.entry(options, 0, "Input key passphrase", "bundle_input", secret=True)
        export_password = self.entry(options, 1, "PKCS#12 passphrase", "bundle_output", secret=True)
        export_confirm = self.entry(
            options, 2, "Confirm PKCS#12 passphrase", "bundle_confirm", secret=True
        )
        mode = tk.StringVar(value="chain")
        ttk.Label(options, text="Export type").grid(row=3, column=0, sticky="w")
        ttk.Combobox(
            options,
            textvariable=mode,
            values=("chain", "key", "combined", "pkcs12"),
            state="readonly",
        ).grid(row=3, column=1, sticky="ew")
        include_root = tk.BooleanVar(value=False)
        spacing = tk.BooleanVar(value=True)
        ttk.Checkbutton(options, text="Include root certificate", variable=include_root).grid(
            row=4, column=0, sticky="w"
        )
        ttk.Checkbutton(options, text="Blank lines between PEM blocks", variable=spacing).grid(
            row=4, column=1, sticky="w"
        )
        ttk.Label(
            tab,
            text="Checks format, key match, and issuer linkage. "
            "Does not establish trust or check revocation.\n"
            "PEM exports preserve the input key’s encryption. "
            "PKCS#12 always requires a passphrase.",
            wraplength=600,
        ).grid(row=7, column=0, sticky="ew", pady=6)

        def export():
            if mode.get() == "pkcs12" and export_password.get() != export_confirm.get():
                self.error(ValidationError("PKCS#12 passphrases do not match.", "bundle_confirm"))
                return
            values = (
                certs.get("1.0", "end-1c").encode(),
                key.get("1.0", "end-1c").encode(),
                key_password.get(),
                mode.get(),
                include_root.get(),
                spacing.get(),
                export_password.get(),
            )

            def save(data):
                path = filedialog.asksaveasfilename(
                    title="Export to a new file (no overwrites)",
                    defaultextension=".p12" if values[3] == "pkcs12" else ".pem",
                )
                if path:
                    try:
                        save_exclusive(Path(path), data)
                        self.status.set(f"Saved {Path(path).name}")
                        key_password.set("")
                        export_password.set("")
                        export_confirm.set("")
                    except ApplicationError as exc:
                        self.error(exc)

            self.start(lambda: bundle(*values), save)

        buttons = ttk.Frame(tab)
        buttons.grid(row=8, column=0, sticky="ew")
        self.action(buttons, "Validate and export", export).pack(side="left")

        def clear():
            self.set_text(certs, "")
            self.set_text(key, "")
            for var in (key_password, export_password, export_confirm):
                var.set("")
            # Reset undo history so Clear also removes recoverable text from these widgets.
            certs.edit_reset()
            key.edit_reset()

        self.action(buttons, "Clear sensitive input", clear).pack(side="left", padx=8)

    def start(self, work, complete):
        if self.busy:
            return
        self.busy = True
        self.cancelled.clear()
        self.status.set("Working… Cancel waits for the current cryptographic step to finish.")
        for button in self.action_buttons:
            button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.progress.start()

        def run():
            try:
                self.events.put((complete, work(), None))
            except Exception as exc:
                # Do not log arbitrary exception values: parser failures can include input.
                error = (
                    exc
                    if isinstance(exc, ApplicationError)
                    else ApplicationError(
                        "Unexpected operation failure. No success has been confirmed."
                    )
                )
                self.events.put((complete, None, error))

        threading.Thread(target=run, daemon=True).start()

    def poll(self):
        try:
            complete, value, error = self.events.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            self.progress.stop()
            self.cancel_button.configure(state="disabled")
            for button in self.action_buttons:
                button.configure(state="normal")
            if self.closing:
                self.root.destroy()
                return
            if error:
                self.error(error)
            elif self.cancelled.is_set() and not hasattr(value, "directory"):
                self.status.set("Cancelled.")
            else:
                self.status.set("Complete.")
                complete(value)
        self.poll_id = self.root.after(100, self.poll)

    def cancel(self):
        self.cancelled.set()
        self.status.set("Cancelling after the current step…")

    def close(self):
        if self.busy:
            self.closing = True
            self.cancel()
        else:
            self.root.after_cancel(self.poll_id)
            self.root.destroy()

    def error(self, error):
        self.status.set(str(error))
        if isinstance(error, Cancelled):
            return
        widget = self.fields.get(getattr(error, "field", ""))
        if widget:
            widget.focus_set()
        messagebox.showerror("Operation could not complete", str(error))

    def toggle_theme(self):
        self.dark = not self.dark
        self.apply_theme()

    def apply_theme(self):
        bg, fg, entry, selected = (
            ("#252a33", "#f1f4f8", "#171c24", "#3865a0")
            if self.dark
            else ("#f3f5f8", "#18202c", "#ffffff", "#c7dcf6")
        )
        self.root.configure(bg=bg)
        self.style.configure(".", background=bg, foreground=fg)
        for name in ("TEntry", "TCombobox"):
            self.style.configure(name, fieldbackground=entry, foreground=fg, insertcolor=fg)
            self.style.map(
                name,
                fieldbackground=[("readonly", entry), ("disabled", bg)],
                foreground=[("readonly", fg), ("disabled", "#8993a3")],
            )
        self.style.map(
            "TButton", background=[("active", selected)], foreground=[("disabled", "#8993a3")]
        )
        self.style.map("TNotebook.Tab", background=[("selected", selected)])
        self.form_canvas.configure(bg=bg)
        for widget in self.text_widgets:
            widget.configure(
                bg=entry, fg=fg, insertbackground=fg, selectbackground=selected, selectforeground=fg
            )
        self.theme.configure(text="Light theme" if self.dark else "Dark theme")


def main():
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        raise SystemExit(
            "A graphical display and Tk are required. Use csr-generator --help for the CLI."
        ) from exc
    if "--smoke-test" in sys.argv:
        root.withdraw()
        app = Application(root)
        root.update()
        assert len(app.notebook.tabs()) == 5
        app.toggle_theme()
        app.close()
        return
    Application(root)
    root.mainloop()


if __name__ == "__main__":
    main()
