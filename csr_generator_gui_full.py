#!/usr/bin/env python3
import os
import subprocess
import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import re

# Check Ed25519 support
openssl_ver = subprocess.getoutput("openssl version")
ed25519_supported = "OpenSSL 3" in openssl_ver or "OpenSSL 1.1.1" in openssl_ver

root = tk.Tk()
root.title("CSR Generator v1.1-dev")
root.geometry("720x720")

style = ttk.Style()
style.theme_use("default")
dark_mode = tk.BooleanVar(value=False)

# --- Dark Mode Toggle ---
def apply_theme():
    is_dark = dark_mode.get()
    bg = "#2e2e2e" if is_dark else "lightgray"
    fg = "white" if is_dark else "black"
    entry_bg = "#3c3c3c" if is_dark else "white"

    root.configure(bg=bg)
    header.configure(bg=bg)
    theme_button.configure(bg=bg, fg=fg)

    style.theme_use("clam" if is_dark else "default")
    style.configure("TFrame", background=bg)
    style.configure("TLabel", background=bg, foreground=fg)
    style.configure("TEntry", fieldbackground=entry_bg, foreground=fg)
    style.configure("TCheckbutton", background=bg, foreground=fg)
    style.configure("TCombobox", fieldbackground=entry_bg, foreground=fg)
    style.map("TCombobox", fieldbackground=[("readonly", entry_bg)], foreground=[("readonly", fg)])

    for container in [frm, viewer_tab, cert_tab, pem_tab, about_tab]:
        for widget in container.winfo_children():
            cls = widget.__class__.__name__
            if cls in ("Text", "ScrolledText"):
                current_text = widget.get("1.0", tk.END)
                widget.configure(bg=entry_bg, fg=fg, insertbackground=fg)
                widget.delete("1.0", tk.END)
                widget.insert("1.0", current_text)
            elif cls == "Button" and isinstance(widget, tk.Button):
                widget.configure(bg=bg, fg=fg, activebackground=bg)

# --- Header with theme toggle ---
def toggle_dark_icon():
    dark_mode.set(not dark_mode.get())
    theme_button.config(text="🌙" if not dark_mode.get() else "☀️")
    apply_theme()

header = tk.Frame(root)
header.pack(fill=tk.X, anchor="ne")
theme_button = tk.Button(header, text="🌙", command=toggle_dark_icon)
theme_button.pack(side="right", padx=5, pady=5)

# --- Tabs ---
notebook = ttk.Notebook(root)
frm = ttk.Frame(notebook)
viewer_tab = ttk.Frame(notebook)
cert_tab = ttk.Frame(notebook)
pem_tab = ttk.Frame(notebook)
about_tab = ttk.Frame(notebook)
notebook.add(frm, text="Generate CSR")
notebook.add(viewer_tab, text="CSR Viewer")
notebook.add(cert_tab, text="Cert Decoder")
notebook.add(pem_tab, text="PEM Builder")
notebook.add(about_tab, text="About")
notebook.pack(fill=tk.BOTH, expand=True)

# --- CSR Tab Fields ---
cn_var = tk.StringVar()
pass_var = tk.StringVar()
key_type_var = tk.StringVar(value="ECC (secp384r1) - Recommended")
hash_alg_var = tk.StringVar(value="SHA-512 (Recommended)")
c_var = tk.StringVar(value="US")
st_var = tk.StringVar(value="MA")
l_var = tk.StringVar(value="MARBLEHEAD")
o_var = tk.StringVar(value="STATE")
ou_var = tk.StringVar(value="IT")
email_var = tk.StringVar(value="csr@example.com")
dns_vars = [tk.StringVar() for _ in range(3)]
ip_checkbox_var = tk.BooleanVar()
ip_vars = [tk.StringVar() for _ in range(3)]
save_path_var = tk.StringVar(value=os.path.expanduser("~/csrs"))
self_signed_var = tk.BooleanVar()

row = 0
def label(text):
    global row
    ttk.Label(frm, text=text).grid(row=row, column=0, sticky="w")
    row += 1

label("Common Name (CN):")
ttk.Entry(frm, textvariable=cn_var, width=50).grid(row=row-1, column=1, columnspan=2, sticky="w")
label("Passphrase for Key:")
ttk.Entry(frm, textvariable=pass_var, width=30, show="*").grid(row=row-1, column=1, sticky="w")

label("Key Type:")
key_opts = [
    "ECC (secp521r1) - Strongest ECC",
    "ECC (secp384r1) - Recommended",
    "ECC (prime256v1) - Widely compatible",
    "RSA (4096-bit) - Strong, slower",
    "RSA (2048-bit) - Standard compatibility"
]
if ed25519_supported:
    key_opts.append("Ed25519 (experimental - mostly for SSH)")
else:
    key_opts.append("Ed25519 (unsupported - SSH only)")
ttk.Combobox(frm, textvariable=key_type_var, values=key_opts, width=45, state="readonly").grid(row=row-1, column=1, columnspan=2, sticky="w")

# New: Hash Algorithm dropdown
label("Hash Algorithm:")
hash_opts = [
    "SHA-512 (Recommended)",
    "SHA-384",
    "SHA-256",
    "SHA-1 (Deprecated)"
]
ttk.Combobox(frm, textvariable=hash_alg_var, values=hash_opts, width=45, state="readonly").grid(row=row-1, column=1, columnspan=2, sticky="w")

# Org info
for lbl, var in zip(["Country (C):", "State (ST):", "City (L):", "Organization (O):", "Org Unit (OU):", "Email:"],
                    [c_var, st_var, l_var, o_var, ou_var, email_var]):
    label(lbl)
    ttk.Entry(frm, textvariable=var, width=40).grid(row=row-1, column=1, columnspan=2, sticky="w")

label("Subject Alternative Names (SANs):")
for i in range(3):
    label(f"DNS.{i+1}:")
    ttk.Entry(frm, textvariable=dns_vars[i], width=40).grid(row=row-1, column=1, columnspan=2, sticky="w")

ttk.Checkbutton(frm, text="Include IP SANs", variable=ip_checkbox_var).grid(row=row, column=0, sticky="w")
row += 1
ip_entries = []
for i in range(3):
    ttk.Label(frm, text=f"IP.{i+1}:").grid(row=row, column=0, sticky="w")
    entry = ttk.Entry(frm, textvariable=ip_vars[i], width=40)
    entry.grid(row=row, column=1, columnspan=2, sticky="w")
    ip_entries.append(entry)
    row += 1

def toggle_ips(*_):
    for entry in ip_entries:
        entry.configure(state="normal" if ip_checkbox_var.get() else "disabled")
ip_checkbox_var.trace_add("write", toggle_ips)
toggle_ips()

label("Save To:")
ttk.Entry(frm, textvariable=save_path_var, width=40).grid(row=row-1, column=1)
ttk.Button(frm, text="Browse", command=lambda: save_path_var.set(filedialog.askdirectory())).grid(row=row-1, column=2)

ttk.Checkbutton(frm, text="Generate self-signed certificate", variable=self_signed_var).grid(row=row, column=0, columnspan=2, sticky="w")
row += 1
ttk.Button(frm, text="Generate CSR", command=lambda: generate()).grid(row=row, column=0, pady=10)

# --- ABOUT TAB ---
about_text = """CSR Generator v1.1-dev

Created by Mike Binkowski
GitHub: https://github.com/th3r3isnospoon
MIT Licensed"""
tk.Label(about_tab, text=about_text, justify="left", padx=10, pady=10).pack(anchor="nw")

# --- Generate CSR Logic ---
def generate():
    cn = cn_var.get().strip()
    passwd = pass_var.get().strip()
    email = email_var.get().strip()
    hash_map = {
        "SHA-512": "-sha512",
        "SHA-384": "-sha384",
        "SHA-256": "-sha256",
        "SHA-1": "-sha1"
    }
    hash_sel = hash_alg_var.get().split()[0]  # Pull "SHA-512" from "SHA-512 (Recommended)"
    hash_flag = hash_map.get(hash_sel, "-sha512")

    if not cn or not passwd:
        messagebox.showerror("Missing", "Common Name and Passphrase are required")
        return
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        messagebox.showerror("Invalid Email", "Please enter a valid email address.")
        return
    for ip in ip_vars:
        ipval = ip.get().strip()
        if ipval and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ipval):
            messagebox.showerror("Invalid IP", f"Invalid IP: {ipval}")
            return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    outdir = os.path.join(save_path_var.get(), f"{cn}_{timestamp}")
    os.makedirs(outdir, exist_ok=True)
    csr_file = os.path.join(outdir, f"{cn}.csr")
    key_file = os.path.join(outdir, f"{cn}.key")
    crt_file = os.path.join(outdir, f"{cn}.crt")
    conf_file = os.path.join(outdir, "openssl.conf")

    with open(conf_file, "w") as f:
        f.write("[req]\nprompt = no\ndefault_md = sha512\nreq_extensions = req_ext\ndistinguished_name = dn\n\n[ dn ]\n")
        f.write(f"C={c_var.get()}\nST={st_var.get()}\nL={l_var.get()}\nO={o_var.get()}\nOU={ou_var.get()}\nemailAddress={email}\nCN={cn}\n")
        f.write("\n[ req_ext ]\nsubjectAltName = @alt_names\n\n[ alt_names ]\n")
        for i, dns in enumerate(dns_vars, 1):
            if dns.get():
                f.write(f"DNS.{i} = {dns.get()}\n")
        if ip_checkbox_var.get():
            for i, ip in enumerate(ip_vars, 1):
                if ip.get():
                    f.write(f"IP.{i} = {ip.get()}\n")

    try:
        if "secp" in key_type_var.get():
            curve = key_type_var.get().split("(")[1].split(")")[0]
            subprocess.run(f"openssl ecparam -name {curve} -genkey -out '{key_file}'", shell=True, check=True)
            subprocess.run(f"openssl req -new -passout pass:'{passwd}' -subj /CN={cn} -key '{key_file}' -out '{csr_file}' {hash_flag} -config '{conf_file}'", shell=True, check=True)
        elif "RSA" in key_type_var.get():
            bits = "4096" if "4096" in key_type_var.get() else "2048"
            subprocess.run(f"openssl req -new -passout pass:'{passwd}' -subj /CN={cn} -newkey rsa:{bits} -keyout '{key_file}' -out '{csr_file}' {hash_flag} -config '{conf_file}'", shell=True, check=True)
        elif "Ed25519" in key_type_var.get() and ed25519_supported:
            subprocess.run(f"openssl genpkey -algorithm Ed25519 -out '{key_file}'", shell=True, check=True)
            subprocess.run(f"openssl req -new -subj /CN={cn} -key '{key_file}' -out '{csr_file}' -config '{conf_file}'", shell=True, check=True)

        if self_signed_var.get():
            subprocess.run(f"openssl x509 -req -days 365 -in '{csr_file}' -signkey '{key_file}' -out '{crt_file}' -extfile '{conf_file}' -extensions req_ext", shell=True, check=True)

        messagebox.showinfo("Success", f"Files saved to: {outdir}")
    except subprocess.CalledProcessError:
        messagebox.showerror("OpenSSL Error", "An error occurred during CSR or cert generation.")

# --- Run App ---
apply_theme()
root.mainloop()
