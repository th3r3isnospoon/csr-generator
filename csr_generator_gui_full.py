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
root.title("CSR Generator v1.0")
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
            if isinstance(widget, (tk.Text, scrolledtext.ScrolledText)):
                current_text = widget.get("1.0", tk.END)
                widget.configure(bg=entry_bg, fg=fg, insertbackground=fg)
                widget.delete("1.0", tk.END)
                widget.insert("1.0", current_text)
            elif isinstance(widget, tk.Button):
                widget.configure(bg=bg, fg=fg, activebackground=bg)

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

# --- Placeholder Helper ---
def add_placeholder(entry, placeholder_text):
    def on_focus_in(event):
        if entry.get() == placeholder_text:
            entry.delete(0, tk.END)
            entry.config(fg="black")
    def on_focus_out(event):
        if not entry.get():
            entry.insert(0, placeholder_text)
            entry.config(fg="gray")
    entry.insert(0, placeholder_text)
    entry.config(fg="gray")
    entry.bind("<FocusIn>", on_focus_in)
    entry.bind("<FocusOut>", on_focus_out)
# --- CSR Variables ---
cn_var = tk.StringVar()
pass_var = tk.StringVar()
key_type_var = tk.StringVar(value="ECC (secp384r1) - Recommended")
c_var = tk.StringVar()
st_var = tk.StringVar()
l_var = tk.StringVar()
o_var = tk.StringVar()
ou_var = tk.StringVar()
email_var = tk.StringVar()
dns_vars = [tk.StringVar() for _ in range(3)]
ip_vars = [tk.StringVar() for _ in range(3)]
ip_checkbox_var = tk.BooleanVar()
save_path_var = tk.StringVar(value=os.path.expanduser("~/csrs"))
self_signed_var = tk.BooleanVar()
row = 0

def label(text):
    global row
    ttk.Label(frm, text=text).grid(row=row, column=0, sticky="w")
    row += 1

# --- Entry Fields ---
label("Common Name (CN):")
cn_entry = tk.Entry(frm, width=50, textvariable=cn_var)
cn_entry.grid(row=row-1, column=1, columnspan=2, sticky="w")
add_placeholder(cn_entry, "example.arubademo.com")

label("Passphrase for Key:")
pass_entry = tk.Entry(frm, textvariable=pass_var, width=30, show="*")
pass_entry.grid(row=row-1, column=1, sticky="w")

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

# --- Subject Info ---
for lbl, var, ph in zip(
    ["Country (C):", "State (ST):", "City (L):", "Organization (O):", "Org Unit (OU):", "Email:"],
    [c_var, st_var, l_var, o_var, ou_var, email_var],
    ["US", "MA", "MARBLEHEAD", "STATE", "IT", "binky1@gmail.com"]
):
    label(lbl)
    entry = tk.Entry(frm, textvariable=var, width=40)
    entry.grid(row=row-1, column=1, columnspan=2, sticky="w")
    add_placeholder(entry, ph)

# --- SANs ---
label("Subject Alternative Names (SANs):")
for i in range(3):
    label(f"DNS.{i+1}:")
    entry = tk.Entry(frm, textvariable=dns_vars[i], width=40)
    entry.grid(row=row-1, column=1, columnspan=2, sticky="w")
    add_placeholder(entry, f"dns{i+1}.arubademo.com")

ttk.Checkbutton(frm, text="Include IP SANs", variable=ip_checkbox_var).grid(row=row, column=0, sticky="w")
row += 1
ip_entries = []
for i in range(3):
    ttk.Label(frm, text=f"IP.{i+1}:").grid(row=row, column=0, sticky="w")
    entry = tk.Entry(frm, textvariable=ip_vars[i], width=40)
    entry.grid(row=row, column=1, columnspan=2, sticky="w")
    add_placeholder(entry, f"192.168.1.{i+10}")
    ip_entries.append(entry)
    row += 1

def toggle_ips(*_):
    for entry in ip_entries:
        entry.configure(state="normal" if ip_checkbox_var.get() else "disabled")
ip_checkbox_var.trace_add("write", toggle_ips)
toggle_ips()

# --- Save path and self-signed cert checkbox ---
label("Save To:")
ttk.Entry(frm, textvariable=save_path_var, width=40).grid(row=row-1, column=1)
ttk.Button(frm, text="Browse", command=lambda: save_path_var.set(filedialog.askdirectory())).grid(row=row-1, column=2)

ttk.Checkbutton(frm, text="Generate self-signed certificate", variable=self_signed_var).grid(row=row, column=0, columnspan=2, sticky="w")
row += 1

def valid_email(email): return re.match(r"[^@]+@[^@]+\\.[^@]+", email)
def valid_ip(ip): return re.match(r"^\\d{1,3}(\\.\\d{1,3}){3}$", ip)

def generate():
    cn = cn_var.get().strip()
    passwd = pass_var.get().strip()
    email = email_var.get().strip()
    if not cn or not passwd:
        messagebox.showerror("Missing", "Common Name and Passphrase are required")
        return
    if not valid_email(email):
        messagebox.showerror("Invalid Email", "Please enter a valid email address.")
        return
    for ip in ip_vars:
        ipval = ip.get().strip()
        if ipval and not valid_ip(ipval):
            messagebox.showerror("Invalid IP", f"Invalid IP: {ipval}")
            return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
    outdir = os.path.join(save_path_var.get(), f"{cn}_{timestamp}")
    os.makedirs(outdir, exist_ok=True)
    csr_file = os.path.join(outdir, f"{cn}.csr")
    key_file = os.path.join(outdir, f"{cn}.key")
    crt_file = os.path.join(outdir, f"{cn}.crt")
    conf_file = os.path.join(outdir, "openssl.conf")

    san_lines = []
    for i, dns in enumerate(dns_vars, 1):
        if dns.get().strip():
            san_lines.append(f"DNS.{i} = {dns.get().strip()}")
    if ip_checkbox_var.get():
        for i, ip in enumerate(ip_vars, 1):
            if ip.get().strip():
                san_lines.append(f"IP.{i} = {ip.get().strip()}")

    with open(conf_file, "w") as f:
        f.write("[req]\\ndefault_bits = 4096\\nprompt = no\\ndefault_md = sha512\\n")
        if san_lines: f.write("req_extensions = req_ext\\n")
        f.write("distinguished_name = dn\\n\\n[ dn ]\\n")
        f.write(f"C={c_var.get()}\\nST={st_var.get()}\\nL={l_var.get()}\\nO={o_var.get()}\\nOU={ou_var.get()}\\nemailAddress={email}\\nCN={cn}\\n")
        if san_lines:
            f.write("\\n[ req_ext ]\\nsubjectAltName = @alt_names\\n\\n[ alt_names ]\\n")
            for line in san_lines:
                f.write(line + "\\n")

    try:
        if "secp" in key_type_var.get():
            curve = key_type_var.get().split("(")[1].split(")")[0]
            subprocess.run(f"openssl ecparam -name {curve} -genkey -out '{key_file}'", shell=True, check=True)
            subprocess.run(f"openssl req -new -passout pass:'{passwd}' -subj /CN={cn} -key '{key_file}' -out '{csr_file}' -sha512 -config '{conf_file}'", shell=True, check=True)
        elif "RSA" in key_type_var.get():
            bits = "4096" if "4096" in key_type_var.get() else "2048"
            subprocess.run(f"openssl req -new -passout pass:'{passwd}' -subj /CN={cn} -newkey rsa:{bits} -keyout '{key_file}' -out '{csr_file}' -sha512 -config '{conf_file}'", shell=True, check=True)
        elif "Ed25519" in key_type_var.get() and ed25519_supported:
            subprocess.run(f"openssl genpkey -algorithm Ed25519 -out '{key_file}'", shell=True, check=True)
            subprocess.run(f"openssl req -new -subj /CN={cn} -key '{key_file}' -out '{csr_file}' -config '{conf_file}'", shell=True, check=True)
        if self_signed_var.get():
            subprocess.run(f"openssl x509 -req -days 365 -in '{csr_file}' -signkey '{key_file}' -out '{crt_file}' -extfile '{conf_file}' -extensions req_ext", shell=True, check=True)

        messagebox.showinfo("Success", f"Files saved to: {outdir}")
    except subprocess.CalledProcessError:
        messagebox.showerror("OpenSSL Error", "An error occurred during CSR or cert generation.")

ttk.Button(frm, text="Generate CSR", command=generate).grid(row=row, column=0, pady=10)

# --- CSR Viewer ---
csr_input = scrolledtext.ScrolledText(viewer_tab, height=10, width=90)
csr_output = scrolledtext.ScrolledText(viewer_tab, height=20, width=90)
ttk.Label(viewer_tab, text="Paste CSR:").pack(anchor="w", padx=10)
csr_input.pack(padx=10, pady=5, fill=tk.X)
ttk.Button(viewer_tab, text="Decode CSR", command=lambda: decode_csr()).pack()
ttk.Label(viewer_tab, text="Decoded Output:").pack(anchor="w", padx=10)
csr_output.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

def decode_csr():
    with open("/tmp/tmpcsr.csr", "w") as f:
        f.write(csr_input.get("1.0", tk.END))
    try:
        out = subprocess.check_output(["openssl", "req", "-in", "/tmp/tmpcsr.csr", "-noout", "-text"], text=True)
        csr_output.delete("1.0", tk.END)
        csr_output.insert(tk.END, out)
    except subprocess.CalledProcessError:
        csr_output.insert(tk.END, "Invalid CSR or OpenSSL error.")

# --- Certificate Decoder ---
cert_input = scrolledtext.ScrolledText(cert_tab, height=10, width=90)
cert_output = scrolledtext.ScrolledText(cert_tab, height=20, width=90)
ttk.Label(cert_tab, text="Paste Certificate:").pack(anchor="w", padx=10)
cert_input.pack(padx=10, pady=5, fill=tk.X)
ttk.Button(cert_tab, text="Decode Certificate", command=lambda: decode_cert()).pack()
ttk.Label(cert_tab, text="Decoded Output:").pack(anchor="w", padx=10)
cert_output.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

def decode_cert():
    with open("/tmp/tmpcert.pem", "w") as f:
        f.write(cert_input.get("1.0", tk.END))
    try:
        out = subprocess.check_output(["openssl", "x509", "-in", "/tmp/tmpcert.pem", "-noout", "-text"], text=True)
        cert_output.delete("1.0", tk.END)
        cert_output.insert(tk.END, out)
    except subprocess.CalledProcessError:
        cert_output.insert(tk.END, "Invalid certificate or OpenSSL error.")

# --- PEM Builder ---
pem_key = scrolledtext.ScrolledText(pem_tab, height=6, width=90)
pem_cert = scrolledtext.ScrolledText(pem_tab, height=6, width=90)
pem_chain = scrolledtext.ScrolledText(pem_tab, height=6, width=90)
pem_root = scrolledtext.ScrolledText(pem_tab, height=6, width=90)
ttk.Label(pem_tab, text="Private Key").pack(anchor="w", padx=10)
pem_key.pack(padx=10)
ttk.Label(pem_tab, text="End-Entity Certificate (Optional)").pack(anchor="w", padx=10)
pem_cert.pack(padx=10)
ttk.Label(pem_tab, text="Intermediate Certificate(s)").pack(anchor="w", padx=10)
pem_chain.pack(padx=10)
ttk.Label(pem_tab, text="Root Certificate (Optional)").pack(anchor="w", padx=10)
pem_root.pack(padx=10)

include_end_cert = tk.BooleanVar(value=True)
newline_spacing = tk.BooleanVar(value=True)
ttk.Checkbutton(pem_tab, text="Include end-entity cert at top", variable=include_end_cert).pack(anchor="w", padx=10)
ttk.Checkbutton(pem_tab, text="Append with newline spacing", variable=newline_spacing).pack(anchor="w", padx=10)
ttk.Button(pem_tab, text="Build .PEM", command=lambda: build_pem()).pack(pady=10)

def build_pem():
    parts = []
    if include_end_cert.get():
        parts.append(pem_cert.get("1.0", tk.END).strip())
    parts.append(pem_chain.get("1.0", tk.END).strip())
    parts.append(pem_root.get("1.0", tk.END).strip())
    parts.append(pem_key.get("1.0", tk.END).strip())
    joined = "\n\n".join(filter(None, parts)) if newline_spacing.get() else "\n".join(filter(None, parts))
    outdir = filedialog.askdirectory(title="Save .PEM to folder")
    if not outdir:
        return
    outfile = os.path.join(outdir, f"combined_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pem")
    try:
        with open(outfile, "w") as f:
            f.write(joined + "\n")
        messagebox.showinfo("PEM Created", f"PEM saved to:\n{outfile}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# --- About Tab ---
about_text = """CSR Generator v1.0

Created by: Mike Binkowski
GitHub: https://github.com/th3r3isnospoon
MIT Licensed"""
tk.Label(about_tab, text=about_text, justify="left", padx=10, pady=10).pack(anchor="nw")

# --- Launch App ---
apply_theme()
root.mainloop()
