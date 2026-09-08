# Changelog

## 2.0.0 — 2026-09-08

Major modernization. Replaced shell-based generation with typed cryptography services;
fixed complete subjects, P-256 dispatch, key encryption, self-signing, SAN validation,
unsafe paths, overwrite risk, and decoder temporary files. Added structured validation,
private output storage, existing-key renewal, self-signed usage profiles, PKCS#12,
validated PEM export, allowlisted profiles, and a headless CLI.

Rebuilt the Tk UI with background work and responsive layouts. Added regression,
OpenSSL integration, Tk, and frozen application smoke tests. Replaced placeholder
AppImage packaging, unified Windows/Linux builds, pinned build dependencies/actions,
and removed automatic release publishing. Updated installation, security, architecture,
and build documentation. V1 screenshots are retained as historical material.

Breaking changes: Python 3.11+; output files use fixed safe names inside unique folders;
keys are encrypted by default across algorithms; TLS server SANs are required;
SHA-1 removed; malformed/empty bundles rejected; exports never overwrite files.

### User-facing v2 highlights

- Complete subject information and validated DNS/IPv4/IPv6 SANs.
- RSA 2048/4096, ECDSA P-256/P-384/P-521, and Ed25519.
- Encrypted PKCS#8 private keys by default, including EC and Ed25519.
- Optional existing-key renewal and purpose-specific self-signed certificates.
- Unique output directories and exclusive exports: existing keys are never overwritten.
- Background GUI jobs, cancellation, resizable forms, light/dark themes, and profiles without secrets.
- CSR signature verification, certificate summaries, optional OpenSSL text decoding.
- PEM syntax/key-match/issuer-linkage checks and encrypted PKCS#12 export.
- A reusable Python core, command-line interface, regression tests, and artifact-only CI.
