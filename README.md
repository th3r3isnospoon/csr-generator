# CSR Generator 2.0

A local desktop application and CLI for generating certificate signing requests,
inspecting CSRs/certificates, and exporting validated PEM or PKCS#12 bundles.
No accounts, telemetry, cloud service, or network access are used by the application.

## What changed in v2

- Complete subject information and validated DNS/IPv4/IPv6 SANs.
- RSA 2048/4096, ECDSA P-256/P-384/P-521, and Ed25519.
- Encrypted PKCS#8 private keys by default, including EC and Ed25519.
- Optional existing-key renewal and purpose-specific self-signed certificates.
- Unique output directories and exclusive exports: existing keys are never overwritten.
- Background GUI jobs, cancellation, resizable forms, light/dark themes, and profiles without secrets.
- CSR signature verification, certificate summaries, optional OpenSSL text decoding.
- PEM syntax/key-match/issuer-linkage checks and encrypted PKCS#12 export.
- A reusable Python core, command-line interface, regression tests, and artifact-only CI.

## Preview

![V2 generation form](screenshots/v2-generate.png)
![V2 bundle builder in dark mode](screenshots/v2-bundle-dark.png)

Other images in `screenshots/` are retained as historical v1 screenshots.

## Install from source

Python **3.11–3.14** is the intended support range. Python 3.12 is used for binary builds.
The GUI requires Tk; the CLI does not require a display. Runtime dependencies are
`cryptography` and `idna`. The external `openssl` executable is optional for detailed
inspection and required to run the independent integration tests.

On Debian/Ubuntu, install `python3`, `python3-venv`, and `python3-tk` through your package manager.
Then, from this checkout:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
csr-generator-gui
```

On Windows, use Python from python.org with Tcl/Tk enabled:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install .
.venv\Scripts\csr-generator-gui.exe
```

On macOS, a python.org Python installation includes Tk. Source/CLI support is tested
in the CI matrix; a signed/notarized macOS app is not provided.

From a checkout with dependencies installed, `python csr_generator_gui_full.py`
remains a compatibility launcher. You can also use `csr-generator gui`.

## Generate a CSR

1. Enter the common name and any organization fields required by your CA.
2. Add DNS and/or IP SANs. **TLS server** requests require at least one SAN; the
   “Add common name as SAN” button can populate the appropriate list.
3. Choose a key algorithm your CA and consuming application accept. P-256 is the
   default; automatic digest selection uses SHA-256 for RSA/P-256, SHA-384 for
   P-384, SHA-512 for P-521, and no separate digest for Ed25519.
4. Enter and confirm an output passphrase, or explicitly choose an unencrypted key.
   Spaces in passphrases are preserved exactly.
5. Choose an output folder and generate.

Each successful run creates a unique `csr-<UTC time>-<random suffix>/` containing:

- `private-key.pem`: encrypted PKCS#8 by default.
- `request.csr`: submit this to your CA, **not** the private key.
- `certificate.crt`: present only when self-signing is selected.

The common name is never used as a filename. Failed/cancelled operations clean up
staging directories on handled failures. Cancellation waits for a cryptographic step
to finish; it cannot interrupt the library's key-generation call. Once publication
has completed, cancellation does not delete a successful result.

For renewal, choose an existing PEM key and provide its passphrase if encrypted.
The existing key determines the algorithm. The output key is reserialized with the
chosen output encryption; the original file is never modified.

Self-signed certificates are **end-entity certificates, not root CAs**. TLS server
and client profiles set the corresponding extended key usage. Generic mode permits
no SANs and omits extended key usage. Validity is configurable from 1 to 3650 days;
these are local settings, not a promise that a public CA will issue the same certificate.

## Inspect and export

The CSR viewer verifies the CSR's self-signature. The certificate decoder reports
subject, issuer, SAN/extensions, validity, and SHA-256 fingerprints. A valid signature
or a decoded certificate does **not** prove identity or establish trust.

For PEM / PKCS#12 exports, provide certificates in **leaf → intermediates → root** order.
The application rejects malformed input, duplicate certificates, invalid adjacent
issuer signatures, and key/leaf mismatches. It checks issuer CA constraints and
certificate-signing key usage when present. It does not perform full RFC 5280 path
validation, revocation, hostname, policy, or trust-store checks.

Choose:

- **chain**: certificates only; root omitted by default when it is the final self-signed issuer.
- **key**: private key only, preserving input encryption.
- **combined**: certificates followed by the key, preserving input encryption.
- **pkcs12**: an encrypted `.p12` containing the key, leaf, and supplied chain.

A standalone self-signed leaf is retained even when “include root” is off. Root
inclusion and combined-PEM layout depend on the consuming application. Exporting
to an existing filename is refused; choose a new name. Use “Clear sensitive input”
to clear pasted keys and their text-widget undo history.

## CLI

```sh
csr-generator generate --cn example.com --dns example.com --dns www.example.com --output ./csrs
csr-generator generate --cn localhost --dns localhost --ip ::1 --self-signed --output ./csrs
csr-generator inspect csr ./request.csr
csr-generator inspect certificate ./certificate.crt --openssl
csr-generator bundle --certificates ./chain.pem --output ./fullchain.pem
csr-generator bundle --certificates ./chain.pem --key ./key.pem --key-encrypted --mode pkcs12 --output ./server.p12
```

Passphrases are prompted and never accepted as command-line arguments. Use
`--unencrypted` only when an unencrypted output key is intentional. For existing
keys, use `--existing-key` and, if needed, `--existing-key-encrypted`.
`--profile-file profile.json` loads a GUI-saved profile; explicit CLI fields override it.
Run `csr-generator <command> --help` for all options. Errors return a nonzero exit code.

## Security and limits

- Protect output folders. POSIX output directories are `0700` and files are `0600`.
  On Windows, v2 removes inherited ACL entries and grants the current user full
  access on new output objects before writing secrets, using System32 `whoami` and
  `icacls`. If this fails, the operation stops. Administrator access is not prevented;
  actual Windows behavior still needs target-platform validation.
- Python cannot guarantee secure erasure of passwords or key material from memory.
  Do not paste secrets on a shared desktop. Profiles contain identities/SANs but no
  keys, passphrases, or key paths.
- PEM input is limited to 2 MiB and profiles to 64 KiB. Files must be PEM, not DER.
- DNS names use IDNA normalization. Wildcards are restricted to a complete leftmost
  label. This does not check public suffixes, CA policy, or domain ownership.
- No network validation, trust-store modification, certificate installation, or automatic updates occur.
- OpenSSL details use argument arrays, standard input, no temporary input files,
  and a timeout. Generation does not invoke a shell or write OpenSSL configuration.

See [security reporting](SECURITY.md), [architecture](docs/architecture.md),
[testing](docs/testing.md), and [build instructions](docs/building.md).

## Development

```sh
python -m pip install -r requirements-build.txt
python -m pip install --no-build-isolation --no-deps -e .
python -m ruff check .
python -m ruff format --check .
python -m unittest discover -v
```

The OpenSSL tests are explicitly skipped if the executable is missing; CI requires
it so these checks cannot silently disappear. GUI tests are opt-in:

```sh
CSR_GUI_TESTS=1 python -m unittest tests.test_gui -v
# On a headless Linux machine with Xvfb installed:
xvfb-run -a env CSR_GUI_TESTS=1 python -m unittest tests.test_gui -v
```

## License

MIT © Mike Binkowski. See [LICENSE](LICENSE). Packaged builds include dependency
license files and a build-environment inventory. See [CHANGELOG](CHANGELOG.md).
