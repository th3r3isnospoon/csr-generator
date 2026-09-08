# Test strategy

`python -m unittest discover -v` runs the core, CLI, storage, parser, and OpenSSL suites.
GUI tests are opt-in with `CSR_GUI_TESTS=1`; they require Tk and a display. Missing
OpenSSL is an explicit skip locally and an error in CI's dependency preflight.

Coverage focuses on behavior that protects users:

- Every advertised algorithm: complete subject, DNS/IP extensions, signature validity,
  encrypted key serialization, rejection of wrong passphrases, matching certificates.
- Independent OpenSSL verification of CSR signatures, key checks, self-signed certificate
  signatures, TLS server purpose, hostname, and PKCS#12 readability.
- Unicode DNS normalization, IPv4/IPv6 validation, invalid input and empty-SAN policies.
- Existing-key reuse with a new output passphrase and no alteration of the original.
- Unique paths unrelated to CN, restrictive POSIX modes, overwrite/symlink refusal,
  cancellation, cleanup after write failures, and fail-closed Windows ACL command handling.
- Empty/malformed PEM rejection, signature failures, mismatched keys, duplicates,
  issuer order, root omission, and encryption-preserving exports.
- Profile round trips and rejection of embedded secrets.
- CLI exit behavior, headless imports, and frozen CLI execution outside the checkout.
- Actual Tk widget construction, theme text preservation, form values, background result
  delivery, and directory-dialog cancellation.

Run lint and formatting checks as well:

```sh
python -m ruff check .
python -m ruff format --check .
```

GUI automated checks are not a substitute for visual review, accessibility testing,
platform dialogs, scaling, and screen-reader testing. Certificate tests establish
interoperability for these inputs, not acceptance by every CA or TLS implementation.
See the final modernization report for the actual platforms and commands exercised;
a configured CI matrix is not evidence that remote jobs have already run.

## Local modernization verification

On Linux x86_64, Python 3.12.14, cryptography 46.0.7, Tcl/Tk 9.0, and external
OpenSSL 3.5.7, the full suite passed: **38 tests, zero failures or skips**, with
`CSR_GUI_TESTS=1`. This includes six actual Tk widget tests. The GUI was also
visually inspected at 960×860, and bundle controls were checked at 680×560.
Windows and macOS execution, remote GitHub Actions runs, and screen-reader testing
remain unverified locally. The Windows permission-command tests use mocks here.

## Development commands

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
