# Architecture and decisions

## Boundaries

- `models.py`: immutable request, subject, and result data. Secret fields are excluded from repr.
- `validation.py`: names, addresses, algorithms, passphrases, and profiles.
- `crypto.py`: typed X.509 construction and encrypted PKCS#8 serialization.
- `storage.py`: unique private staging/output directories and exclusive file creation.
- `permissions.py`: fail-closed Windows ACL restriction using SID-based OS utilities.
- `pem.py`: strict PEM blocks, summaries, key match, issuer linkage, and exports.
- `openssl.py`: optional subprocess adapter for detailed text inspection.
- `profiles.py`: versioned allowlisted JSON metadata; no secrets.
- `io.py`: bounded file reads.
- `gui.py`: Tk widgets and a background worker/event queue.
- `cli.py`: argument parsing and terminal passphrase prompts.

There are no import-time windows, subprocesses, or filesystem writes. The GUI reads
all input on the Tk thread, creates ordinary Python values, and sends them to a
worker. Only the Tk thread changes widgets. One job runs at a time. Cancellation
is cooperative and is checked before publication. Library key generation cannot
be forcefully interrupted safely; the window waits for that step on close.

## Why cryptography

OpenSSL remains a valuable independent verifier, but a command-line backend required
three different input grammars (shell, OpenSSL config, subject strings), portable
secret transport, executable discovery, and multiple key serialization paths.
Typed builders eliminate those application-layer hazards and preserve Unicode
subjects directly. This deliberately adds a maintained binary dependency rather
than implementing cryptographic primitives ourselves. Binary distributions must
include and regularly update its dependencies.

The optional OpenSSL adapter uses a resolved executable, argument arrays, bounded
input, captured output, and timeouts. No passphrases enter it. Error text is deliberately
sanitized because parser errors can include supplied input. Unexpected GUI exceptions
are contained at the worker boundary; expected service failures retain useful messages.

## File lifecycle

Artifacts are built and checked in memory before creating output. They are serialized
into a newly created private staging directory. An independently reserved final
directory receives the files; callers receive success only after every move succeeds.
Handled failures remove both owned directories. This is not a cross-file filesystem
transaction and does not promise crash/power-loss recovery. Abrupt termination may
leave private staging or partial output directories. Never delete old user files to
recover automatically. Export writes use exclusive creation, not truncating writes.

POSIX modes are explicit. Windows output objects have inherited ACL entries removed
and a current-user grant applied before secret data is written. Utility failures stop
the write and trigger cleanup. Unit tests check argument construction and fail-closed
behavior; actual ACL semantics require Windows validation.
The output directory should be on a trusted local filesystem. A malicious process
running as the same user, an administrator, or a filesystem that ignores access modes
is outside the protection provided by file creation modes.

## Scope of validation

The CSR's self-signature proves possession of its private key, not ownership of a DNS
name or legal organization. Self-signed certificates are explicitly non-CA and are not
installed into trust stores. PEM chain checks verify adjacent signatures, issuer names,
CA flags, and signing key usage when present. They do not claim full trust/path validation.
SHA-1 is not offered. Ed25519 has no independent digest choice.

## Deliberate limits

Tkinter is retained; no new UI framework or service architecture is introduced.
The GUI remains a single presentation module because tab behavior shares a small
amount of state. Split it by tab if it grows substantially. Tests use standard-library
unittest and real cryptographic operations rather than asserting every internal call.

OS signing/notarization requires maintainer credentials and remains a release step.
Native file drag-and-drop, DER conversion, and a trust/path validation UI are future
features; file-picker and paste workflows are fully supported. The evaluated tkinterdnd2 0.4.3 extension fails to load on the local Tcl/Tk 9 runtime
because it is compiled for Tcl 8. It was not added as an application dependency.
