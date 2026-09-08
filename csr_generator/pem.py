"""Strict PEM parsing and export. Chain linkage is not a trust decision."""

import re
from datetime import UTC, datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from .errors import ValidationError
from .validation import password_bytes

MAX_INPUT = 2 * 1024 * 1024
BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n.*?-----END \1-----", re.DOTALL)


def pem_blocks(data: bytes) -> list[tuple[str, bytes]]:
    if len(data) > MAX_INPUT:
        raise ValidationError("Input exceeds 2 MiB.")
    matches = list(BLOCK.finditer(data))
    position = 0
    for match in matches:
        if data[position : match.start()].strip():
            raise ValidationError("Unexpected text outside PEM blocks.")
        position = match.end()
    if not matches or data[position:].strip():
        raise ValidationError("Supply complete PEM blocks without surrounding text.")
    return [(m[1].decode("ascii"), m[0].replace(b"\r\n", b"\n") + b"\n") for m in matches]


def certificates(data: bytes) -> list[x509.Certificate]:
    blocks = pem_blocks(data)
    if any(label != "CERTIFICATE" for label, _ in blocks):
        raise ValidationError("The certificate field must contain only certificates.")
    try:
        return [x509.load_pem_x509_certificate(block) for _, block in blocks]
    except ValueError as exc:
        raise ValidationError("Invalid PEM certificate.") from exc


def validate_chain(certs: list[x509.Certificate]) -> None:
    if len({cert.fingerprint(hashes.SHA256()) for cert in certs}) != len(certs):
        raise ValidationError("Duplicate certificate in chain.")
    for child, issuer in zip(certs, certs[1:], strict=False):
        try:
            child.verify_directly_issued_by(issuer)
            if not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValidationError("An issuer certificate is not a CA.")
            try:
                usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
                if not usage.key_cert_sign:
                    raise ValidationError("An issuer does not permit certificate signing.")
            except x509.ExtensionNotFound:
                pass
        except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound) as exc:
            raise ValidationError("Certificates are not in valid leaf-to-issuer order.") from exc


def bundle(
    cert_data: bytes = b"",
    key_data: bytes = b"",
    key_passphrase: str = "",
    mode: str = "chain",
    include_root: bool = False,
    blank_lines: bool = True,
    export_passphrase: str = "",
) -> bytes:
    from .crypto import load_key, public_bytes

    if mode not in {"chain", "key", "combined", "pkcs12"}:
        raise ValidationError("Choose chain, key, combined, or pkcs12 export.")
    certs = certificates(cert_data) if cert_data.strip() else []
    key = load_key(key_data, key_passphrase) if key_data.strip() else None
    if mode in {"chain", "combined", "pkcs12"} and not certs:
        raise ValidationError("This export requires a certificate.")
    if mode in {"key", "combined", "pkcs12"} and key is None:
        raise ValidationError("This export requires a private key.")
    validate_chain(certs)
    if certs and key and public_bytes(certs[0].public_key()) != public_bytes(key.public_key()):
        raise ValidationError("The private key does not match the first (leaf) certificate.")
    if len(certs) > 1 and not include_root and certs[-1].issuer == certs[-1].subject:
        try:
            certs[-1].verify_directly_issued_by(certs[-1])
        except (ValueError, TypeError, InvalidSignature) as exc:
            raise ValidationError(
                "The last certificate claims to be self-signed but is invalid."
            ) from exc
        certs = certs[:-1]
    if mode == "pkcs12":
        try:
            return pkcs12.serialize_key_and_certificates(
                b"CSR Generator",
                key,
                certs[0],
                certs[1:] or None,
                serialization.BestAvailableEncryption(password_bytes(export_passphrase)),
            )
        except (TypeError, ValueError) as exc:
            raise ValidationError(
                "This key cannot be exported as PKCS#12 by this backend."
            ) from exc
    parts = []
    if mode in {"chain", "combined"}:
        parts.extend(cert.public_bytes(serialization.Encoding.PEM).strip() for cert in certs)
    if mode in {"key", "combined"}:
        # Preserve input encryption; never silently decrypt a key for PEM export.
        parts.append(pem_blocks(key_data)[0][1].strip())
    return (b"\n\n" if blank_lines else b"\n").join(parts) + b"\n"


def inspect_pem(data: bytes, kind: str) -> str:
    from .crypto import public_bytes

    try:
        blocks = pem_blocks(data)
        if kind == "csr":
            if len(blocks) != 1 or blocks[0][0] not in {
                "CERTIFICATE REQUEST",
                "NEW CERTIFICATE REQUEST",
            }:
                raise ValidationError("Supply exactly one CSR.")
            objects = [x509.load_pem_x509_csr(blocks[0][1])]
        elif kind == "certificate":
            objects = certificates(data)
        else:
            raise ValidationError("Choose csr or certificate.")
        reports = []
        for obj in objects:
            key = obj.public_key()
            fingerprint = hashes.Hash(hashes.SHA256())
            fingerprint.update(public_bytes(key))
            lines = [
                f"Subject: {obj.subject.rfc4514_string()}",
                f"Public key: {type(key).__name__} {getattr(key, 'key_size', '')}",
                f"Public key SHA-256: {fingerprint.finalize().hex(':')}",
                f"Signature: {obj.signature_algorithm_oid.dotted_string}",
            ]
            if kind == "csr":
                if not obj.is_signature_valid:
                    raise ValidationError("CSR signature is invalid.")
                lines.append("CSR self-signature: valid (identity has not been verified)")
            else:
                now = datetime.now(UTC)
                state = (
                    "not yet valid"
                    if now < obj.not_valid_before_utc
                    else "expired"
                    if now > obj.not_valid_after_utc
                    else "within validity period"
                )
                lines += [
                    f"Issuer: {obj.issuer.rfc4514_string()}",
                    f"Serial: {obj.serial_number:x}",
                    f"Valid from: {obj.not_valid_before_utc.isoformat()}",
                    f"Valid until: {obj.not_valid_after_utc.isoformat()} ({state})",
                    f"Certificate SHA-256: {obj.fingerprint(hashes.SHA256()).hex(':')}",
                    "Trust, hostname, revocation, and full path validation: not performed",
                ]
            for extension in obj.extensions:
                lines.append(
                    f"Extension {extension.oid.dotted_string} "
                    f"(critical={extension.critical}): {extension.value}"
                )
            reports.append("\n".join(lines))
        return "\n\n".join(reports)
    except (ValueError, TypeError) as exc:
        raise ValidationError("Invalid or unsupported CSR/certificate data.") from exc
