"""Cryptographic operations independent of Tk, subprocesses, and output paths."""

import ipaddress
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .errors import ApplicationError, ValidationError
from .models import Artifacts, GenerationResult, Request, Subject
from .storage import check_cancel, publish
from .validation import password_bytes, validate_request

PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
PEM = serialization.Encoding.PEM


def public_bytes(key) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_key(data: bytes, passphrase: str = "") -> PrivateKey:
    from .pem import pem_blocks

    blocks = pem_blocks(data)
    if len(blocks) != 1 or blocks[0][0] not in {
        "PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
    }:
        raise ValidationError("Supply exactly one PEM private key.", "existing_key")
    try:
        key = serialization.load_pem_private_key(data, password=password_bytes(passphrase, False))
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ValidationError(
            "Cannot open private key. Check its format and passphrase.", "existing_key"
        ) from exc
    if not isinstance(
        key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey)
    ):
        raise ValidationError("Only RSA, ECDSA, and Ed25519 keys are supported.", "existing_key")
    if isinstance(key, rsa.RSAPrivateKey) and key.key_size < 2048:
        raise ValidationError("RSA keys must be at least 2048 bits.", "existing_key")
    if isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name not in {
        "secp256r1",
        "secp384r1",
        "secp521r1",
    }:
        raise ValidationError("Use a P-256, P-384, or P-521 EC key.", "existing_key")
    return key


def make_key(algorithm: str) -> PrivateKey:
    if algorithm.startswith("rsa-"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(algorithm[4:]))
    if algorithm == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    curves = {"ec-p256": ec.SECP256R1, "ec-p384": ec.SECP384R1, "ec-p521": ec.SECP521R1}
    return ec.generate_private_key(curves[algorithm]())


def digest_for(key: PrivateKey, choice: str):
    if isinstance(key, ed25519.Ed25519PrivateKey):
        if choice != "auto":
            raise ValidationError("Ed25519 requires automatic digest selection.", "digest")
        return None
    if choice == "auto":
        choice = "sha256"
        if isinstance(key, ec.EllipticCurvePrivateKey):
            choice = (
                "sha512" if key.key_size > 384 else "sha384" if key.key_size > 256 else "sha256"
            )
    return {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}[choice]()


def subject_name(subject: Subject) -> x509.Name:
    attributes = [
        ("country", NameOID.COUNTRY_NAME),
        ("state", NameOID.STATE_OR_PROVINCE_NAME),
        ("locality", NameOID.LOCALITY_NAME),
        ("organization", NameOID.ORGANIZATION_NAME),
        ("organizational_unit", NameOID.ORGANIZATIONAL_UNIT_NAME),
        ("common_name", NameOID.COMMON_NAME),
        ("email", NameOID.EMAIL_ADDRESS),
    ]
    return x509.Name(
        [
            x509.NameAttribute(oid, getattr(subject, name))
            for name, oid in attributes
            if getattr(subject, name)
        ]
    )


def create_artifacts(request: Request, cancelled: Callable[[], bool] | None = None) -> Artifacts:
    request = validate_request(request)
    check_cancel(cancelled)
    try:
        key = (
            load_key(request.existing_key, request.existing_passphrase)
            if request.existing_key is not None
            else make_key(request.algorithm)
        )
        check_cancel(cancelled)
        digest = digest_for(key, request.digest)
        name = subject_name(request.subject)
        sans = [x509.DNSName(v) for v in request.dns_names]
        sans += [x509.IPAddress(ipaddress.ip_address(v)) for v in request.ip_addresses]
        builder = x509.CertificateSigningRequestBuilder().subject_name(name)
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        csr = builder.sign(key, digest)
        if not csr.is_signature_valid or public_bytes(csr.public_key()) != public_bytes(
            key.public_key()
        ):
            raise ApplicationError("Generated CSR did not pass verification.")
        cert_data = None
        if request.self_signed:
            now = datetime.now(UTC)
            cert_builder = (
                x509.CertificateBuilder()
                .subject_name(name)
                .issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=5))
                .not_valid_after(now + timedelta(days=request.validity_days))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False
                )
                .add_extension(
                    x509.KeyUsage(
                        True,
                        False,
                        isinstance(key, rsa.RSAPrivateKey),
                        False,
                        False,
                        False,
                        False,
                        False,
                        False,
                    ),
                    True,
                )
            )
            if sans:
                cert_builder = cert_builder.add_extension(x509.SubjectAlternativeName(sans), False)
            if request.profile != "generic":
                usage = (
                    ExtendedKeyUsageOID.SERVER_AUTH
                    if request.profile == "tls-server"
                    else ExtendedKeyUsageOID.CLIENT_AUTH
                )
                cert_builder = cert_builder.add_extension(x509.ExtendedKeyUsage([usage]), False)
            cert = cert_builder.sign(key, digest)
            cert.verify_directly_issued_by(cert)
            cert_data = cert.public_bytes(PEM)
        encryption = (
            serialization.BestAvailableEncryption(password_bytes(request.passphrase))
            if request.encrypt_key
            else serialization.NoEncryption()
        )
        key_data = key.private_bytes(PEM, serialization.PrivateFormat.PKCS8, encryption)
        # Verify serialization and the password contract before touching disk.
        loaded = serialization.load_pem_private_key(
            key_data, password=password_bytes(request.passphrase, False)
        )
        if public_bytes(loaded.public_key()) != public_bytes(csr.public_key()):
            raise ApplicationError("Serialized key did not match the CSR.")
        check_cancel(cancelled)
        return Artifacts(csr.public_bytes(PEM), key_data, cert_data)
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise ApplicationError(
            "Cryptographic operation failed; check algorithm support and input."
        ) from exc


def generate(
    request: Request, destination: Path, cancelled: Callable[[], bool] | None = None
) -> GenerationResult:
    return publish(create_artifacts(request, cancelled), destination, cancelled)
