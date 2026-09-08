"""Values shared by the GUI, CLI, and cryptographic services."""

from dataclasses import dataclass, field
from pathlib import Path

ALGORITHMS = {
    "ec-p256": "ECDSA P-256 — broad compatibility",
    "ec-p384": "ECDSA P-384",
    "ec-p521": "ECDSA P-521",
    "rsa-2048": "RSA 2048 — legacy compatibility",
    "rsa-4096": "RSA 4096",
    "ed25519": "Ed25519 — check CA/application support",
}
DIGESTS = ("auto", "sha256", "sha384", "sha512")
PROFILES = ("tls-server", "tls-client", "generic")


@dataclass(frozen=True)
class Subject:
    common_name: str
    country: str = ""
    state: str = ""
    locality: str = ""
    organization: str = ""
    organizational_unit: str = ""
    email: str = ""


@dataclass(frozen=True)
class Request:
    subject: Subject
    dns_names: tuple[str, ...] = ()
    ip_addresses: tuple[str, ...] = ()
    algorithm: str = "ec-p256"
    digest: str = "auto"
    profile: str = "tls-server"
    self_signed: bool = False
    validity_days: int = 365
    encrypt_key: bool = True
    passphrase: str = field(default="", repr=False)
    existing_key: bytes | None = field(default=None, repr=False)
    existing_passphrase: str = field(default="", repr=False)


@dataclass(frozen=True)
class Artifacts:
    csr: bytes
    key: bytes = field(repr=False)
    certificate: bytes | None = None


@dataclass(frozen=True)
class GenerationResult:
    directory: Path
    files: tuple[Path, ...]
