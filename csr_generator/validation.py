"""Validate structured input; display labels and filenames are never identities."""

import ipaddress
import re
import unicodedata
from dataclasses import fields, replace

import idna

from .errors import ValidationError
from .models import ALGORITHMS, DIGESTS, PROFILES, Request, Subject


def clean_text(value: str, field: str, maximum: int = 128) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be text.", field)
    if any(unicodedata.category(c).startswith("C") for c in value):
        raise ValidationError(f"{field} cannot contain control characters.", field)
    value = value.strip()
    if len(value.encode("utf-8")) > maximum:
        raise ValidationError(f"{field} is too long (maximum {maximum} UTF-8 bytes).", field)
    return value


def dns_name(value: str) -> str:
    value = clean_text(value, "dns_names", 1024)
    wildcard = value.startswith("*.")
    name = value[2:] if wildcard else value
    try:
        name = idna.uts46_remap(name, std3_rules=True)
        if name.endswith("."):
            name = name[:-1]
        if name.endswith("."):
            raise idna.IDNAError("Multiple trailing dots")
        name = idna.encode(name, std3_rules=True).decode("ascii").lower()
    except idna.IDNAError as exc:
        raise ValidationError(
            "Invalid DNS SAN; use a hostname or *.example.com.", "dns_names"
        ) from exc
    if len(name) > 253 or (wildcard and "." not in name):
        raise ValidationError("DNS SAN is too long or wildcard is too broad.", "dns_names")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise ValidationError("Put IP addresses in IP SANs, not DNS SANs.", "dns_names")
    return ("*." if wildcard else "") + name


def password_bytes(value: str, required: bool = True) -> bytes | None:
    # Preserve spaces exactly. A conservative limit is portable across serializers.
    if not isinstance(value, str) or "\x00" in value or "\n" in value or "\r" in value:
        raise ValidationError("Passphrase cannot contain NUL or line breaks.", "passphrase")
    encoded = value.encode("utf-8")
    if required and not encoded:
        raise ValidationError(
            "Enter a passphrase or explicitly disable key encryption.", "passphrase"
        )
    if len(encoded) > 1023:
        raise ValidationError("Passphrase exceeds 1023 UTF-8 bytes.", "passphrase")
    return encoded or None


def validate_request(request: Request) -> Request:
    if request.algorithm not in ALGORITHMS:
        raise ValidationError("Choose a supported key algorithm.", "algorithm")
    if request.digest not in DIGESTS:
        raise ValidationError("Choose SHA-256, SHA-384, SHA-512, or automatic.", "digest")
    if request.profile not in PROFILES:
        raise ValidationError("Choose a supported certificate profile.", "profile")
    if request.algorithm == "ed25519" and request.digest != "auto":
        raise ValidationError("Ed25519 requires automatic digest selection.", "digest")
    if type(request.validity_days) is not int or not 1 <= request.validity_days <= 3650:
        raise ValidationError("Validity must be between 1 and 3650 days.", "validity_days")
    values = {
        f.name: clean_text(
            getattr(request.subject, f.name), f.name, 64 if f.name == "common_name" else 128
        )
        for f in fields(Subject)
    }
    if not values["common_name"]:
        raise ValidationError("Common name is required.", "common_name")
    country = values["country"].upper()
    if country and not re.fullmatch("[A-Z]{2}", country):
        raise ValidationError("Country must be a two-letter country code.", "country")
    values["country"] = country
    email = values["email"]
    if email and (not email.isascii() or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)):
        raise ValidationError("Enter an ASCII email address, or leave it blank.", "email")
    dns = tuple(dict.fromkeys(dns_name(v) for v in request.dns_names))
    ips = []
    for value in request.ip_addresses:
        try:
            value = clean_text(value, "ip_addresses")
            if "%" in value:
                raise ValueError("Scoped addresses are not X.509 IP addresses")
            ips.append(str(ipaddress.ip_address(value)))
        except ValueError as exc:
            raise ValidationError(
                "IP SANs must be valid IPv4 or IPv6 addresses.", "ip_addresses"
            ) from exc
    if len(dns) + len(ips) > 500:
        raise ValidationError("Limit SANs to 500 entries.", "dns_names")
    if request.profile == "tls-server" and not dns and not ips:
        raise ValidationError(
            "TLS server requests require at least one DNS or IP SAN.", "dns_names"
        )
    if request.encrypt_key:
        password_bytes(request.passphrase)
    elif request.passphrase:
        raise ValidationError("Clear the passphrase when disabling encryption.", "passphrase")
    return replace(
        request, subject=Subject(**values), dns_names=dns, ip_addresses=tuple(dict.fromkeys(ips))
    )
