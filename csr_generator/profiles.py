"""Versioned, allowlisted JSON profiles. Never serialize secrets or key paths."""

import json
from dataclasses import asdict
from pathlib import Path

from .errors import ValidationError
from .models import Request, Subject
from .storage import save_exclusive
from .validation import validate_request

FIELDS = {
    "subject",
    "dns_names",
    "ip_addresses",
    "algorithm",
    "digest",
    "profile",
    "self_signed",
    "validity_days",
}


def profile_bytes(request: Request) -> bytes:
    # Build explicitly: asdict(request) would copy private key material unnecessarily.
    values = {name: getattr(request, name) for name in FIELDS if name != "subject"}
    values["subject"] = asdict(request.subject)
    return (
        json.dumps({"version": 1, "request": values}, indent=2, ensure_ascii=False) + "\n"
    ).encode()


def save_profile(path: Path, request: Request) -> Path:
    return save_exclusive(path, profile_bytes(request))


def load_profile(data: bytes) -> Request:
    try:
        if len(data) > 65536:
            raise ValueError("too large")
        document = json.loads(data)
        if set(document) != {"version", "request"} or document["version"] != 1:
            raise ValueError("version")
        values = document["request"]
        if not isinstance(values, dict) or set(values) - FIELDS:
            raise ValueError("fields")
        subject = Subject(**values.pop("subject"))
        for name in ("dns_names", "ip_addresses"):
            items = values.get(name, [])
            if not isinstance(items, list) or not all(isinstance(v, str) for v in items):
                raise ValueError("SANs")
            values[name] = tuple(items)
        if "self_signed" in values and type(values["self_signed"]) is not bool:
            raise ValueError("self_signed")
        request = Request(subject=subject, **values)
        # Validate metadata without needing a secret in the profile.
        from dataclasses import replace

        validate_request(replace(request, encrypt_key=False))
        return request
    except (TypeError, ValueError, KeyError, AttributeError, ValidationError) as exc:
        raise ValidationError(
            "Invalid profile. Use a version 1 CSR Generator profile without secrets."
        ) from exc
