"""Bounded local input loading."""

from pathlib import Path

from .errors import ApplicationError
from .pem import MAX_INPUT


def read_input(path: str | Path, limit: int = MAX_INPUT) -> bytes:
    try:
        with Path(path).expanduser().open("rb") as stream:
            data = stream.read(limit + 1)
    except OSError as exc:
        raise ApplicationError(f"Cannot read {Path(path).name}: {exc.strerror}") from exc
    if len(data) > limit:
        raise ApplicationError(f"Input is larger than {limit} bytes.")
    return data
