"""Exclusive writes and private staging directories; no user identity in paths."""

import os
import shutil
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from .errors import ApplicationError, Cancelled, ValidationError
from .models import Artifacts, GenerationResult
from .permissions import restrict_windows


def check_cancel(cancelled: Callable[[], bool] | None) -> None:
    if cancelled and cancelled():
        raise Cancelled("Operation cancelled. No output was published.")


def save_exclusive(path: Path, data: bytes) -> Path:
    """Never truncate existing files or follow an existing symlink."""
    path = Path(path).expanduser()
    created = False
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        fd = os.open(path, flags, 0o600)
        created = True
        with os.fdopen(fd, "wb") as stream:
            restrict_windows(path)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, ApplicationError) as exc:
        if created:
            path.unlink(missing_ok=True)
        if isinstance(exc, ApplicationError):
            raise
        raise ApplicationError(
            f"Could not save {path.name}: {exc.strerror or 'filesystem error'}"
        ) from exc
    return path


def publish(
    artifacts: Artifacts, destination: Path, cancelled: Callable[[], bool] | None = None
) -> GenerationResult:
    if not str(destination).strip():
        raise ValidationError("Choose an output folder.", "destination")
    check_cancel(cancelled)
    destination = Path(destination).expanduser().resolve()
    stage = None
    final = None
    try:
        destination.mkdir(parents=True, exist_ok=True)
        # Both directories are exclusively allocated, so a same-second run cannot collide.
        stage = Path(tempfile.mkdtemp(prefix=".csr-staging-", dir=destination))
        restrict_windows(stage)
        items = {"private-key.pem": artifacts.key, "request.csr": artifacts.csr}
        if artifacts.certificate is not None:
            items["certificate.crt"] = artifacts.certificate
        for name, data in items.items():
            check_cancel(cancelled)
            save_exclusive(stage / name, data)
        check_cancel(cancelled)
        prefix = "csr-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ-")
        final = Path(tempfile.mkdtemp(prefix=prefix, dir=destination))
        restrict_windows(final)
        # Publish into our private reserved directory. The result is returned only after all moves.
        for name in items:
            (stage / name).rename(final / name)
        stage.rmdir()
        return GenerationResult(final, tuple(final / name for name in items))
    except (OSError, ApplicationError) as exc:
        for directory in (stage, final):
            if directory is not None:
                shutil.rmtree(directory, ignore_errors=True)
        if isinstance(exc, ApplicationError):
            raise
        raise ApplicationError(f"Could not write output folder: {exc.strerror}") from exc
