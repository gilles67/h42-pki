"""Heartbeat of the launcher, read by ``h42pki healthcheck`` from another process.

A small file in the temporary directory rather than a database row: no write every 10 seconds in
the database (SQLite WAL, backups), and it works in idle mode, without any port. The file name
derives from the database URL, so that two instances on one host do not mix and the healthcheck,
which reads the same environment, finds the right file.
"""

import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

HEARTBEAT_INTERVAL_SECONDS = 10.0
HEARTBEAT_MAX_AGE_SECONDS = 60.0


def heartbeat_path(database_url: str) -> Path:
    digest = hashlib.sha256(database_url.encode("utf-8")).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / f"h42pki-{digest}.heartbeat"


def write_heartbeat(path: Path, now: datetime | None = None) -> None:
    """Atomic write: a reader never sees a partial file."""
    now = now or datetime.now(UTC)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps({"timestamp": now.isoformat(), "pid": os.getpid()}), encoding="utf-8"
    )
    os.replace(temporary, path)


def read_heartbeat(path: Path) -> datetime | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return datetime.fromisoformat(data["timestamp"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def heartbeat_age(path: Path, now: datetime | None = None) -> float | None:
    """Seconds since the last beat, or None if there is none."""
    beat = read_heartbeat(path)
    if beat is None:
        return None
    return ((now or datetime.now(UTC)) - beat).total_seconds()


def remove_heartbeat(path: Path) -> None:
    path.unlink(missing_ok=True)
