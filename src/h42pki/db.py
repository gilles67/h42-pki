"""Tortoise ORM configuration built from the application settings."""

from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from tortoise.backends.base.config_generator import expand_db_url

from h42pki.config import Settings

MODEL_MODULES = ["h42pki.models"]


def with_pool_size(database_url: str, pool_size: int | None) -> str:
    """Apply ``database.pool_size`` (``maxsize`` of Tortoise); SQLite has no pool: unchanged."""
    if pool_size is None or database_url.startswith("sqlite://"):
        return database_url
    parts = urlsplit(database_url)
    query = [(k, v) for k, v in parse_qsl(parts.query) if k != "maxsize"]
    query.append(("maxsize", str(pool_size)))
    return urlunsplit(parts._replace(query=urlencode(query)))


def tortoise_config(settings: Settings, *, pool_size: int | None = None) -> dict[str, Any]:
    """Return the Tortoise configuration dictionary for ``settings``."""
    return {
        "connections": {"default": with_pool_size(settings.database_url, pool_size)},
        "apps": {
            # The app label stays "models", as in the legacy register_tortoise() call.
            "models": {"models": MODEL_MODULES, "default_connection": "default"},
        },
        "use_tz": True,
        "timezone": "UTC",
    }


def ensure_sqlite_directory(database_url: str) -> None:
    """Create the parent directory of a file-based SQLite database if needed."""
    if not database_url.startswith("sqlite://"):
        return
    file_path = expand_db_url(database_url)["credentials"]["file_path"]
    if file_path != ":memory:":
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
