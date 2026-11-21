"""Tortoise ORM configuration built from the application settings."""

from pathlib import Path
from typing import Any

from tortoise.backends.base.config_generator import expand_db_url

from h42pki.config import Settings

MODEL_MODULES = ["h42pki.models"]


def tortoise_config(settings: Settings) -> dict[str, Any]:
    """Return the Tortoise configuration dictionary for ``settings``."""
    return {
        "connections": {"default": settings.database_url},
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
