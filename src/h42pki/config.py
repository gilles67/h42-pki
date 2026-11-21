"""Application settings.

Values are resolved in this order (first wins):

1. arguments passed to ``Settings(...)``;
2. environment variables ``H42_PKI_<FIELD>``;
3. ``H42_PKI_<FIELD>_FILE`` environment variables pointing to a file holding the value;
4. files named ``h42_pki_<field>`` in the secrets directory (Docker secrets layout);
5. field defaults.

The secrets directory defaults to ``/run/secrets`` and can be changed with
``H42_PKI_SECRETS_DIR``; it is silently ignored when it does not exist.
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import SecretStr
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

ENV_PREFIX = "H42_PKI_"
DEFAULT_SECRETS_DIR = "/run/secrets"


class FileEnvSettingsSource(PydanticBaseSettingsSource):
    """Read ``H42_PKI_<FIELD>_FILE`` variables and load the referenced files."""

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        variable = f"{ENV_PREFIX}{field_name}_FILE".upper()
        path = os.environ.get(variable)
        if not path:
            return None, field_name, False
        return Path(path).read_text(encoding="utf-8").strip(), field_name, False

    def __call__(self) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for field_name, field in self.settings_cls.model_fields.items():
            value, key, _ = self.get_field_value(field, field_name)
            if value is not None:
                values[key] = value
        return values


class Settings(BaseSettings):
    """Runtime configuration of one h42-pki instance (one CA)."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        extra="ignore",
        hide_input_in_errors=True,
    )

    environment: Literal["dev", "test", "production"] = "production"
    database_url: str = "sqlite://data/h42pki.sqlite3"
    ca_passphrase: SecretStr

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            env_settings,
            FileEnvSettingsSource(settings_cls),
            dotenv_settings,
            file_secret_settings,
        )


def secrets_dir() -> Path | None:
    """Return the secrets directory to read, or ``None`` if it does not exist."""
    path = Path(os.environ.get(f"{ENV_PREFIX}SECRETS_DIR", DEFAULT_SECRETS_DIR))
    return path if path.is_dir() else None


@lru_cache
def get_settings() -> Settings:
    """Load the settings once per process (call ``get_settings.cache_clear()`` to reload)."""
    return Settings(_secrets_dir=secrets_dir())
