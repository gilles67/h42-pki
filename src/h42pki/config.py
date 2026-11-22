"""Application settings.

Values are resolved in this order (first wins):

1. arguments passed to ``Settings(...)``;
2. environment variables ``H42_PKI_<FIELD>``;
3. ``H42_PKI_<FIELD>_FILE`` environment variables pointing to a file holding the value;
4. files named ``h42_pki_<field>`` in the secrets directory (Docker secrets layout);
5. field defaults.

The secrets directory defaults to ``/run/secrets`` and can be changed with
``H42_PKI_SECRETS_DIR``; it is silently ignored when it does not exist.

Secret files are checked on POSIX systems (B4): a file writable by group or others is an
error in ``production`` and a warning otherwise; a world-readable file outside the secrets
directory is a warning (``0444`` is the normal mode of Docker secrets, so it is accepted
silently inside the secrets directory). Messages name the file and its mode, never its content.
"""

import os
import stat
import warnings
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import SecretStr, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SecretsSettingsSource,
    SettingsConfigDict,
)

ENV_PREFIX = "H42_PKI_"
DEFAULT_SECRETS_DIR = "/run/secrets"


@dataclass(frozen=True)
class SecretFileIssue:
    """A permission problem found on a secret file (never holds the secret itself)."""

    message: str
    fatal_in_production: bool


# Issues found by the file-based sources while one ``Settings`` instance is being built;
# they are reported by ``Settings._report_secret_file_issues`` once ``environment`` is known.
_secret_file_issues: ContextVar[list[SecretFileIssue] | None] = ContextVar(
    "_secret_file_issues", default=None
)


def check_secret_file(path: Path, *, in_secrets_dir: bool) -> list[SecretFileIssue]:
    """Return the permission issues of a secret file (POSIX only)."""
    if os.name == "nt":
        return []
    mode = stat.S_IMODE(path.stat().st_mode)
    issues: list[SecretFileIssue] = []
    if mode & 0o022:
        issues.append(
            SecretFileIssue(
                f"secret file {path} is writable by group or others (mode {mode:04o})",
                fatal_in_production=True,
            )
        )
    if mode & 0o004 and not in_secrets_dir:
        issues.append(
            SecretFileIssue(
                f"secret file {path} is readable by others (mode {mode:04o})",
                fatal_in_production=False,
            )
        )
    return issues


def _record_secret_file(path: Path, *, in_secrets_dir: bool) -> None:
    issues = _secret_file_issues.get()
    if issues is not None:
        issues.extend(check_secret_file(path, in_secrets_dir=in_secrets_dir))


class FileEnvSettingsSource(PydanticBaseSettingsSource):
    """Read ``H42_PKI_<FIELD>_FILE`` variables and load the referenced files."""

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        variable = f"{ENV_PREFIX}{field_name}_FILE".upper()
        path = os.environ.get(variable)
        if not path:
            return None, field_name, False
        file_path = Path(path)
        _record_secret_file(file_path, in_secrets_dir=False)
        return file_path.read_text(encoding="utf-8").strip(), field_name, False

    def __call__(self) -> dict[str, Any]:
        values: dict[str, Any] = {}
        for field_name, field in self.settings_cls.model_fields.items():
            value, key, _ = self.get_field_value(field, field_name)
            if value is not None:
                values[key] = value
        return values


class CheckedSecretsSettingsSource(SecretsSettingsSource):
    """Docker secrets directory source that also checks the permissions of the files it reads."""

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        value, key, is_complex = super().get_field_value(field, field_name)
        if value is not None:
            for _, env_name, _ in self._extract_field_info(field, field_name):
                for secrets_path in self.secrets_paths:
                    path = self.find_case_path(secrets_path, env_name, self.case_sensitive)
                    if path is not None and path.is_file():
                        _record_secret_file(path, in_secrets_dir=True)
        return value, key, is_complex


class Settings(BaseSettings):
    """Runtime configuration of one h42-pki instance (one CA)."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        extra="ignore",
        hide_input_in_errors=True,
    )

    environment: Literal["dev", "test", "production"] = "production"
    database_url: str = "sqlite://data/h42pki.sqlite3"
    # Optional here: only the key store needs it (B32). The server refuses to start without
    # it (h42pki.main), read-only CLI commands work without it.
    ca_passphrase: SecretStr | None = None

    def __init__(self, **values: Any) -> None:
        token = _secret_file_issues.set([])
        try:
            super().__init__(**values)
        finally:
            _secret_file_issues.reset(token)

    @model_validator(mode="after")
    def _report_secret_file_issues(self) -> "Settings":
        for issue in _secret_file_issues.get() or []:
            if issue.fatal_in_production and self.environment == "production":
                raise ValueError(issue.message)
            warnings.warn(issue.message, UserWarning, stacklevel=2)
        return self

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
            CheckedSecretsSettingsSource(
                settings_cls,
                secrets_dir=getattr(file_secret_settings, "secrets_dir", None),
            ),
        )


def secrets_dir() -> Path | None:
    """Return the secrets directory to read, or ``None`` if it does not exist."""
    path = Path(os.environ.get(f"{ENV_PREFIX}SECRETS_DIR", DEFAULT_SECRETS_DIR))
    return path if path.is_dir() else None


@lru_cache
def get_settings() -> Settings:
    """Load the settings once per process (call ``get_settings.cache_clear()`` to reload)."""
    return Settings(_secrets_dir=secrets_dir())
