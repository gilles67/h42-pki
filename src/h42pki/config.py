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

import ipaddress
import os
import stat
import warnings
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    NoDecode,
    PydanticBaseSettingsSource,
    SecretsSettingsSource,
    SettingsConfigDict,
)

from h42pki.core.hostnames import (
    IPNetwork,
    normalize_alt_names,
    normalize_fqdn,
    parse_networks,
    split_list,
)
from h42pki.errors import H42Error

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


def _as_value_error[T, R](function: Callable[[T], R], value: T) -> R:
    """Run a core validator inside a pydantic validator (core raises typed business errors)."""
    try:
        return function(value)
    except H42Error as exc:
        raise ValueError(exc.detail) from None


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

    # Closed list of environment variables (ADR-0011): every other setting is stored in the
    # database (h42pki.core.settings_schema). Do not add a field here without a new ADR.
    environment: Literal["dev", "test", "production"] = "production"
    # Relative path for local development; the image sets sqlite:///data/h42pki.sqlite3.
    database_url: str = "sqlite://data/h42pki.sqlite3"
    # Optional here: only the key store needs it (B32). The server refuses to start without
    # it (h42pki.cli.serve), read-only CLI commands work without it.
    ca_passphrase: SecretStr | None = None
    # FQDN of the service, required by the server only (common name and first SAN of the
    # built-in HTTPS certificate, ADR-0013).
    server_hostname: str | None = None
    server_alt_names: Annotated[list[str], NoDecode] = Field(default_factory=list)
    bind_address: str = "127.0.0.1"  # 0.0.0.0 in the image
    http_enabled: bool = True
    http_port: int = Field(default=8080, ge=1, le=65535)
    https_enabled: bool = True
    https_port: int = Field(default=8443, ge=1, le=65535)
    trusted_proxies: Annotated[list[IPNetwork], NoDecode] = Field(default_factory=list)

    @field_validator("server_hostname", mode="before")
    @classmethod
    def _check_hostname(cls, value: object) -> object:
        if isinstance(value, str):
            if not value.strip():
                return None
            return _as_value_error(normalize_fqdn, value)
        return value

    @field_validator("server_alt_names", mode="before")
    @classmethod
    def _check_alt_names(cls, value: object) -> object:
        items = split_list(value) if isinstance(value, str) else value
        if isinstance(items, list):
            return _as_value_error(normalize_alt_names, [str(item) for item in items])
        return items

    @field_validator("trusted_proxies", mode="before")
    @classmethod
    def _check_proxies(cls, value: object) -> object:
        items = split_list(value) if isinstance(value, str) else value
        if isinstance(items, list):
            return _as_value_error(parse_networks, [str(item) for item in items])
        return items

    @field_validator("bind_address")
    @classmethod
    def _check_bind_address(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            raise ValueError("must be an IP address (for example 0.0.0.0 or ::)") from None

    @model_validator(mode="after")
    def _check_listeners(self) -> "Settings":
        if self.http_enabled and self.https_enabled and self.http_port == self.https_port:
            raise ValueError("HTTP and HTTPS ports must differ when both listeners are enabled")
        if self.server_hostname in self.server_alt_names:
            self.server_alt_names = [n for n in self.server_alt_names if n != self.server_hostname]
        return self

    @property
    def server_names(self) -> list[str]:
        """Names of the built-in HTTPS certificate: the hostname first, then the extra names."""
        return [self.server_hostname, *self.server_alt_names] if self.server_hostname else []

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
