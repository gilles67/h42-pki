"""Runtime settings stored in the database (ADR-0011): schema, defaults and application levels.

Only modified values are stored (table ``Setting``, key ``section.name``); defaults stay in the
code, so an instance that did not override a value benefits from a new default. Every write is
validated by :class:`RuntimeSettings` as a whole (cross-field rules included).

Each field declares how a change is applied:

- ``hot``: at once, without interruption;
- ``listener``: the launcher restarts the listed listeners only (``http``, ``https``);
- ``process``: at the next start of the container.

Settings of phases 1.1 to 6 (ARCHITECTURE section 7.2).
"""

import ipaddress
import json
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal, Self
from urllib.parse import urlsplit

from cryptography import x509
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from pydantic.config import JsonDict

from h42pki.core.errors import InvalidSetting, UnknownSetting
from h42pki.core.profiles import BUILTIN_PROFILES

Listener = Literal["http", "https"]


class ApplyLevel(StrEnum):
    HOT = "hot"
    LISTENER = "listener"
    PROCESS = "process"


def _setting(
    default: Any,
    *,
    apply: ApplyLevel,
    description: str,
    listeners: tuple[Listener, ...] = (),
    **constraints: Any,
) -> Any:
    if (apply is ApplyLevel.LISTENER) != bool(listeners):
        raise ValueError("listeners are declared exactly for the 'listener' level")
    extra: JsonDict = {"apply": apply.value, "listeners": [str(name) for name in listeners]}
    if isinstance(default, list):
        return Field(
            default_factory=list, description=description, json_schema_extra=extra, **constraints
        )
    return Field(default=default, description=description, json_schema_extra=extra, **constraints)


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# SC-081v3: a TLS server certificate lasts 200 days at most since 2026-03-15.
MAX_SERVICE_TLS_VALIDITY_DAYS = 200


class TlsServiceSettings(_Section):
    """Certificate of the built-in HTTPS server (ADR-0013)."""

    validity_days: int = _setting(
        47,
        apply=ApplyLevel.HOT,
        description="Validity of the HTTPS server certificate, in days (next issuance).",
        ge=2,
        le=MAX_SERVICE_TLS_VALIDITY_DAYS,
    )
    renew_before_days: int = _setting(
        15,
        apply=ApplyLevel.HOT,
        description="Renew the HTTPS server certificate when this many days or fewer remain.",
        ge=1,
        le=MAX_SERVICE_TLS_VALIDITY_DAYS - 1,
    )

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.renew_before_days >= self.validity_days:
            raise ValueError(
                "tls_service.renew_before_days must be lower than tls_service.validity_days"
            )
        return self


def _disableable_profiles() -> set[str]:
    return {spec.name for spec in BUILTIN_PROFILES.values() if not spec.internal}


class IssuanceSettings(_Section):
    disabled_profiles: list[str] = _setting(
        [],
        apply=ApplyLevel.HOT,
        description="Built-in profiles refused by this CA (all are enabled by default).",
    )

    @field_validator("disabled_profiles")
    @classmethod
    def _check_profiles(cls, value: list[str]) -> list[str]:
        allowed = _disableable_profiles()
        internal = {spec.name for spec in BUILTIN_PROFILES.values() if spec.internal}
        names: list[str] = []
        for name in value:
            if name in internal:
                raise ValueError(
                    f"{name!r} is an internal profile and cannot be disabled "
                    "(use H42_PKI_HTTPS_ENABLED=false to turn HTTPS off)"
                )
            if name not in allowed:
                raise ValueError(
                    f"unknown profile {name!r} (built-in profiles: {', '.join(sorted(allowed))})"
                )
            if name not in names:
                names.append(name)
        return names


class ServerSettings(_Section):
    """Listener settings: TLS of the HTTPS listener, Uvicorn limits of both listeners."""

    tls_min_version: Literal["tls1.2", "tls1.3"] = _setting(
        "tls1.2",
        apply=ApplyLevel.LISTENER,
        listeners=("https",),
        description="Minimum TLS version of the HTTPS listener.",
    )
    tls_ciphers: str | None = _setting(
        None,
        apply=ApplyLevel.LISTENER,
        listeners=("https",),
        description=(
            "OpenSSL cipher list for TLS 1.2 (null = OpenSSL defaults); TLS 1.3 suites cannot "
            "be chosen from Python."
        ),
        min_length=1,
    )
    client_trust_anchors: list[str] = _setting(
        [],
        apply=ApplyLevel.LISTENER,
        listeners=("https",),
        description=(
            "Extra CA certificates (PEM) trusted for client certificates, on top of the local "
            "CA chain."
        ),
    )
    keep_alive_timeout: int | None = _setting(
        None,
        apply=ApplyLevel.LISTENER,
        listeners=("http", "https"),
        description="Keep-alive timeout in seconds (null = Uvicorn default).",
        ge=1,
        le=3600,
    )
    limit_concurrency: int | None = _setting(
        None,
        apply=ApplyLevel.LISTENER,
        listeners=("http", "https"),
        description="Maximum concurrent connections or tasks (null = no limit).",
        ge=1,
    )
    backlog: int | None = _setting(
        None,
        apply=ApplyLevel.LISTENER,
        listeners=("http", "https"),
        description="Socket backlog (null = Uvicorn default).",
        ge=1,
        le=65535,
    )
    max_header_size: int | None = _setting(
        None,
        apply=ApplyLevel.LISTENER,
        listeners=("http", "https"),
        description="Maximum size of the request head in bytes (null = h11 default).",
        ge=1024,
        le=1024 * 1024,
    )

    @field_validator("tls_ciphers")
    @classmethod
    def _check_ciphers(cls, value: str | None) -> str | None:
        if value is not None:
            try:  # OpenSSL itself decides; checked here rather than at the listener restart
                ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).set_ciphers(value)
            except ssl.SSLError:
                raise ValueError("OpenSSL selects no cipher with this cipher list") from None
        return value

    @field_validator("client_trust_anchors")
    @classmethod
    def _check_anchors(cls, value: list[str]) -> list[str]:
        anchors: list[str] = []
        for pem in value:
            try:
                certificate = x509.load_pem_x509_certificate(pem.encode("ascii"))
            except (ValueError, UnicodeEncodeError):
                raise ValueError("each trust anchor must be one PEM certificate") from None
            try:
                is_ca = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
            except x509.ExtensionNotFound:
                is_ca = None
            if is_ca is None or not is_ca.value.ca:
                raise ValueError("a trust anchor must be a CA certificate (basicConstraints CA)")
            normalized = pem.strip() + "\n"
            if normalized not in anchors:
                anchors.append(normalized)
        return anchors


# A CRL of a root CA that is rarely online may last long (half a year, federation.md section 6).
MAX_CRL_VALIDITY_HOURS = 8784  # one leap year


class CrlSettings(_Section):
    """CRL of a CA created with --crl (ADR-0017)."""

    validity_hours: int = _setting(
        168,
        apply=ApplyLevel.HOT,
        description="Validity of a new CRL (nextUpdate - thisUpdate), in hours.",
        ge=1,
        le=MAX_CRL_VALIDITY_HOURS,
    )
    regenerate_before_hours: int = _setting(
        48,
        apply=ApplyLevel.HOT,
        description="Generate a new CRL when this many hours or fewer remain before nextUpdate.",
        ge=0,
        le=MAX_CRL_VALIDITY_HOURS,
    )

    @model_validator(mode="after")
    def _check_window(self) -> Self:
        if self.regenerate_before_hours >= self.validity_hours:
            raise ValueError(
                "crl.regenerate_before_hours must be lower than crl.validity_hours, otherwise "
                "every check would generate a new CRL"
            )
        return self


class OcspSettings(_Section):
    """OCSP of a CA created with --ocsp (ADR-0017)."""

    response_validity_hours: int = _setting(
        24,
        apply=ApplyLevel.HOT,
        description=(
            "Validity of an OCSP answer (nextUpdate - thisUpdate), in hours; never beyond the "
            "nextUpdate of the CRL when it is enabled."
        ),
        ge=1,
        le=168,
    )


class EstSettings(_Section):
    """EST enrollment (RFC 7030, ADR-0018): disabled by default, like every enrollment protocol."""

    enabled: bool = _setting(
        False,
        apply=ApplyLevel.HOT,
        description="Serve EST (/.well-known/est, HTTPS only); false: every EST route answers 404.",
    )
    default_profile: str = _setting(
        "",
        apply=ApplyLevel.HOT,
        description=(
            "Profile of the EST routes without label (/.well-known/est/simpleenroll); empty: "
            "those routes answer 404 and a label is required (/.well-known/est/{profile}/...)."
        ),
    )
    retry_after_seconds: int = _setting(
        60,
        apply=ApplyLevel.HOT,
        description="Retry-After of a 202 answer, while a request waits for its approval.",
        ge=1,
        le=3600,
    )

    @field_validator("default_profile")
    @classmethod
    def _check_profile(cls, value: str) -> str:
        if value and value not in _disableable_profiles():
            raise ValueError(
                f"unknown profile {value!r} "
                f"(built-in profiles: {', '.join(sorted(_disableable_profiles()))})"
            )
        return value


class ScepSettings(_Section):
    """SCEP enrollment (RFC 8894, ADR-0019): disabled by default, like every enrollment protocol."""

    enabled: bool = _setting(
        False,
        apply=ApplyLevel.HOT,
        description="Serve SCEP (/scep, HTTP and HTTPS); false: every SCEP route answers 404.",
    )
    default_profile: str = _setting(
        "",
        apply=ApplyLevel.HOT,
        description=(
            "Profile of /scep without label; empty: those routes answer 404 and a label is "
            "required (/scep/{profile})."
        ),
    )
    allow_legacy_crypto: bool = _setting(
        False,
        apply=ApplyLevel.HOT,
        description=(
            "Also accept 3DES and SHA-1 (and announce them in GetCACaps), for old devices; "
            "false: AES and SHA-256/512 only."
        ),
    )
    ra_validity_days: int = _setting(
        365,
        apply=ApplyLevel.HOT,
        description="Validity of the SCEP RA certificate, in days (next issuance).",
        ge=2,
        le=825,
    )
    ra_renew_before_days: int = _setting(
        30,
        apply=ApplyLevel.HOT,
        description="Renew the SCEP RA certificate when this many days or fewer remain.",
        ge=1,
        le=824,
    )

    @field_validator("default_profile")
    @classmethod
    def _check_profile(cls, value: str) -> str:
        if value and value not in _disableable_profiles():
            raise ValueError(
                f"unknown profile {value!r} "
                f"(built-in profiles: {', '.join(sorted(_disableable_profiles()))})"
            )
        return value

    @model_validator(mode="after")
    def _check_renewal(self) -> Self:
        if self.ra_renew_before_days >= self.ra_validity_days:
            raise ValueError(
                "scep.ra_renew_before_days must be lower than scep.ra_validity_days, otherwise "
                "every check would issue a new RA certificate"
            )
        return self


def _https_origin(value: str, name: str) -> str:
    """An https:// origin without path, query or fragment (trailing slash dropped)."""
    value = value.strip().rstrip("/")
    if not value:
        return ""
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or parts.path or parts.query or parts.fragment:
        raise ValueError(
            f"{name} must be an https:// URL without path, for example https://pki.test"
        )
    try:
        parts.port  # noqa: B018 - validates the port
    except ValueError:
        raise ValueError(f"{name} has an invalid port") from None
    return value


def parse_resolver(value: str) -> tuple[str, int]:
    """``IP``, ``IP:port`` or ``[IPv6]:port`` → (address, port); port 53 by default."""
    text = value.strip()
    host, port = text, "53"
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        if rest:
            if not rest.startswith(":"):
                raise ValueError(f"invalid DNS resolver {value!r}")
            port = rest[1:]
    elif text.count(":") == 1:
        host, port = text.split(":")
    try:
        address = str(ipaddress.ip_address(host))
        number = int(port)
    except ValueError:
        raise ValueError(f"invalid DNS resolver {value!r}: an IP address and a port") from None
    if not 1 <= number <= 65535:
        raise ValueError(f"invalid DNS resolver {value!r}: port out of range")
    return address, number


def format_resolver(address: str, port: int) -> str:
    host = f"[{address}]" if ":" in address else address
    return f"{host}:{port}"


class AcmeSettings(_Section):
    """ACME (RFC 8555, ADR-0020): disabled by default, like every enrollment protocol."""

    enabled: bool = _setting(
        False,
        apply=ApplyLevel.HOT,
        description="Serve ACME (/acme, HTTPS only); false: every ACME route answers 404.",
    )
    default_profile: str = _setting(
        "tls_server",
        apply=ApplyLevel.HOT,
        description=(
            "Profile of /acme/directory; empty: that directory answers 404 and a profile is "
            "required (/acme/{profile}/directory)."
        ),
    )
    base_url: str = _setting(
        "",
        apply=ApplyLevel.HOT,
        description=(
            "Origin of the absolute ACME URLs (https://host[:port]); empty: https://"
            "H42_PKI_SERVER_HOSTNAME:H42_PKI_HTTPS_PORT. Never taken from the Host header."
        ),
    )
    terms_of_service_url: str = _setting(
        "",
        apply=ApplyLevel.HOT,
        description=(
            "Terms of service announced in the directory (meta.termsOfService); empty: none, "
            "and newAccount does not ask for termsOfServiceAgreed."
        ),
    )
    insecure_skip_validation: bool = _setting(
        False,
        apply=ApplyLevel.HOT,
        description=(
            "Lab mode: every challenge is declared valid without any check. Refused when "
            "H42_PKI_ENVIRONMENT is production."
        ),
    )
    manual_approval: bool = _setting(
        False,
        apply=ApplyLevel.HOT,
        description=(
            "Every ACME order waits for a decision (h42pki request approve|reject), whatever the "
            "approval of its profile; the order stays processing with Retry-After."
        ),
    )
    retry_after_seconds: int = _setting(
        60,
        apply=ApplyLevel.HOT,
        description="Retry-After of an order or a challenge still being processed.",
        ge=1,
        le=3600,
    )
    nonce_lifetime_minutes: int = _setting(
        60,
        apply=ApplyLevel.HOT,
        description="Lifetime of a Replay-Nonce not used yet.",
        ge=1,
        le=1440,
    )
    authorization_lifetime_hours: int = _setting(
        168,
        apply=ApplyLevel.HOT,
        description="Lifetime of a new authorization (its challenges must be validated within it).",
        ge=1,
        le=720,
    )
    order_lifetime_hours: int = _setting(
        168,
        apply=ApplyLevel.HOT,
        description="Lifetime of a new order (it must be finalized within it).",
        ge=1,
        le=720,
    )
    dns_resolvers: list[str] = _setting(
        [],
        apply=ApplyLevel.HOT,
        description=(
            "Resolvers asked for the TXT records of dns-01 (IP or IP:port, [IPv6]:port); "
            "empty: the resolvers of the system."
        ),
    )

    @field_validator("default_profile")
    @classmethod
    def _check_profile(cls, value: str) -> str:
        if value and value not in _disableable_profiles():
            raise ValueError(
                f"unknown profile {value!r} "
                f"(built-in profiles: {', '.join(sorted(_disableable_profiles()))})"
            )
        return value

    @field_validator("base_url")
    @classmethod
    def _check_base_url(cls, value: str) -> str:
        return _https_origin(value, "acme.base_url")

    @field_validator("dns_resolvers")
    @classmethod
    def _check_resolvers(cls, value: list[str]) -> list[str]:
        return [format_resolver(*parse_resolver(item)) for item in value]

    @field_validator("terms_of_service_url")
    @classmethod
    def _check_terms(cls, value: str) -> str:
        value = value.strip()
        if value and (
            urlsplit(value).scheme not in ("http", "https") or not urlsplit(value).netloc
        ):
            raise ValueError("acme.terms_of_service_url must be an http(s) URL")
        return value


class LoggingSettings(_Section):
    level: Literal["debug", "info", "warning", "error"] = _setting(
        "info", apply=ApplyLevel.HOT, description="Log level of the server."
    )
    format: Literal["text", "json"] = _setting(
        "text", apply=ApplyLevel.PROCESS, description="Log format: text or one JSON per line."
    )


class DatabaseSettings(_Section):
    pool_size: int | None = _setting(
        None,
        apply=ApplyLevel.PROCESS,
        description=(
            "Maximum connections of the pool for PostgreSQL / MySQL (null = Tortoise default); "
            "ignored with SQLite."
        ),
        ge=1,
        le=100,
    )


class RuntimeSettings(_Section):
    """All runtime settings, by section. ``RuntimeSettings()`` holds the code defaults."""

    tls_service: TlsServiceSettings = Field(default_factory=TlsServiceSettings)
    issuance: IssuanceSettings = Field(default_factory=IssuanceSettings)
    server: ServerSettings = Field(default_factory=ServerSettings)
    crl: CrlSettings = Field(default_factory=CrlSettings)
    ocsp: OcspSettings = Field(default_factory=OcspSettings)
    est: EstSettings = Field(default_factory=EstSettings)
    scep: ScepSettings = Field(default_factory=ScepSettings)
    acme: AcmeSettings = Field(default_factory=AcmeSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)


@dataclass(frozen=True)
class SettingInfo:
    key: str
    default: Any  # JSON value
    apply: ApplyLevel
    listeners: tuple[Listener, ...]
    description: str


def _catalog() -> dict[str, SettingInfo]:
    defaults = RuntimeSettings().model_dump(mode="json")
    catalog: dict[str, SettingInfo] = {}
    for section, section_field in RuntimeSettings.model_fields.items():
        model = section_field.annotation
        if not (isinstance(model, type) and issubclass(model, _Section)):
            raise TypeError(f"section {section} must be a settings section")
        for name, field in model.model_fields.items():
            extra = field.json_schema_extra
            listeners = extra.get("listeners") if isinstance(extra, dict) else None
            if not isinstance(extra, dict) or not isinstance(listeners, list):
                raise TypeError(f"{section}.{name} must be declared with _setting()")
            catalog[f"{section}.{name}"] = SettingInfo(
                key=f"{section}.{name}",
                default=defaults[section][name],
                apply=ApplyLevel(str(extra["apply"])),
                listeners=tuple(listeners),  # type: ignore[arg-type]
                description=field.description or "",
            )
    return catalog


SETTINGS: dict[str, SettingInfo] = _catalog()


def setting_info(key: str) -> SettingInfo:
    try:
        return SETTINGS[key]
    except KeyError:
        raise UnknownSetting(
            f"unknown setting {key!r} (see 'h42pki config show' for the list)"
        ) from None


def _message(exc: ValidationError) -> str:
    # include_input=False: submitted values are never echoed back.
    parts = []
    for error in exc.errors(include_input=False, include_url=False):
        location = ".".join(str(part) for part in error["loc"])
        message = str(error["msg"]).removeprefix("Value error, ")
        parts.append(f"{location}: {message}" if location else message)
    return "; ".join(parts)


def build_settings(values: Mapping[str, Any]) -> RuntimeSettings:
    """Validate stored values (``section.name`` → JSON value) over the code defaults."""
    nested: dict[str, dict[str, Any]] = {}
    for key, value in values.items():
        setting_info(key)
        section, name = key.split(".", 1)
        nested.setdefault(section, {})[name] = value
    try:
        return RuntimeSettings.model_validate(nested)
    except ValidationError as exc:
        raise InvalidSetting(_message(exc)) from None


def value_of(settings: RuntimeSettings, key: str) -> Any:
    """JSON value of one setting."""
    setting_info(key)
    section, name = key.split(".", 1)
    return settings.model_dump(mode="json")[section][name]


def parse_cli_value(text: str) -> Any:
    """Value typed on the command line: JSON if it parses, plain text otherwise."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text
