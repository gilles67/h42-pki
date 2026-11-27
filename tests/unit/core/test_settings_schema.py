from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from h42pki.core.errors import InvalidSetting, UnknownSetting
from h42pki.core.settings_schema import (
    SETTINGS,
    ApplyLevel,
    RuntimeSettings,
    build_settings,
    parse_cli_value,
    setting_info,
    value_of,
)

# Expected application level of every setting (ARCHITECTURE section 7.2): a new setting must
# be added here, which forces a decision on its level.
EXPECTED_LEVELS = {
    "tls_service.validity_days": ("hot", ()),
    "tls_service.renew_before_days": ("hot", ()),
    "issuance.disabled_profiles": ("hot", ()),
    "server.tls_min_version": ("listener", ("https",)),
    "server.tls_ciphers": ("listener", ("https",)),
    "server.client_trust_anchors": ("listener", ("https",)),
    "server.keep_alive_timeout": ("listener", ("http", "https")),
    "server.limit_concurrency": ("listener", ("http", "https")),
    "server.backlog": ("listener", ("http", "https")),
    "server.max_header_size": ("listener", ("http", "https")),
    "crl.validity_hours": ("hot", ()),
    "crl.regenerate_before_hours": ("hot", ()),
    "ocsp.response_validity_hours": ("hot", ()),
    "est.enabled": ("hot", ()),
    "est.default_profile": ("hot", ()),
    "est.retry_after_seconds": ("hot", ()),
    "logging.level": ("hot", ()),
    "logging.format": ("process", ()),
    "database.pool_size": ("process", ()),
}


def _certificate(*, ca: bool) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "anchor")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def test_every_setting_declares_its_level() -> None:
    assert {key: (info.apply.value, info.listeners) for key, info in SETTINGS.items()} == (
        EXPECTED_LEVELS
    )
    assert all(info.description for info in SETTINGS.values())


def test_defaults() -> None:
    settings = RuntimeSettings()

    assert settings.tls_service.validity_days == 47
    assert settings.tls_service.renew_before_days == 15
    assert settings.issuance.disabled_profiles == []
    assert settings.server.tls_min_version == "tls1.2"
    assert settings.server.tls_ciphers is None
    assert settings.server.client_trust_anchors == []
    assert settings.logging.level == "info"
    assert settings.logging.format == "text"
    assert settings.database.pool_size is None
    assert (settings.crl.validity_hours, settings.crl.regenerate_before_hours) == (168, 48)
    assert settings.ocsp.response_validity_hours == 24
    assert (settings.est.enabled, settings.est.default_profile) == (False, "")
    assert settings.est.retry_after_seconds == 60
    assert SETTINGS["tls_service.validity_days"].default == 47


def test_build_and_read_values() -> None:
    settings = build_settings(
        {"tls_service.validity_days": 30, "issuance.disabled_profiles": ["device", "device"]}
    )

    assert value_of(settings, "tls_service.validity_days") == 30
    assert value_of(settings, "issuance.disabled_profiles") == ["device"]  # deduplicated
    assert value_of(settings, "tls_service.renew_before_days") == 15


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"tls_service.validity_days": 201}, "less than or equal to 200"),
        ({"tls_service.validity_days": 1}, "greater than or equal to 2"),
        ({"tls_service.validity_days": "long"}, "valid integer"),
        ({"tls_service.renew_before_days": 47}, "lower than tls_service.validity_days"),
        (
            {"tls_service.validity_days": 10, "tls_service.renew_before_days": 10},
            "lower than tls_service.validity_days",
        ),
        ({"issuance.disabled_profiles": ["nope"]}, "unknown profile 'nope'"),
        ({"issuance.disabled_profiles": "device"}, "valid list"),
        ({"server.tls_min_version": "tls1.1"}, "tls1.2"),
        ({"server.tls_ciphers": ""}, "at least 1 character"),
        ({"server.tls_ciphers": "NOT-A-CIPHER"}, "OpenSSL selects no cipher"),
        ({"server.keep_alive_timeout": 0}, "greater than or equal to 1"),
        ({"server.max_header_size": 10}, "greater than or equal to 1024"),
        ({"server.client_trust_anchors": ["not a certificate"]}, "one PEM certificate"),
        ({"logging.level": "verbose"}, "debug"),
        ({"logging.format": "xml"}, "text"),
        ({"database.pool_size": 0}, "greater than or equal to 1"),
    ],
)
def test_invalid_values(values: dict[str, object], message: str) -> None:
    with pytest.raises(InvalidSetting, match=message):
        build_settings(values)


def test_error_never_echoes_the_value() -> None:
    with pytest.raises(InvalidSetting) as exc_info:
        build_settings({"server.tls_ciphers": 12345})

    assert "12345" not in exc_info.value.detail


def test_unknown_setting() -> None:
    with pytest.raises(UnknownSetting, match="unknown setting 'server.nope'"):
        build_settings({"server.nope": 1})
    with pytest.raises(UnknownSetting):
        setting_info("nope")


def test_trust_anchors_must_be_ca_certificates() -> None:
    anchor = _certificate(ca=True)

    settings = build_settings({"server.client_trust_anchors": [anchor, anchor]})

    assert settings.server.client_trust_anchors == [anchor.strip() + "\n"]
    with pytest.raises(InvalidSetting, match="must be a CA certificate"):
        build_settings({"server.client_trust_anchors": [_certificate(ca=False)]})


def test_levels_are_an_enum() -> None:
    assert {info.apply for info in SETTINGS.values()} <= set(ApplyLevel)


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("30", 30),
        ('["device", "tls_client"]', ["device", "tls_client"]),
        ("null", None),
        ("true", True),
        ("tls1.3", "tls1.3"),  # not JSON: plain text
        ('"30"', "30"),
        ("ECDHE+AESGCM", "ECDHE+AESGCM"),
    ],
)
def test_parse_cli_value(text: str, value: object) -> None:
    assert parse_cli_value(text) == value


def test_valid_cipher_list() -> None:
    assert build_settings({"server.tls_ciphers": "ECDHE+AESGCM"}).server.tls_ciphers == (
        "ECDHE+AESGCM"
    )


def test_crl_window_must_leave_time_before_regeneration() -> None:
    assert build_settings({"crl.validity_hours": 4380, "crl.regenerate_before_hours": 720})
    with pytest.raises(InvalidSetting, match="lower than crl.validity_hours"):
        build_settings({"crl.validity_hours": 24})  # 48 hours before: every check would regenerate
    with pytest.raises(InvalidSetting):
        build_settings({"crl.validity_hours": 0})


def test_est_default_profile_must_be_a_profile() -> None:
    assert build_settings({"est.default_profile": "tls_client"}).est.default_profile == "tls_client"
    with pytest.raises(InvalidSetting, match="unknown profile"):
        build_settings({"est.default_profile": "service_tls"})  # internal
    with pytest.raises(InvalidSetting, match="unknown profile"):
        build_settings({"est.default_profile": "nope"})
