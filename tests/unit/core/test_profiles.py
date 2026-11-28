from typing import Any

import pytest
from pydantic import ValidationError

from h42pki.core.extensions import validate_for_key
from h42pki.core.keys import KeyAlgorithm
from h42pki.core.profiles import BUILTIN_PROFILES, ProfileKind, ProfileSpec, resolve_key_usage

RSA = [KeyAlgorithm.RSA2048, KeyAlgorithm.RSA3072, KeyAlgorithm.RSA4096]
NOT_RSA = [KeyAlgorithm.EC_P256, KeyAlgorithm.EC_P384, KeyAlgorithm.ED25519]


def test_the_builtin_profiles() -> None:
    assert set(BUILTIN_PROFILES) == {
        "sub_ca",
        "tls_server",
        "tls_client",
        "ocsp_signer",
        "device",
        "service_tls",
        "scep_ra",
    }
    assert {spec.kind for spec in BUILTIN_PROFILES.values()} == set(ProfileKind)
    # Internal: the built-in HTTPS server (ADR-0013) and the SCEP RA (ADR-0019).
    internal = [spec.name for spec in BUILTIN_PROFILES.values() if spec.internal]
    assert internal == ["service_tls", "scep_ra"]


def test_scep_ra_profile() -> None:
    spec = BUILTIN_PROFILES["scep_ra"]

    assert (spec.validity_days, spec.max_validity_days) == (365, 825)
    assert spec.key_usage.digital_signature and spec.key_usage.key_encipherment
    assert not spec.key_usage.key_cert_sign and spec.extended_key_usage == []
    assert spec.basic_constraints.ca is False
    assert all(algorithm.value.startswith("rsa") for algorithm in spec.allowed_key_algorithms)


def test_service_tls_profile() -> None:
    spec = BUILTIN_PROFILES["service_tls"]

    assert (spec.validity_days, spec.max_validity_days) == (47, 200)
    assert spec.extended_key_usage == ["server_auth"]
    assert spec.basic_constraints.ca is False
    assert spec.san_policy.types == ["dns", "ip"] and spec.san_policy.required
    assert spec.subject_policy.required == ["common_name"]
    assert spec.subject_policy.cn_must_match_san
    assert spec.include_aia


def test_tls_server_follows_sc081v3() -> None:
    spec = BUILTIN_PROFILES["tls_server"]

    assert (spec.validity_days, spec.max_validity_days) == (47, 100)
    assert "SC-081v3" in spec.description
    assert spec.auto_approve
    assert spec.extended_key_usage == ["server_auth"]
    assert spec.san_policy.required and set(spec.san_policy.types) == {"dns", "ip"}
    assert spec.subject_policy.required == [] and spec.subject_policy.cn_must_match_san


@pytest.mark.parametrize(
    ("name", "validity", "auto_approve", "eku"),
    [
        ("sub_ca", (1825, 3650), False, []),
        ("tls_client", (365, 825), True, ["client_auth"]),
        ("ocsp_signer", (30, 90), False, ["ocsp_signing"]),
        ("device", (730, 1095), True, ["client_auth"]),
    ],
)
def test_builtin_values(
    name: str, validity: tuple[int, int], auto_approve: bool, eku: list[str]
) -> None:
    spec = BUILTIN_PROFILES[name]

    assert (spec.validity_days, spec.max_validity_days) == validity
    assert spec.auto_approve is auto_approve
    assert spec.extended_key_usage == eku


def test_sub_ca_constraints() -> None:
    spec = BUILTIN_PROFILES["sub_ca"]

    assert spec.basic_constraints.ca and spec.basic_constraints.path_length == 0
    assert spec.key_usage.key_cert_sign and spec.key_usage.crl_sign
    assert KeyAlgorithm.RSA2048 not in spec.allowed_key_algorithms
    assert len(spec.allowed_key_algorithms) == 5


def test_only_sub_ca_is_a_ca_and_only_ocsp_signer_has_nocheck() -> None:
    for name, spec in BUILTIN_PROFILES.items():
        assert spec.basic_constraints.ca is (name == "sub_ca")
        assert spec.ocsp_no_check is (name == "ocsp_signer")


@pytest.mark.parametrize("name", ["tls_server", "device"])
@pytest.mark.parametrize("algorithm", RSA)
def test_key_encipherment_kept_for_rsa(name: str, algorithm: KeyAlgorithm) -> None:
    usage = resolve_key_usage(BUILTIN_PROFILES[name], algorithm)

    assert usage.digital_signature and usage.key_encipherment


@pytest.mark.parametrize("name", ["tls_server", "device"])
@pytest.mark.parametrize("algorithm", NOT_RSA)
def test_key_encipherment_dropped_for_ec_and_ed25519(name: str, algorithm: KeyAlgorithm) -> None:
    usage = resolve_key_usage(BUILTIN_PROFILES[name], algorithm)

    assert usage.digital_signature and not usage.key_encipherment


@pytest.mark.parametrize("name", list(BUILTIN_PROFILES))
@pytest.mark.parametrize("algorithm", list(KeyAlgorithm))
def test_resolved_extensions_fit_every_allowed_key(name: str, algorithm: KeyAlgorithm) -> None:
    spec = BUILTIN_PROFILES[name]

    validate_for_key(spec.extensions_for(algorithm), algorithm)


def _spec(**overrides: Any) -> dict[str, Any]:
    return {**BUILTIN_PROFILES["tls_client"].model_dump(), **overrides}


def test_validity_cannot_exceed_maximum() -> None:
    with pytest.raises(ValidationError, match="cannot exceed max_validity_days"):
        ProfileSpec.model_validate(_spec(validity_days=900, max_validity_days=825))


def test_profile_extensions_follow_structural_rules() -> None:
    with pytest.raises(ValidationError, match="key_cert_sign requires"):
        ProfileSpec.model_validate(
            _spec(key_usage={"key_cert_sign": True}, basic_constraints={"ca": False})
        )


def test_required_and_allowed_are_disjoint() -> None:
    with pytest.raises(ValidationError, match="both required and allowed"):
        ProfileSpec.model_validate(
            _spec(subject_policy={"required": ["common_name"], "allowed": ["common_name"]})
        )


def test_required_san_needs_a_type() -> None:
    with pytest.raises(ValidationError, match="at least one allowed type"):
        ProfileSpec.model_validate(_spec(san_policy={"types": [], "required": True}))


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        ProfileSpec.model_validate(_spec(include_cdp=True))


@pytest.mark.parametrize("name", ["sub_ca", "tls_server", "tls_client", "device"])
def test_state_and_locality_allowed(name: str) -> None:  # B33
    permitted = BUILTIN_PROFILES[name].subject_policy.permitted()

    assert {"state_or_province_name", "locality_name"} <= permitted


def test_ocsp_signer_keeps_a_bare_common_name() -> None:
    assert BUILTIN_PROFILES["ocsp_signer"].subject_policy.permitted() == {"common_name"}
