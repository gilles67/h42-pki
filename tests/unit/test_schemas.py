"""Request schemas are snake_case only (ADR-0006): legacy PascalCase names are rejected."""

import pytest
from pydantic import ValidationError

from h42pki.ca.pki_models import Extensions, Subject

SUBJECT = {
    "country_name": "FR",
    "state_or_province_name": "Ile-de-France",
    "locality_name": "Paris",
    "organization_name": "Home42",
    "organizational_unit_name": "PKI",
    "common_name": "h42 Test CA",
    "email_address": "pki@example.test",
}


def test_snake_case_subject_accepted() -> None:
    subject = Subject.model_validate(SUBJECT)

    assert subject.x509_subject().rfc4514_string() == (
        "1.2.840.113549.1.9.1=pki@example.test,CN=h42 Test CA,OU=PKI,O=Home42,"
        "L=Paris,ST=Ile-de-France,C=FR"
    )


def test_pascal_case_subject_rejected() -> None:
    legacy = {
        "CountryName": "FR",
        "ProvinceName": "Ile-de-France",
        "LocalityName": "Paris",
        "OrganizationName": "Home42",
        "OrganizationUnitName": "PKI",
        "CommonName": "h42 Test CA",
        "Email": "pki@example.test",
    }
    with pytest.raises(ValidationError) as excinfo:
        Subject.model_validate(legacy)
    errors = {error["type"] for error in excinfo.value.errors()}
    assert "extra_forbidden" in errors


def test_pascal_case_field_mixed_with_snake_case_rejected() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden|Extra inputs"):
        Subject.model_validate({**SUBJECT, "CommonName": "duplicate"})


def test_snake_case_extensions_accepted() -> None:
    extensions = Extensions.model_validate(
        {
            "basic_constraints": {"ca": True, "path_length": 0},
            "key_usage": {"key_cert_sign": True, "crl_sign": True},
            "extended_key_usage": ["server_auth", "client_auth", "ocsp_signing"],
        }
    )

    assert extensions.basic_constraints is not None
    assert extensions.basic_constraints.ca is True
    assert extensions.extended_key_usage == ["server_auth", "client_auth", "ocsp_signing"]


@pytest.mark.parametrize(
    "payload",
    [
        {"BasicConstraints": {"ca": True}},
        {"basic_constraints": {"CertificateAuthority": True, "PathLength": 0}},
        {"basic_constraints": {"ca": True, "PathLength": 0}},
        {"key_usage": {"KeyCertSign": True}},
        {"ExtendedKeyUsage": ["server_auth"]},
    ],
)
def test_pascal_case_extensions_rejected(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Extensions.model_validate(payload)


def test_unknown_extended_key_usage_rejected() -> None:
    with pytest.raises(ValidationError):
        Extensions.model_validate({"extended_key_usage": ["server_auth", "ServerAuthentication"]})
