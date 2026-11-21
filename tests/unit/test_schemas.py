"""Extensions are snake_case only (ADR-0006): legacy PascalCase names are rejected."""

import pytest
from pydantic import ValidationError

from h42pki.ca.pki_models import Extensions


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
