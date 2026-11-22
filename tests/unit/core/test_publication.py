import pytest

from h42pki.core.errors import InvalidAuthorityName, InvalidPublicBaseUrl
from h42pki.core.publication import (
    HTTPS_WARNING,
    ca_certificate_url,
    normalize_public_base_url,
    validate_authority_name,
)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://pki.example.test", "http://pki.example.test"),
        ("http://pki.example.test/", "http://pki.example.test"),
        ("http://PKI.Example.TEST:8080/", "http://pki.example.test:8080"),
        ("HTTP://pki.example.test/h42//", "http://pki.example.test/h42"),
        ("  http://192.0.2.10:8000 ", "http://192.0.2.10:8000"),
        ("http://[2001:db8::1]:8000/", "http://[2001:db8::1]:8000"),
    ],
)
def test_accepted_and_normalized(url: str, expected: str) -> None:
    result = normalize_public_base_url(url)

    assert result.url == expected
    assert result.warnings == []


def test_https_is_accepted_with_a_warning() -> None:
    result = normalize_public_base_url("https://pki.example.test/")

    assert result.url == "https://pki.example.test"
    assert result.warnings == [HTTPS_WARNING]
    assert "RFC 5280" in HTTPS_WARNING


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("ftp://pki.example.test", "must use http or https"),
        ("pki.example.test", "must use http or https"),
        ("http://", "has no host"),
        ("http:///path", "has no host"),
        ("http://pki.example.test/?x=1", "query string"),
        ("http://pki.example.test/?", "query string"),
        ("http://pki.example.test/#top", "fragment"),
        ("http://user:secret@pki.example.test", "credentials"),
    ],
)
def test_refused(url: str, message: str) -> None:
    with pytest.raises(InvalidPublicBaseUrl, match=message):
        normalize_public_base_url(url)


def test_credentials_are_not_echoed() -> None:
    with pytest.raises(InvalidPublicBaseUrl) as excinfo:
        normalize_public_base_url("http://user:secret@pki.example.test")

    assert "secret" not in str(excinfo.value)


def test_ca_certificate_url() -> None:
    assert ca_certificate_url("http://pki.example.test", "home42-root") == (
        "http://pki.example.test/ca/home42-root.crt"
    )


@pytest.mark.parametrize("name", ["home42-root", "root", "a", "ca1", "x" * 64])
def test_valid_authority_names(name: str) -> None:
    assert validate_authority_name(name) == name


@pytest.mark.parametrize(
    "name", ["", "Home42", "home 42", "home/42", "-root", "root-", "x" * 65, "root.ca"]
)
def test_invalid_authority_names(name: str) -> None:
    with pytest.raises(InvalidAuthorityName, match="invalid CA name"):
        validate_authority_name(name)


def test_chain_is_reserved() -> None:
    with pytest.raises(InvalidAuthorityName, match="reserved"):
        validate_authority_name("chain")
