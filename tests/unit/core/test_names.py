import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from h42pki.core.errors import InvalidSubject
from h42pki.core.names import Subject, name_attributes, rfc4514

FULL_SUBJECT = {
    "country_name": "FR",
    "state_or_province_name": "Ile-de-France",
    "locality_name": "Paris",
    "organization_name": "Home42",
    "organizational_unit_name": "PKI",
    "common_name": "h42 Test CA",
    "email_address": "pki@example.test",
}


def test_common_name_only() -> None:  # B11
    name = Subject(common_name="h42 Root").x509_name()

    assert [attribute.oid for attribute in name] == [NameOID.COMMON_NAME]
    assert rfc4514(name) == "CN=h42 Root"


def test_attribute_order_and_rfc4514() -> None:
    name = Subject.model_validate(FULL_SUBJECT).x509_name()

    assert [attribute.oid for attribute in name] == [
        NameOID.COUNTRY_NAME,
        NameOID.STATE_OR_PROVINCE_NAME,
        NameOID.LOCALITY_NAME,
        NameOID.ORGANIZATION_NAME,
        NameOID.ORGANIZATIONAL_UNIT_NAME,
        NameOID.COMMON_NAME,
        NameOID.EMAIL_ADDRESS,
    ]
    # RFC 4514 lists the most specific attribute first.
    assert rfc4514(name) == (
        "emailAddress=pki@example.test,CN=h42 Test CA,OU=PKI,O=Home42,L=Paris,ST=Ile-de-France,C=FR"
    )


def test_email_address_is_named_in_dn() -> None:  # B28
    name = Subject(common_name="ops", email_address="ops@example.test").x509_name()

    assert rfc4514(name) == "emailAddress=ops@example.test,CN=ops"
    assert "1.2.840.113549.1.9.1" not in rfc4514(name)


def test_absent_attributes_are_skipped() -> None:
    name = Subject(common_name="x", organization_name="Home42").x509_name()

    assert [attribute.oid for attribute in name] == [
        NameOID.ORGANIZATION_NAME,
        NameOID.COMMON_NAME,
    ]


@pytest.mark.parametrize("country", ["fr", "FRA", "F", "F1", ""])
def test_invalid_country_rejected(country: str) -> None:
    with pytest.raises(ValidationError):
        Subject(common_name="x", country_name=country)


@pytest.mark.parametrize("common_name", ["", "   ", "x" * 65])
def test_invalid_common_name_rejected(common_name: str) -> None:
    with pytest.raises(ValidationError):
        Subject(common_name=common_name)


def test_common_name_required() -> None:
    with pytest.raises(ValidationError):
        Subject.model_validate({"organization_name": "Home42"})


@pytest.mark.parametrize(
    ("field", "limit"),
    [
        ("state_or_province_name", 128),
        ("locality_name", 128),
        ("organization_name", 64),
        ("organizational_unit_name", 64),
        ("common_name", 64),
        ("email_address", 255),
    ],
)
def test_rfc5280_upper_bounds(field: str, limit: int) -> None:
    base = {"common_name": "x"}

    Subject.model_validate({**base, field: "a" * limit})
    with pytest.raises(ValidationError):
        Subject.model_validate({**base, field: "a" * (limit + 1)})


def test_pascal_case_rejected() -> None:
    legacy = {
        "CountryName": "FR",
        "CommonName": "h42 Test CA",
        "Email": "pki@example.test",
    }
    with pytest.raises(ValidationError) as excinfo:
        Subject.model_validate({**legacy, "common_name": "x"})
    assert {error["type"] for error in excinfo.value.errors()} == {"extra_forbidden"}


def test_name_attributes_reads_a_name() -> None:
    name = Subject.model_validate(FULL_SUBJECT).x509_name()

    assert name_attributes(name).model_dump(exclude_none=True) == FULL_SUBJECT


def test_name_attributes_may_be_empty() -> None:
    attributes = name_attributes(x509.Name([]))

    assert attributes.present() == set()
    assert attributes.x509_name() == x509.Name([])


def test_name_attributes_refuses_unknown_attribute() -> None:
    name = x509.Name([x509.NameAttribute(NameOID.SERIAL_NUMBER, "42")])

    with pytest.raises(InvalidSubject, match=r"2\.5\.4\.5 is not supported"):
        name_attributes(name)


def test_name_attributes_refuses_repeated_attribute() -> None:
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "a"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "b"),
        ]
    )

    with pytest.raises(InvalidSubject, match="more than once"):
        name_attributes(name)


def test_name_attributes_refuses_multi_valued_rdn() -> None:
    rdn = x509.RelativeDistinguishedName(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "a"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "b"),
        ]
    )

    with pytest.raises(InvalidSubject, match="multi-valued"):
        name_attributes(x509.Name([rdn]))


@pytest.mark.filterwarnings("ignore:Attribute's length must be:UserWarning")
def test_name_attributes_checks_bounds() -> None:
    # cryptography refuses to build it, but a CSR from elsewhere may carry it.
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x" * 65, _validate=False)])

    with pytest.raises(InvalidSubject, match="common_name"):
        name_attributes(name)
