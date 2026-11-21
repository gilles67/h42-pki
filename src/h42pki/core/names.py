"""Certificate subject names (B11, B28)."""

from typing import Annotated

from cryptography import x509
from cryptography.x509.oid import NameOID
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

from h42pki.core.errors import InvalidSubject

# Upper bounds from RFC 5280 appendix A.1 (ub-*).
UB_STATE_NAME = 128
UB_LOCALITY_NAME = 128
UB_ORGANIZATION_NAME = 64
UB_ORGANIZATIONAL_UNIT_NAME = 64
UB_COMMON_NAME = 64
UB_EMAILADDRESS_LENGTH = 255

# Attribute order inside the encoded Name (most general first).
SUBJECT_OIDS: dict[str, x509.ObjectIdentifier] = {
    "country_name": NameOID.COUNTRY_NAME,
    "state_or_province_name": NameOID.STATE_OR_PROVINCE_NAME,
    "locality_name": NameOID.LOCALITY_NAME,
    "organization_name": NameOID.ORGANIZATION_NAME,
    "organizational_unit_name": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "common_name": NameOID.COMMON_NAME,
    "email_address": NameOID.EMAIL_ADDRESS,
}

# Readable names for attributes that cryptography prints as dotted OIDs (B28).
RFC4514_OVERRIDES = {NameOID.EMAIL_ADDRESS: "emailAddress"}


def _bounded(max_length: int) -> StringConstraints:
    return StringConstraints(strip_whitespace=True, min_length=1, max_length=max_length)


CountryName = Annotated[str, Field(pattern=r"^[A-Z]{2}$")]
StateName = Annotated[str, _bounded(UB_STATE_NAME)]
LocalityName = Annotated[str, _bounded(UB_LOCALITY_NAME)]
OrganizationName = Annotated[str, _bounded(UB_ORGANIZATION_NAME)]
OrganizationalUnitName = Annotated[str, _bounded(UB_ORGANIZATIONAL_UNIT_NAME)]
CommonName = Annotated[str, _bounded(UB_COMMON_NAME)]
EmailAddress = Annotated[str, _bounded(UB_EMAILADDRESS_LENGTH)]


class NameAttributes(BaseModel):
    """Distinguished name attributes, all optional (a TLS server certificate may have none)."""

    model_config = ConfigDict(extra="forbid")

    country_name: CountryName | None = None
    state_or_province_name: StateName | None = None
    locality_name: LocalityName | None = None
    organization_name: OrganizationName | None = None
    organizational_unit_name: OrganizationalUnitName | None = None
    common_name: CommonName | None = None
    email_address: EmailAddress | None = None

    def present(self) -> set[str]:
        """Names of the attributes that have a value."""
        return {field for field in SUBJECT_OIDS if getattr(self, field) is not None}

    def x509_name(self) -> x509.Name:
        """Encode as a Name in the order C, ST, L, O, OU, CN, emailAddress; skip absent values."""
        return x509.Name(
            [
                x509.NameAttribute(oid, value)
                for field, oid in SUBJECT_OIDS.items()
                if (value := getattr(self, field)) is not None
            ]
        )


class Subject(NameAttributes):
    """Subject of a CA certificate: only ``common_name`` is mandatory (B11)."""

    common_name: CommonName


_FIELDS_BY_OID = {oid: field for field, oid in SUBJECT_OIDS.items()}


def name_attributes(name: x509.Name) -> NameAttributes:
    """Read a Name (e.g. from a CSR) into :class:`NameAttributes`.

    Unknown attribute types, multi-valued RDNs and repeated attributes are refused rather than
    dropped: the requester must know exactly what will be certified.
    """
    values: dict[str, str] = {}
    for rdn in name.rdns:
        if len(rdn) != 1:
            raise InvalidSubject("multi-valued RDNs are not supported")
        attribute = next(iter(rdn))
        field = _FIELDS_BY_OID.get(attribute.oid)
        if field is None:
            label = attribute.rfc4514_attribute_name
            raise InvalidSubject(f"subject attribute {label} is not supported")
        if field in values:
            raise InvalidSubject(f"subject attribute {field} appears more than once")
        if not isinstance(attribute.value, str):
            raise InvalidSubject(f"subject attribute {field} must be a string")
        values[field] = attribute.value
    try:
        return NameAttributes.model_validate(values)
    except ValidationError as exc:
        messages = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors())
        raise InvalidSubject(f"invalid subject: {messages}") from None


def rfc4514(name: x509.Name) -> str:
    """RFC 4514 string of ``name``, with ``emailAddress`` instead of its OID (B28)."""
    return name.rfc4514_string(attr_name_overrides=RFC4514_OVERRIDES)
