# Legacy request models, renamed to snake_case (ADR-0006); moved to core/ in lot 4.
from typing import Literal

from cryptography import x509
from cryptography.x509.oid import NameOID
from pydantic import BaseModel, ConfigDict, Field

SUBJECT_OIDS = {
    "country_name": NameOID.COUNTRY_NAME,
    "state_or_province_name": NameOID.STATE_OR_PROVINCE_NAME,
    "locality_name": NameOID.LOCALITY_NAME,
    "organization_name": NameOID.ORGANIZATION_NAME,
    "organizational_unit_name": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "common_name": NameOID.COMMON_NAME,
    "email_address": NameOID.EMAIL_ADDRESS,
}

ExtendedKeyUsageName = Literal[
    "server_auth",
    "client_auth",
    "code_signing",
    "email_protection",
    "time_stamping",
    "ocsp_signing",
]


class Subject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # All attributes are still mandatory (B11, lot 4).
    country_name: str
    state_or_province_name: str
    locality_name: str
    organization_name: str
    organizational_unit_name: str
    common_name: str
    email_address: str

    def x509_subject(self) -> x509.Name:
        return x509.Name([x509.NameAttribute(SUBJECT_OIDS[field], value) for field, value in self])


class BasicConstraints(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ca: bool = False
    path_length: int = 0  # legacy default kept (B10, lot 4)


class KeyUsage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    digital_signature: bool = False
    content_commitment: bool = False
    key_encipherment: bool = False
    data_encipherment: bool = False
    key_agreement: bool = False
    key_cert_sign: bool = False
    crl_sign: bool = False
    encipher_only: bool = False
    decipher_only: bool = False


class Extensions(BaseModel):
    """Extensions requested for a certificate (until profiles exist)."""

    model_config = ConfigDict(extra="forbid")

    basic_constraints: BasicConstraints | None = None
    key_usage: KeyUsage | None = None
    extended_key_usage: list[ExtendedKeyUsageName] = Field(default_factory=list)

    def append_extension(self, cert: x509.CertificateBuilder) -> x509.CertificateBuilder:
        if self.basic_constraints is not None:
            cert = cert.add_extension(
                x509.BasicConstraints(
                    ca=self.basic_constraints.ca,
                    path_length=self.basic_constraints.path_length,
                ),
                critical=True,
            )
        if self.key_usage is not None:
            cert = cert.add_extension(
                x509.KeyUsage(**self.key_usage.model_dump()),
                critical=True,
            )
        # TODO(lot4): B9 - extended_key_usage is stored but not added to the certificate.
        return cert
