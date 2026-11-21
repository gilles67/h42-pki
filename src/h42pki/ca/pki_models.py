# Legacy request models, renamed to snake_case (ADR-0006); moved to core/ in lot 4.
from typing import Literal

from cryptography import x509
from pydantic import BaseModel, ConfigDict, Field

ExtendedKeyUsageName = Literal[
    "server_auth",
    "client_auth",
    "code_signing",
    "email_protection",
    "time_stamping",
    "ocsp_signing",
]


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
