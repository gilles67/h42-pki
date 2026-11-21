"""Requested certificate extensions and their validation (B9, B10).

Until profiles exist, the extensions stored with a certificate are the ones requested through
the API. Structural rules are checked by the Pydantic validators (422 at request time); rules
that depend on the key algorithm are checked by :func:`validate_for_key`.
"""

from typing import Literal, Self

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from pydantic import BaseModel, ConfigDict, Field, model_validator

from h42pki.core.errors import InvalidExtensions
from h42pki.core.keys import KeyAlgorithm

ExtendedKeyUsageName = Literal[
    "server_auth",
    "client_auth",
    "code_signing",
    "email_protection",
    "time_stamping",
    "ocsp_signing",
]

EKU_OIDS: dict[ExtendedKeyUsageName, x509.ObjectIdentifier] = {
    "server_auth": ExtendedKeyUsageOID.SERVER_AUTH,
    "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
    "email_protection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "time_stamping": ExtendedKeyUsageOID.TIME_STAMPING,
    "ocsp_signing": ExtendedKeyUsageOID.OCSP_SIGNING,
}

RSA_ALGORITHMS = frozenset({KeyAlgorithm.RSA2048, KeyAlgorithm.RSA3072, KeyAlgorithm.RSA4096})
EC_ALGORITHMS = frozenset({KeyAlgorithm.EC_P256, KeyAlgorithm.EC_P384})


class BasicConstraints(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ca: bool = False
    path_length: int | None = Field(default=None, ge=0)  # absent by default (B10)

    @model_validator(mode="after")
    def _path_length_needs_ca(self) -> Self:
        if self.path_length is not None and not self.ca:
            raise ValueError("path_length is only allowed when ca is true")
        return self


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

    @model_validator(mode="after")
    def _check(self) -> Self:
        if (self.encipher_only or self.decipher_only) and not self.key_agreement:
            raise ValueError("encipher_only and decipher_only require key_agreement")
        if not any(self.model_dump().values()):
            raise ValueError("key_usage must assert at least one usage")
        return self


class Extensions(BaseModel):
    """Extensions requested for a certificate."""

    model_config = ConfigDict(extra="forbid")

    basic_constraints: BasicConstraints | None = None
    key_usage: KeyUsage | None = None
    extended_key_usage: list[ExtendedKeyUsageName] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> Self:
        is_ca = self.basic_constraints is not None and self.basic_constraints.ca
        if self.key_usage is not None and self.key_usage.key_cert_sign and not is_ca:
            # RFC 5280 section 4.2.1.9
            raise ValueError("key_cert_sign requires basic_constraints.ca = true")
        if len(set(self.extended_key_usage)) != len(self.extended_key_usage):
            raise ValueError("extended_key_usage contains duplicates")
        return self

    def apply(self, builder: x509.CertificateBuilder) -> x509.CertificateBuilder:
        """Add the requested extensions: BasicConstraints and KeyUsage critical, EKU not."""
        if self.basic_constraints is not None:
            builder = builder.add_extension(
                x509.BasicConstraints(
                    ca=self.basic_constraints.ca,
                    path_length=self.basic_constraints.path_length,
                ),
                critical=True,
            )
        if self.key_usage is not None:
            builder = builder.add_extension(
                x509.KeyUsage(**self.key_usage.model_dump()), critical=True
            )
        if self.extended_key_usage:  # B9
            builder = builder.add_extension(
                x509.ExtendedKeyUsage([EKU_OIDS[name] for name in self.extended_key_usage]),
                critical=False,
            )
        return builder


def validate_for_key(extensions: Extensions, algorithm: KeyAlgorithm) -> None:
    """Reject key usages the key algorithm cannot perform."""
    usage = extensions.key_usage
    if usage is None:
        return
    if algorithm not in RSA_ALGORITHMS and (usage.key_encipherment or usage.data_encipherment):
        raise InvalidExtensions(
            f"key_encipherment and data_encipherment require an RSA key, not {algorithm.value}"
        )
    if algorithm not in EC_ALGORITHMS and usage.key_agreement:
        raise InvalidExtensions(f"key_agreement requires an EC key, not {algorithm.value}")
