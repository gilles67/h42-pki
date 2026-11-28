"""Certificate profiles: what an issued certificate may contain (ADR-0009).

A profile, not the CSR, decides basic constraints, key usage, extended key usage and validity;
the CSR only provides the public key, the subject and the SANs, both filtered by the profile
(CLAUDE.md section 6.3). The built-in profiles below are written to the database at start-up.
"""

from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from h42pki.core.extensions import (
    RSA_ALGORITHMS,
    BasicConstraints,
    ExtendedKeyUsageName,
    Extensions,
    KeyUsage,
)
from h42pki.core.keys import KeyAlgorithm
from h42pki.core.validity import MAX_VALIDITY_DAYS, MIN_VALIDITY_DAYS

SubjectField = Literal[
    "country_name",
    "state_or_province_name",
    "locality_name",
    "organization_name",
    "organizational_unit_name",
    "common_name",
    "email_address",
]
SanType = Literal["dns", "ip", "email", "uri"]


class ProfileKind(StrEnum):
    SUB_CA = "sub_ca"
    TLS_SERVER = "tls_server"
    TLS_CLIENT = "tls_client"
    OCSP_SIGNER = "ocsp_signer"
    DEVICE = "device"
    SERVICE_TLS = "service_tls"
    SCEP_RA = "scep_ra"


class SubjectPolicy(BaseModel):
    """Subject attributes a request must (``required``) or may (``allowed``) contain."""

    model_config = ConfigDict(extra="forbid")

    required: list[SubjectField] = Field(default_factory=list)
    allowed: list[SubjectField] = Field(default_factory=list)
    # When present, the common name must repeat one of the SANs (TLS server certificates).
    cn_must_match_san: bool = False

    @model_validator(mode="after")
    def _check(self) -> Self:
        if set(self.required) & set(self.allowed):
            raise ValueError("an attribute cannot be both required and allowed")
        return self

    def permitted(self) -> set[str]:
        return set(self.required) | set(self.allowed)


class SanPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    types: list[SanType] = Field(default_factory=list)
    required: bool = False

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.required and not self.types:
            raise ValueError("required SANs need at least one allowed type")
        return self


class ProfileSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    kind: ProfileKind
    description: str
    auto_approve: bool
    validity_days: int = Field(ge=MIN_VALIDITY_DAYS, le=MAX_VALIDITY_DAYS)
    max_validity_days: int = Field(ge=MIN_VALIDITY_DAYS, le=MAX_VALIDITY_DAYS)
    basic_constraints: BasicConstraints
    key_usage: KeyUsage
    extended_key_usage: list[ExtendedKeyUsageName] = Field(default_factory=list)
    allowed_key_algorithms: list[KeyAlgorithm]
    subject_policy: SubjectPolicy
    san_policy: SanPolicy
    ocsp_no_check: bool = False
    # AIA caIssuers in issued certificates, when the CA has a public base URL.
    include_aia: bool = True
    # Internal profile (service_tls, ADR-0013): issued by the CA for its own server only, never
    # through requests or enrolment protocols, and cannot be disabled.
    internal: bool = False

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.validity_days > self.max_validity_days:
            raise ValueError("validity_days cannot exceed max_validity_days")
        if not self.allowed_key_algorithms:
            raise ValueError("allowed_key_algorithms cannot be empty")
        Extensions(  # same structural rules as requested extensions
            basic_constraints=self.basic_constraints,
            key_usage=self.key_usage,
            extended_key_usage=self.extended_key_usage,
        )
        return self

    def extensions_for(self, algorithm: KeyAlgorithm) -> Extensions:
        """BasicConstraints / KU / EKU to put in a certificate for a key of ``algorithm``."""
        return Extensions(
            basic_constraints=self.basic_constraints,
            key_usage=resolve_key_usage(self, algorithm),
            extended_key_usage=self.extended_key_usage,
        )


def resolve_key_usage(spec: ProfileSpec, algorithm: KeyAlgorithm) -> KeyUsage:
    """Key usage for ``algorithm``: key encipherment only makes sense for RSA keys."""
    if algorithm in RSA_ALGORITHMS:
        return spec.key_usage
    return spec.key_usage.model_copy(update={"key_encipherment": False})


ALL_ALGORITHMS = list(KeyAlgorithm)
# State and locality are allowed wherever a full organisation subject makes sense (B33), so that
# CSRs from an interactive `openssl req` pass; the OCSP signer keeps a bare common name.
LOCATION: list[SubjectField] = ["state_or_province_name", "locality_name"]
CA_SUBJECT = SubjectPolicy(
    required=["common_name"],
    allowed=["organization_name", "organizational_unit_name", "country_name", *LOCATION],
)

# Internal profile of the built-in HTTPS server certificate (ADR-0013).
SERVICE_TLS_PROFILE = "service_tls"
SCEP_RA_PROFILE = "scep_ra"
# Profile of the CAs signed by this one, by request or by federation (ADR-0015).
SUB_CA_PROFILE = "sub_ca"

BUILTIN_PROFILES: dict[str, ProfileSpec] = {
    spec.name: spec
    for spec in (
        ProfileSpec(
            name=SUB_CA_PROFILE,
            kind=ProfileKind.SUB_CA,
            description="Subordinate CA certificate (pathLen 0). Requires manual approval.",
            auto_approve=False,
            validity_days=1825,
            max_validity_days=3650,
            basic_constraints=BasicConstraints(ca=True, path_length=0),
            key_usage=KeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=True),
            allowed_key_algorithms=[alg for alg in KeyAlgorithm if alg is not KeyAlgorithm.RSA2048],
            subject_policy=CA_SUBJECT,
            san_policy=SanPolicy(),
        ),
        ProfileSpec(
            name="tls_server",
            kind=ProfileKind.TLS_SERVER,
            description=(
                "TLS server certificate. Validity follows CA/Browser Forum ballot SC-081v3, "
                "ahead of its schedule: 47 days by default, 100 at most (47 at most from "
                "2029-03-15)."
            ),
            auto_approve=True,
            validity_days=47,
            max_validity_days=100,
            basic_constraints=BasicConstraints(ca=False),
            key_usage=KeyUsage(digital_signature=True, key_encipherment=True),
            extended_key_usage=["server_auth"],
            allowed_key_algorithms=ALL_ALGORITHMS,
            subject_policy=SubjectPolicy(
                allowed=[
                    "common_name",
                    "organization_name",
                    "organizational_unit_name",
                    "country_name",
                    *LOCATION,
                ],
                cn_must_match_san=True,
            ),
            san_policy=SanPolicy(types=["dns", "ip"], required=True),
        ),
        ProfileSpec(
            name="tls_client",
            kind=ProfileKind.TLS_CLIENT,
            description="TLS client certificate (users, services).",
            auto_approve=True,
            validity_days=365,
            max_validity_days=825,
            basic_constraints=BasicConstraints(ca=False),
            key_usage=KeyUsage(digital_signature=True),
            extended_key_usage=["client_auth"],
            allowed_key_algorithms=ALL_ALGORITHMS,
            subject_policy=SubjectPolicy(
                required=["common_name"],
                allowed=[
                    "organization_name",
                    "organizational_unit_name",
                    "country_name",
                    "email_address",
                    *LOCATION,
                ],
            ),
            san_policy=SanPolicy(types=["dns", "email", "uri"]),
        ),
        ProfileSpec(
            name="ocsp_signer",
            kind=ProfileKind.OCSP_SIGNER,
            description="Delegated OCSP responder certificate (id-pkix-ocsp-nocheck).",
            auto_approve=False,
            validity_days=30,
            max_validity_days=90,
            basic_constraints=BasicConstraints(ca=False),
            key_usage=KeyUsage(digital_signature=True),
            extended_key_usage=["ocsp_signing"],
            allowed_key_algorithms=ALL_ALGORITHMS,
            subject_policy=SubjectPolicy(required=["common_name"]),
            san_policy=SanPolicy(),
            ocsp_no_check=True,
        ),
        ProfileSpec(
            name="device",
            kind=ProfileKind.DEVICE,
            description="Network device or IoT certificate (client authentication).",
            auto_approve=True,
            validity_days=730,
            max_validity_days=1095,
            basic_constraints=BasicConstraints(ca=False),
            key_usage=KeyUsage(digital_signature=True, key_encipherment=True),
            extended_key_usage=["client_auth"],
            allowed_key_algorithms=ALL_ALGORITHMS,
            subject_policy=SubjectPolicy(
                required=["common_name"],
                allowed=["organization_name", "organizational_unit_name", *LOCATION],
            ),
            san_policy=SanPolicy(types=["dns", "ip", "uri"]),
        ),
        ProfileSpec(
            name=SERVICE_TLS_PROFILE,
            kind=ProfileKind.SERVICE_TLS,
            description=(
                "Internal: certificate of the built-in HTTPS server of this CA, issued and renewed "
                "by the CA itself (ADR-0013). Never available to requests or enrolment protocols."
            ),
            auto_approve=True,
            validity_days=47,
            max_validity_days=200,
            basic_constraints=BasicConstraints(ca=False),
            key_usage=KeyUsage(digital_signature=True, key_encipherment=True),
            extended_key_usage=["server_auth"],
            allowed_key_algorithms=ALL_ALGORITHMS,
            subject_policy=SubjectPolicy(required=["common_name"], cn_must_match_san=True),
            san_policy=SanPolicy(types=["dns", "ip"], required=True),
            internal=True,
        ),
        ProfileSpec(
            name=SCEP_RA_PROFILE,
            kind=ProfileKind.SCEP_RA,
            description=(
                "Internal: SCEP registration authority of this CA, which decrypts the requests and "
                "signs the answers, so that SCEP never uses the CA key (ADR-0019). Issued and "
                "renewed by the CA itself; never available to requests or enrolment protocols."
            ),
            auto_approve=True,
            validity_days=365,
            max_validity_days=825,
            basic_constraints=BasicConstraints(ca=False),
            key_usage=KeyUsage(digital_signature=True, key_encipherment=True),
            allowed_key_algorithms=[
                KeyAlgorithm.RSA2048,
                KeyAlgorithm.RSA3072,
                KeyAlgorithm.RSA4096,
            ],
            subject_policy=SubjectPolicy(required=["common_name"]),
            san_policy=SanPolicy(),
            internal=True,
        ),
    )
}
