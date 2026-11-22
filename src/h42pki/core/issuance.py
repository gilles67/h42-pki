"""Certificate construction: the root CA certificate and certificates issued by a CA."""

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import assert_never

from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID

from h42pki.core.csr import ParsedCsr, SanEntry
from h42pki.core.errors import (
    InvalidSan,
    InvalidSubject,
    InvalidValidity,
    NotARootCA,
    PathLengthExceeded,
    ProfileViolation,
)
from h42pki.core.extensions import BasicConstraints, Extensions, validate_for_key
from h42pki.core.keys import SupportedPrivateKey, algorithm_of, signature_hash
from h42pki.core.names import Subject
from h42pki.core.profiles import ProfileSpec
from h42pki.core.serial import new_serial_hex
from h42pki.core.validity import (
    CLOCK_SKEW,
    DEFAULT_CA_VALIDITY_DAYS,
    MAX_VALIDITY_DAYS,
    MIN_VALIDITY_DAYS,
    check_validity_days,
    validity_window,
)

__all__ = [
    "CLOCK_SKEW",
    "DEFAULT_CA_VALIDITY_DAYS",
    "MAX_VALIDITY_DAYS",
    "MIN_VALIDITY_DAYS",
    "IssuancePlan",
    "IssuedCertificate",
    "build_issued",
    "build_self_signed",
    "check_root_ca",
    "check_validity_days",
    "plan_issuance",
    "validity_window",
]


# --- root CA certificate -----------------------------------------------------------------------


def check_root_ca(extensions: Extensions) -> None:
    """A root CA certificate needs ``ca`` and ``key_cert_sign``."""
    basic = extensions.basic_constraints
    usage = extensions.key_usage
    if basic is None or not basic.ca or usage is None or not usage.key_cert_sign:
        raise NotARootCA(
            "a root CA certificate requires basic_constraints.ca = true and "
            "key_usage.key_cert_sign = true"
        )


def build_self_signed(
    subject: Subject,
    extensions: Extensions,
    private_key: SupportedPrivateKey,
    *,
    serial_hex: str,
    validity_days: int,
    now: datetime,
) -> x509.Certificate:
    """Build the root CA certificate, issued and signed by its own key (B12, B17, ADR-0010)."""
    check_root_ca(extensions)
    validate_for_key(extensions, algorithm_of(private_key))
    not_before, not_after = validity_window(now, validity_days)

    name = subject.x509_name()
    public_key = private_key.public_key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(int(serial_hex, 16))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    builder = extensions.apply(builder)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
    ).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key), critical=False)

    certificate = builder.sign(private_key, signature_hash(private_key))
    certificate.verify_directly_issued_by(certificate)
    return certificate


# --- certificates issued by a CA from a CSR ----------------------------------------------------


@dataclass(frozen=True)
class IssuancePlan:
    """Everything the profile decided for a request, before any signature."""

    subject: x509.Name
    sans: tuple[SanEntry, ...]
    extensions: Extensions
    not_before: datetime
    not_after: datetime
    validity_truncated: bool


@dataclass(frozen=True)
class IssuedCertificate:
    certificate: x509.Certificate
    validity_truncated: bool


def _issuer_basic_constraints(issuer_cert: x509.Certificate) -> x509.BasicConstraints:
    try:
        basic = issuer_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        basic = None
    if basic is None or not basic.ca:
        raise ProfileViolation("the issuer certificate is not a CA certificate")
    return basic


def _check_sans(parsed: ParsedCsr, spec: ProfileSpec) -> None:
    policy = spec.san_policy
    if parsed.sans and not policy.types:
        raise InvalidSan(f"profile {spec.name} does not allow subject alternative names")
    if forbidden := sorted({san.type for san in parsed.sans} - set(policy.types)):
        raise InvalidSan(f"SAN type(s) {', '.join(forbidden)} not allowed by profile {spec.name}")
    if policy.required and not parsed.sans:
        raise InvalidSan(f"profile {spec.name} requires at least one subject alternative name")


def _check_subject(parsed: ParsedCsr, spec: ProfileSpec) -> None:
    present = parsed.subject.present()
    policy = spec.subject_policy
    if extra := sorted(present - policy.permitted()):
        raise InvalidSubject(
            f"subject attribute(s) {', '.join(extra)} not allowed by profile {spec.name}"
        )
    if missing := sorted(set(policy.required) - present):
        raise InvalidSubject(
            f"subject attribute(s) {', '.join(missing)} required by profile {spec.name}"
        )
    if not present and not parsed.sans:
        raise InvalidSubject("a certificate needs a subject or at least one SAN")
    common_name = parsed.subject.common_name
    if policy.cn_must_match_san and common_name is not None:
        names = {san.value.lower() for san in parsed.sans if san.type in ("dns", "ip")}
        if common_name.lower() not in names:
            raise InvalidSubject(
                f"the common name must repeat one of the DNS or IP SANs in profile {spec.name}"
            )


def _validity(
    spec: ProfileSpec,
    issuer_cert: x509.Certificate,
    validity_days: int | None,
    now: datetime,
) -> tuple[datetime, datetime, bool]:
    days = spec.validity_days if validity_days is None else validity_days
    if days > spec.max_validity_days:
        raise InvalidValidity(
            f"profile {spec.name} allows at most {spec.max_validity_days} days, not {days}"
        )
    not_before, not_after = validity_window(now, days)
    issuer_not_after = issuer_cert.not_valid_after_utc
    truncated = not_after > issuer_not_after
    if truncated:
        not_after = issuer_not_after  # never outlive the issuer (CLAUDE.md section 6.5)
    if not_after <= not_before:
        raise InvalidValidity("the issuing CA certificate expires too soon")
    return not_before, not_after, truncated


def _extensions(
    parsed: ParsedCsr, spec: ProfileSpec, issuer_basic: x509.BasicConstraints
) -> Extensions:
    extensions = spec.extensions_for(parsed.key_algorithm)
    if spec.basic_constraints.ca:
        issuer_path_length = issuer_basic.path_length
        if issuer_path_length == 0:
            raise PathLengthExceeded(
                "the issuing CA has pathLen 0 and cannot issue CA certificates"
            )
        path_length = spec.basic_constraints.path_length
        if issuer_path_length is not None:
            ceiling = issuer_path_length - 1  # strictly below the issuer
            path_length = ceiling if path_length is None else min(path_length, ceiling)
        extensions = extensions.model_copy(
            update={"basic_constraints": BasicConstraints(ca=True, path_length=path_length)}
        )
    validate_for_key(extensions, parsed.key_algorithm)
    return extensions


def plan_issuance(
    parsed: ParsedCsr,
    spec: ProfileSpec,
    issuer_cert: x509.Certificate,
    *,
    validity_days: int | None,
    now: datetime,
) -> IssuancePlan:
    """Apply ``spec`` to a parsed CSR. Pure and key-less: also used to check a request early.

    Violations raise explicit errors (422) instead of silently dropping what was asked.
    """
    if parsed.key_algorithm not in spec.allowed_key_algorithms:
        raise ProfileViolation(
            f"key algorithm {parsed.key_algorithm.value} not allowed by profile {spec.name}"
        )
    issuer_basic = _issuer_basic_constraints(issuer_cert)
    _check_sans(parsed, spec)
    _check_subject(parsed, spec)
    not_before, not_after, truncated = _validity(spec, issuer_cert, validity_days, now)
    return IssuancePlan(
        subject=parsed.subject.x509_name(),
        sans=parsed.sans,
        extensions=_extensions(parsed, spec, issuer_basic),
        not_before=not_before,
        not_after=not_after,
        validity_truncated=truncated,
    )


def _authority_key_identifier(issuer_cert: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    """AKI derived from the issuer's SKI, so that both always match."""
    try:
        ski = issuer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound:
        raise ProfileViolation("the issuer certificate has no subject key identifier") from None
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski)


def _general_name(san: SanEntry) -> x509.GeneralName:
    match san.type:
        case "dns":
            return x509.DNSName(san.value)
        case "ip":
            return x509.IPAddress(ipaddress.ip_address(san.value))
        case "email":
            return x509.RFC822Name(san.value)
        case "uri":
            return x509.UniformResourceIdentifier(san.value)
        case _ as unreachable:  # pragma: no cover - exhaustive
            assert_never(unreachable)


def build_issued(
    csr: ParsedCsr,
    profile_spec: ProfileSpec,
    issuer_cert: x509.Certificate,
    issuer_key: SupportedPrivateKey,
    *,
    validity_days: int | None,
    now: datetime,
    ca_issuers_url: str | None = None,
) -> IssuedCertificate:
    """Issue a certificate for ``csr`` according to ``profile_spec``.

    Only the public key, the subject and the SANs come from the CSR. The AIA caIssuers points to
    ``ca_issuers_url`` when given and the profile includes it; no CRL distribution point nor
    OCSP URL is added before those services exist (phase 3).
    """
    plan = plan_issuance(csr, profile_spec, issuer_cert, validity_days=validity_days, now=now)
    public_key = csr.public_key
    builder = (
        x509.CertificateBuilder()
        .subject_name(plan.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(int(new_serial_hex(), 16))
        .not_valid_before(plan.not_before)
        .not_valid_after(plan.not_after)
    )
    builder = plan.extensions.apply(builder)
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
    ).add_extension(_authority_key_identifier(issuer_cert), critical=False)
    if plan.sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([_general_name(san) for san in plan.sans]),
            critical=len(plan.subject) == 0,  # RFC 5280 section 4.2.1.6
        )
    if profile_spec.ocsp_no_check:
        builder = builder.add_extension(x509.OCSPNoCheck(), critical=False)
    if ca_issuers_url is not None and profile_spec.include_aia:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(ca_issuers_url),
                    )
                ]
            ),
            critical=False,
        )

    certificate = builder.sign(issuer_key, signature_hash(issuer_key))
    certificate.verify_directly_issued_by(issuer_cert)
    return IssuedCertificate(certificate=certificate, validity_truncated=plan.validity_truncated)
