"""core.issuance.build_issued: certificates issued by a CA from a CSR, according to a profile."""

from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
)

from h42pki.core.csr import parse_csr
from h42pki.core.errors import (
    InvalidSan,
    InvalidSubject,
    InvalidValidity,
    PathLengthExceeded,
    ProfileViolation,
)
from h42pki.core.extensions import Extensions
from h42pki.core.issuance import IssuedCertificate, build_issued, build_self_signed
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.core.names import Subject
from h42pki.core.profiles import BUILTIN_PROFILES, ProfileSpec
from h42pki.core.serial import new_serial_hex
from tests.x509_helpers import csr_pem, make_csr, name

KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]
NOW = datetime(2026, 11, 21, 12, 0, 0, tzinfo=UTC)
Root = tuple[x509.Certificate, SupportedPrivateKey]


def _root(
    key: SupportedPrivateKey, *, path_length: int | None = None, validity_days: int = 3650
) -> x509.Certificate:
    extensions = Extensions.model_validate(
        {
            "basic_constraints": {"ca": True, "path_length": path_length},
            "key_usage": {"key_cert_sign": True, "crl_sign": True, "digital_signature": True},
        }
    )
    return build_self_signed(
        Subject(common_name="Test Root CA", organization_name="Home42"),
        extensions,
        key,
        serial_hex=new_serial_hex(),
        validity_days=validity_days,
        now=NOW,
    )


@pytest.fixture
def root(key_for: KeyFor) -> Root:
    key = key_for(KeyAlgorithm.EC_P384)
    return _root(key), key


def _issue(
    root: Root,
    profile: str,
    leaf_key: SupportedPrivateKey,
    subject: x509.Name | None = None,
    *,
    sans: Sequence[str] = (),
    extensions: Sequence[tuple[x509.ExtensionType, bool]] = (),
    validity_days: int | None = None,
    ca_issuers_url: str | None = None,
    crl_url: str | None = None,
    ocsp_url: str | None = None,
    spec: ProfileSpec | None = None,
) -> IssuedCertificate:
    csr = make_csr(leaf_key, subject, sans=sans, extensions=extensions)
    issuer_cert, issuer_key = root
    return build_issued(
        parse_csr(csr_pem(csr)),
        spec or BUILTIN_PROFILES[profile],
        issuer_cert,
        issuer_key,
        validity_days=validity_days,
        now=NOW,
        ca_issuers_url=ca_issuers_url,
        crl_url=crl_url,
        ocsp_url=ocsp_url,
    )


def _ext(
    cert: x509.Certificate, kind: type[x509.ExtensionType]
) -> x509.Extension[x509.ExtensionType]:
    return cert.extensions.get_extension_for_class(kind)


# --- happy path ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "algorithm", [KeyAlgorithm.RSA2048, KeyAlgorithm.EC_P256, KeyAlgorithm.ED25519]
)
def test_tls_server_certificate(root: Root, key_for: KeyFor, algorithm: KeyAlgorithm) -> None:
    issued = _issue(
        root,
        "tls_server",
        key_for(algorithm),
        name(CN="www.example.test", O="Home42"),
        sans=["dns:www.example.test", "ip:192.0.2.10"],
    )
    cert, (issuer_cert, _) = issued.certificate, root

    cert.verify_directly_issued_by(issuer_cert)
    assert cert.issuer == issuer_cert.subject
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=90)
    assert not issued.validity_truncated
    assert isinstance(cert.signature_hash_algorithm, hashes.SHA384)  # issuer key is P-384

    basic = _ext(cert, x509.BasicConstraints)
    assert basic.critical and basic.value.ca is False and basic.value.path_length is None
    usage = _ext(cert, x509.KeyUsage)
    assert usage.critical and usage.value.digital_signature
    assert usage.value.key_encipherment is (algorithm is KeyAlgorithm.RSA2048)
    eku = _ext(cert, x509.ExtendedKeyUsage)
    assert not eku.critical and list(eku.value) == [ExtendedKeyUsageOID.SERVER_AUTH]
    san = _ext(cert, x509.SubjectAlternativeName)
    assert not san.critical
    assert san.value.get_values_for_type(x509.DNSName) == ["www.example.test"]

    issuer_ski = _ext(issuer_cert, x509.SubjectKeyIdentifier).value
    aki = _ext(cert, x509.AuthorityKeyIdentifier)
    assert not aki.critical and aki.value.key_identifier == issuer_ski.digest
    assert _ext(cert, x509.SubjectKeyIdentifier).value == x509.SubjectKeyIdentifier.from_public_key(
        cert.public_key()
    )


def test_no_cdp_nor_aia(root: Root, key_for: KeyFor) -> None:
    cert = _issue(
        root, "tls_server", key_for(KeyAlgorithm.EC_P256), sans=["dns:a.example.test"]
    ).certificate

    oids = {extension.oid for extension in cert.extensions}
    assert ExtensionOID.CRL_DISTRIBUTION_POINTS not in oids
    assert ExtensionOID.AUTHORITY_INFORMATION_ACCESS not in oids


def test_cdp_and_ocsp(root: Root, key_for: KeyFor) -> None:  # B41
    cert = _issue(
        root,
        "tls_server",
        key_for(KeyAlgorithm.EC_P256),
        sans=["dns:a.example.test"],
        ca_issuers_url="http://pki.example.test/ca/root.crt",
        crl_url="http://pki.example.test/crl/root.crl",
        ocsp_url="http://pki.example.test/ocsp",
    ).certificate

    cdp = _ext(cert, x509.CRLDistributionPoints)
    assert not cdp.critical
    assert [point.full_name for point in cdp.value] == [
        [x509.UniformResourceIdentifier("http://pki.example.test/crl/root.crl")]
    ]
    aia = _ext(cert, x509.AuthorityInformationAccess)
    assert not aia.critical
    assert [(d.access_method, d.access_location.value) for d in aia.value] == [
        (AuthorityInformationAccessOID.OCSP, "http://pki.example.test/ocsp"),
        (AuthorityInformationAccessOID.CA_ISSUERS, "http://pki.example.test/ca/root.crt"),
    ]


def test_ocsp_without_ca_issuers(root: Root, key_for: KeyFor) -> None:
    cert = _issue(
        root,
        "tls_server",
        key_for(KeyAlgorithm.EC_P256),
        sans=["dns:a.example.test"],
        ocsp_url="http://pki.example.test/ocsp",
    ).certificate

    aia = _ext(cert, x509.AuthorityInformationAccess).value
    assert [d.access_method for d in aia] == [AuthorityInformationAccessOID.OCSP]
    assert ExtensionOID.CRL_DISTRIBUTION_POINTS not in {e.oid for e in cert.extensions}


def test_cdp_on_a_sub_ca_certificate(root: Root, key_for: KeyFor) -> None:
    cert = _issue(
        root,
        "sub_ca",
        key_for(KeyAlgorithm.EC_P256),
        name(CN="Issuing CA"),
        crl_url="http://pki.example.test/crl/root.crl",
    ).certificate

    assert _ext(cert, x509.BasicConstraints).value.ca
    assert not _ext(cert, x509.CRLDistributionPoints).critical


def test_csr_extensions_are_not_copied(root: Root, key_for: KeyFor) -> None:  # B2
    cert = _issue(
        root,
        "tls_server",
        key_for(KeyAlgorithm.EC_P256),
        sans=["dns:a.example.test"],
        extensions=[
            (x509.BasicConstraints(ca=True, path_length=None), True),
            (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), False),
        ],
    ).certificate

    assert _ext(cert, x509.BasicConstraints).value.ca is False
    assert list(_ext(cert, x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.SERVER_AUTH]


def test_empty_subject_makes_san_critical(root: Root, key_for: KeyFor) -> None:
    cert = _issue(
        root, "tls_server", key_for(KeyAlgorithm.EC_P256), sans=["dns:a.example.test"]
    ).certificate

    assert len(cert.subject) == 0
    assert _ext(cert, x509.SubjectAlternativeName).critical


def test_ocsp_signer_has_ocsp_no_check(root: Root, key_for: KeyFor) -> None:
    cert = _issue(root, "ocsp_signer", key_for(KeyAlgorithm.EC_P256), name(CN="ocsp")).certificate

    assert not _ext(cert, x509.OCSPNoCheck).critical
    assert list(_ext(cert, x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.OCSP_SIGNING]


def test_other_profiles_have_no_ocsp_no_check(root: Root, key_for: KeyFor) -> None:
    cert = _issue(root, "tls_client", key_for(KeyAlgorithm.EC_P256), name(CN="alice")).certificate

    with pytest.raises(x509.ExtensionNotFound):
        _ext(cert, x509.OCSPNoCheck)


# --- subject policy --------------------------------------------------------------------------


def test_subject_attribute_not_allowed(root: Root, key_for: KeyFor) -> None:
    with pytest.raises(InvalidSubject, match="email_address not allowed by profile tls_server"):
        _issue(
            root,
            "tls_server",
            key_for(KeyAlgorithm.EC_P256),
            name(CN="a.example.test", emailAddress="a@example.test"),
            sans=["dns:a.example.test"],
        )


def test_state_and_locality_refused_for_ocsp_signer(root: Root, key_for: KeyFor) -> None:
    with pytest.raises(
        InvalidSubject, match="locality_name, state_or_province_name not allowed by profile"
    ):
        _issue(
            root, "ocsp_signer", key_for(KeyAlgorithm.EC_P256), name(ST="IDF", L="Paris", CN="o")
        )


def test_required_subject_attribute_missing(root: Root, key_for: KeyFor) -> None:
    with pytest.raises(InvalidSubject, match="common_name required"):
        _issue(root, "tls_client", key_for(KeyAlgorithm.EC_P256), name(O="Home42"))


def test_common_name_must_repeat_a_san(root: Root, key_for: KeyFor) -> None:
    with pytest.raises(InvalidSubject, match="must repeat one of the DNS or IP SANs"):
        _issue(
            root,
            "tls_server",
            key_for(KeyAlgorithm.EC_P256),
            name(CN="other.example.test"),
            sans=["dns:a.example.test"],
        )


def test_common_name_may_repeat_an_ip_san(root: Root, key_for: KeyFor) -> None:
    _issue(
        root,
        "tls_server",
        key_for(KeyAlgorithm.EC_P256),
        name(CN="192.0.2.1"),
        sans=["ip:192.0.2.1"],
    )


# --- SAN policy ------------------------------------------------------------------------------


def test_san_type_not_allowed(root: Root, key_for: KeyFor) -> None:
    with pytest.raises(InvalidSan, match="email not allowed by profile tls_server"):
        _issue(
            root,
            "tls_server",
            key_for(KeyAlgorithm.EC_P256),
            sans=["dns:a.example.test", "email:a@example.test"],
        )


def test_required_san_missing(root: Root, key_for: KeyFor) -> None:
    with pytest.raises(InvalidSan, match="requires at least one"):
        _issue(root, "tls_server", key_for(KeyAlgorithm.EC_P256), name(CN="a.example.test"))


def test_profile_without_sans(root: Root, key_for: KeyFor) -> None:
    with pytest.raises(InvalidSan, match="does not allow subject alternative names"):
        _issue(root, "ocsp_signer", key_for(KeyAlgorithm.EC_P256), name(CN="ocsp"), sans=["dns:x"])


def test_optional_sans_accepted(root: Root, key_for: KeyFor) -> None:
    cert = _issue(
        root,
        "tls_client",
        key_for(KeyAlgorithm.EC_P256),
        name(CN="alice"),
        sans=["email:alice@example.test", "uri:urn:example:alice"],
    ).certificate

    assert not _ext(cert, x509.SubjectAlternativeName).critical


# --- validity --------------------------------------------------------------------------------


def test_requested_validity_up_to_the_maximum(root: Root, key_for: KeyFor) -> None:
    cert = _issue(
        root, "tls_server", key_for(KeyAlgorithm.EC_P256), sans=["dns:a"], validity_days=200
    ).certificate

    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=200)


def test_requested_validity_over_the_maximum(root: Root, key_for: KeyFor) -> None:
    with pytest.raises(InvalidValidity, match="at most 200 days, not 201"):
        _issue(root, "tls_server", key_for(KeyAlgorithm.EC_P256), sans=["dns:a"], validity_days=201)


def test_zero_validity_rejected(root: Root, key_for: KeyFor) -> None:
    with pytest.raises(InvalidValidity):
        _issue(root, "tls_server", key_for(KeyAlgorithm.EC_P256), sans=["dns:a"], validity_days=0)


def test_validity_truncated_to_the_issuer(key_for: KeyFor) -> None:
    issuer_key = key_for(KeyAlgorithm.EC_P256)
    short_root = _root(issuer_key, validity_days=30)

    issued = _issue(
        (short_root, issuer_key), "tls_server", key_for(KeyAlgorithm.EC_P256), sans=["dns:a"]
    )

    assert issued.validity_truncated
    assert issued.certificate.not_valid_after_utc == short_root.not_valid_after_utc


# --- CA certificates and path length ---------------------------------------------------------


def test_sub_ca_under_an_unconstrained_root(root: Root, key_for: KeyFor) -> None:
    cert = _issue(root, "sub_ca", key_for(KeyAlgorithm.EC_P256), name(CN="Issuing CA")).certificate

    basic = _ext(cert, x509.BasicConstraints).value
    assert basic.ca and basic.path_length == 0
    assert _ext(cert, x509.KeyUsage).value.key_cert_sign


def test_sub_ca_under_a_path_length_zero_issuer_rejected(key_for: KeyFor) -> None:
    issuer_key = key_for(KeyAlgorithm.EC_P256)
    root = (_root(issuer_key, path_length=0), issuer_key)

    with pytest.raises(PathLengthExceeded, match="pathLen 0"):
        _issue(root, "sub_ca", key_for(KeyAlgorithm.EC_P384), name(CN="Issuing CA"))


def test_sub_ca_path_length_strictly_below_the_issuer(key_for: KeyFor) -> None:
    issuer_key = key_for(KeyAlgorithm.EC_P256)
    root = (_root(issuer_key, path_length=1), issuer_key)

    cert = _issue(root, "sub_ca", key_for(KeyAlgorithm.EC_P384), name(CN="Issuing CA")).certificate

    assert _ext(cert, x509.BasicConstraints).value.path_length == 0


def test_end_entity_under_a_path_length_zero_issuer(key_for: KeyFor) -> None:
    issuer_key = key_for(KeyAlgorithm.EC_P256)
    root = (_root(issuer_key, path_length=0), issuer_key)

    _issue(root, "tls_server", key_for(KeyAlgorithm.EC_P256), sans=["dns:a"])


# --- keys and issuer -------------------------------------------------------------------------


def test_key_algorithm_not_allowed(root: Root, key_for: KeyFor) -> None:
    with pytest.raises(ProfileViolation, match="rsa2048 not allowed by profile sub_ca"):
        _issue(root, "sub_ca", key_for(KeyAlgorithm.RSA2048), name(CN="Issuing CA"))


def test_issuer_must_be_a_ca(root: Root, key_for: KeyFor) -> None:
    leaf_key = key_for(KeyAlgorithm.EC_P256)
    leaf = _issue(root, "tls_client", leaf_key, name(CN="alice")).certificate

    with pytest.raises(ProfileViolation, match="not a CA certificate"):
        _issue((leaf, leaf_key), "tls_client", key_for(KeyAlgorithm.EC_P384), name(CN="bob"))


def test_serial_numbers_differ(root: Root, key_for: KeyFor) -> None:
    key = key_for(KeyAlgorithm.EC_P256)
    serials = {
        _issue(root, "tls_server", key, sans=["dns:a"]).certificate.serial_number for _ in range(3)
    }

    assert len(serials) == 3


# --- authority information access -----------------------------------------------------------

AIA_URL = "http://pki.example.test/ca/test-root.crt"


@pytest.mark.parametrize("profile", sorted(BUILTIN_PROFILES))
def test_aia_ca_issuers(root: Root, key_for: KeyFor, profile: str) -> None:
    sans = ["dns:a.example.test"] if profile in ("tls_server", "service_tls") else []
    algorithm = KeyAlgorithm.RSA2048 if profile == "scep_ra" else KeyAlgorithm.EC_P384
    cert = _issue(
        root, profile, key_for(algorithm), name(CN="a.example.test"), sans=sans,
        ca_issuers_url=AIA_URL,
    ).certificate  # fmt: skip

    aia = _ext(cert, x509.AuthorityInformationAccess)
    assert not aia.critical
    assert [(d.access_method, d.access_location.value) for d in aia.value] == [
        (x509.oid.AuthorityInformationAccessOID.CA_ISSUERS, AIA_URL)
    ]


def test_no_aia_without_url(root: Root, key_for: KeyFor) -> None:
    cert = _issue(root, "tls_server", key_for(KeyAlgorithm.EC_P256), sans=["dns:a"]).certificate

    with pytest.raises(x509.ExtensionNotFound):
        _ext(cert, x509.AuthorityInformationAccess)


def test_no_aia_when_the_profile_excludes_it(root: Root, key_for: KeyFor) -> None:
    spec = BUILTIN_PROFILES["tls_server"].model_copy(update={"include_aia": False})

    cert = _issue(
        root, "tls_server", key_for(KeyAlgorithm.EC_P256), sans=["dns:a"],
        ca_issuers_url=AIA_URL, spec=spec,
    ).certificate  # fmt: skip

    with pytest.raises(x509.ExtensionNotFound):
        _ext(cert, x509.AuthorityInformationAccess)


def test_root_certificate_never_has_aia(root: Root) -> None:
    issuer_cert, _ = root

    with pytest.raises(x509.ExtensionNotFound):
        _ext(issuer_cert, x509.AuthorityInformationAccess)
