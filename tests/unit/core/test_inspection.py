from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from h42pki.core.csr import SanEntry
from h42pki.core.inspection import ca_issuers_url, subject_alternative_names

NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])


def _certificate(*extensions: x509.ExtensionType) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(NAME)
        .issuer_name(NAME)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2027, 1, 1, tzinfo=UTC))
    )
    for extension in extensions:
        builder = builder.add_extension(extension, critical=False)
    return builder.sign(key, hashes.SHA256())


def test_no_extensions() -> None:
    certificate = _certificate()

    assert subject_alternative_names(certificate) == []
    assert ca_issuers_url(certificate) is None


def test_supported_sans_are_read_and_others_skipped() -> None:
    certificate = _certificate(
        x509.SubjectAlternativeName(
            [
                x509.DNSName("www.example.test"),
                x509.DirectoryName(NAME),  # not issued by this project: skipped
                x509.RFC822Name("ops@example.test"),
            ]
        )
    )

    assert subject_alternative_names(certificate) == [
        SanEntry("dns", "www.example.test"),
        SanEntry("email", "ops@example.test"),
    ]


def test_ca_issuers_url_is_the_first_ca_issuers_uri() -> None:
    certificate = _certificate(
        x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.example.test"),
                ),
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier("http://pki.example.test/ca/root.crt"),
                ),
            ]
        )
    )

    assert ca_issuers_url(certificate) == "http://pki.example.test/ca/root.crt"


def test_aia_without_ca_issuers() -> None:
    certificate = _certificate(
        x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.example.test"),
                )
            ]
        )
    )

    assert ca_issuers_url(certificate) is None
