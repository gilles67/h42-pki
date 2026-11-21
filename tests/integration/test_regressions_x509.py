"""Non-regression tests for the X.509 bugs fixed in lot 4, on the lot 5a issuance path."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
import time_machine
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from httpx import AsyncClient

from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.models import Authority, Certificate, PrivateKey
from tests.conftest import TEST_PASSPHRASE, IssueFactory, RootFactory
from tests.x509_helpers import csr_pem, make_csr, name

KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]


async def _root(authority: Authority) -> tuple[Certificate, x509.Certificate]:
    record = await Certificate.get(authority=authority)
    return record, x509.load_der_x509_certificate(record.der)


async def _issued(
    issue: IssueFactory, profile: str, csr: x509.CertificateSigningRequest
) -> x509.Certificate:
    request = await issue(profile, csr_pem(csr))
    record = await Certificate.get(id=request.certificate_id)
    return x509.load_der_x509_certificate(record.der)


@pytest.mark.parametrize(
    ("algorithm", "key_type"),
    [
        ("ec_p256", ec.EllipticCurvePublicKey),
        ("ec_p384", ec.EllipticCurvePublicKey),
        ("ed25519", ed25519.Ed25519PublicKey),
    ],
)
async def test_regression_B8_ec_and_ed25519_keys(
    client: AsyncClient, algorithm: str, key_type: type
) -> None:
    response = await client.post("/api/v1/private-keys", json={"algorithm": algorithm})

    assert response.status_code == 201, response.text
    public_key = serialization.load_pem_public_key(response.json()["public_key_pem"].encode())
    assert isinstance(public_key, key_type)


async def test_regression_B9_extended_key_usage_is_applied(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    await make_root()

    cert = await _issued(
        issue, "tls_client", make_csr(key_for(KeyAlgorithm.EC_P256), name(CN="alice"))
    )

    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert not eku.critical
    assert list(eku.value) == [x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]


async def test_regression_B10_path_length_absent_by_default(make_root: RootFactory) -> None:
    _, root = await _root(await make_root())

    assert root.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length is None


async def test_regression_B10_end_entity_has_no_path_length(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    await make_root(path_length=2)

    cert = await _issued(
        issue, "tls_client", make_csr(key_for(KeyAlgorithm.EC_P256), name(CN="alice"))
    )

    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is False and basic.path_length is None


async def test_regression_B11_common_name_only(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    await make_root()

    cert = await _issued(
        issue, "tls_client", make_csr(key_for(KeyAlgorithm.EC_P256), name(CN="Minimal"))
    )

    assert len(cert.subject) == 1


async def test_regression_B12_aki_validity_and_hash(make_root: RootFactory) -> None:
    _, root = await _root(await make_root(KeyAlgorithm.EC_P384, validity_days=730))

    ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    aki = root.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    assert aki.key_identifier == ski.digest
    assert root.not_valid_after_utc - root.not_valid_before_utc == timedelta(days=730)
    assert isinstance(root.signature_hash_algorithm, hashes.SHA384)


async def test_regression_B17_aware_dates_from_the_current_time(make_root: RootFactory) -> None:
    frozen = datetime(2027, 3, 4, 5, 6, 7, 890000, tzinfo=UTC)

    with time_machine.travel(frozen, tick=False):
        record, root = await _root(await make_root())

    expected = frozen.replace(microsecond=0) - timedelta(minutes=5)
    assert root.not_valid_before_utc == expected
    assert record.not_before == expected
    assert record.not_before.tzinfo is not None


async def test_regression_B18_private_key_is_encrypted_pkcs8_der(client: AsyncClient) -> None:
    response = await client.post("/api/v1/private-keys", json={"algorithm": "ec_p256"})
    stored = await PrivateKey.get(id=response.json()["id"])

    assert not stored.encrypted_key.startswith(b"-----BEGIN")
    with pytest.raises(TypeError):  # encrypted
        serialization.load_der_private_key(stored.encrypted_key, password=None)
    key = serialization.load_der_private_key(
        stored.encrypted_key, password=TEST_PASSPHRASE.encode()
    )
    assert isinstance(key, ec.EllipticCurvePrivateKey)


async def test_regression_B28_email_address_in_subject_dn(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    await make_root()
    csr = make_csr(
        key_for(KeyAlgorithm.EC_P256), name(CN="alice", emailAddress="alice@example.test")
    )

    request = await issue("tls_client", csr_pem(csr))

    body = (await client.get(f"/api/v1/certificates/{request.certificate_id}")).json()
    assert body["subject_dn"] == "emailAddress=alice@example.test,CN=alice"
    assert request.subject_dn == body["subject_dn"]
