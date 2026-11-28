"""Non-regression tests for the X.509 bugs fixed in lot 4, on the lot 5a issuance path."""

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import time_machine
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from httpx import AsyncClient

from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.models import AuditLog, Authority, Certificate, PrivateKey
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


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
WEAK_CSRS = {
    "SHA1": (FIXTURES / "rsa2048-sha1.csr").read_text(encoding="ascii"),
    "MD5": (FIXTURES / "rsa2048-md5.csr").read_text(encoding="ascii"),
}


async def test_regression_B36_weak_csr_signature_refused(
    client: AsyncClient, make_root: RootFactory
) -> None:
    await make_root()

    for hash_name, csr in WEAK_CSRS.items():
        response = await client.post(
            "/api/v1/requests", json={"csr_pem": csr, "profile": "tls_client"}
        )
        assert response.status_code == 422
        assert response.json()["detail"].startswith(f"CSRs signed with {hash_name} are refused")


async def test_regression_B33_state_and_locality(
    client: AsyncClient, make_root: RootFactory, key_for: KeyFor
) -> None:
    await make_root()
    subject = name(C="FR", ST="Ile-de-France", L="Paris", O="Home42", CN="www.example.test")
    key = key_for(KeyAlgorithm.EC_P256)
    server_csr = csr_pem(make_csr(key, subject, sans=["dns:www.example.test"]))
    ocsp_csr = csr_pem(make_csr(key, name(ST="Ile-de-France", L="Paris", CN="ocsp")))

    accepted = await client.post(
        "/api/v1/requests", json={"csr_pem": server_csr, "profile": "tls_server"}
    )
    refused = await client.post(
        "/api/v1/requests", json={"csr_pem": ocsp_csr, "profile": "ocsp_signer"}
    )

    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["subject_dn"] == (
        "CN=www.example.test,O=Home42,L=Paris,ST=Ile-de-France,C=FR"
    )
    assert refused.status_code == 422
    assert "not allowed by profile ocsp_signer" in refused.json()["detail"]


async def test_regression_B35_refused_requests_are_audited(
    client: AsyncClient, make_root: RootFactory, key_for: KeyFor
) -> None:
    await make_root()
    csr = make_csr(key_for(KeyAlgorithm.EC_P256), name(CN="no-san.example.test"))
    pem = csr_pem(csr)

    refused = await client.post("/api/v1/requests", json={"csr_pem": pem, "profile": "tls_server"})
    garbage = await client.post(
        "/api/v1/requests", json={"csr_pem": "not a csr", "profile": "tls_server"}
    )

    assert refused.status_code == garbage.status_code == 422
    entries = await AuditLog.filter(action="request.refuse").order_by("timestamp")
    assert [entry.actor for entry in entries] == ["anonymous", "anonymous"]
    first, second = (entry.details for entry in entries)
    der = csr.public_bytes(serialization.Encoding.DER)
    assert first == {
        "profile": "tls_server",
        "channel": "api",
        "reason": refused.json()["detail"],
        "csr_sha256": hashlib.sha256(der).hexdigest(),
        "csr_sha256_of": "der",
        "subject_dn": "CN=no-san.example.test",
    }
    assert entries[0].object_id == first["csr_sha256"]
    assert second["csr_sha256"] == hashlib.sha256(b"not a csr").hexdigest()
    assert second["csr_sha256_of"] == "received" and second["subject_dn"] is None
    for entry in entries:
        assert "BEGIN CERTIFICATE REQUEST" not in str(entry.details)
    assert (await client.get("/api/v1/requests")).json() == []


async def test_regression_B34_effective_expired_status(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    await make_root()
    csr = make_csr(key_for(KeyAlgorithm.EC_P256), sans=["dns:www.example.test"])
    request = await issue("tls_server", csr_pem(csr))  # 47 days
    url = f"/api/v1/certificates/{request.certificate_id}"

    async def statuses() -> tuple[str, int, int]:
        detail = (await client.get(url)).json()["status"]
        expired = (await client.get("/api/v1/certificates", params={"status": "expired"})).json()
        valid = (await client.get("/api/v1/certificates", params={"status": "valid"})).json()
        return detail, expired["total"], valid["total"]

    assert await statuses() == ("valid", 0, 2)
    with time_machine.travel(datetime.now(UTC) + timedelta(days=100), tick=False):
        assert await statuses() == ("expired", 1, 1)  # the root is still valid
    stored = await Certificate.get(id=request.certificate_id)
    assert stored.status.value == "valid"  # nothing written (persistent status: phase 3)
