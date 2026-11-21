"""Non-regression tests for the X.509 bugs fixed in lot 4 (docs/etat-des-lieux.md)."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import time_machine
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from httpx import AsyncClient

from h42pki.models import PrivateKey
from tests.conftest import TEST_PASSPHRASE
from tests.integration.test_smoke_ca import EXTENSIONS, SUBJECT

ROOT_CA = {
    "basic_constraints": {"ca": True},
    "key_usage": {"key_cert_sign": True, "crl_sign": True},
}


async def _self_signed(
    client: AsyncClient,
    *,
    algorithm: str = "ec_p256",
    subject: dict[str, Any] = SUBJECT,
    extensions: dict[str, Any] = EXTENSIONS,
    body: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], x509.Certificate]:
    response = await client.post("/api/v1/private-keys", json={"algorithm": algorithm})
    assert response.status_code == 201, response.text
    response = await client.post(
        "/api/v1/certificates",
        json={
            "private_key_id": response.json()["id"],
            "subject": subject,
            "extensions": extensions,
        },
    )
    assert response.status_code == 201, response.text
    cert_id = response.json()["id"]
    response = await client.post(f"/api/v1/certificates/{cert_id}/self-sign", json=body)
    assert response.status_code == 200, response.text
    der = (await client.get(f"/api/v1/certificates/{cert_id}.crt")).content
    return response.json(), x509.load_der_x509_certificate(der)


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


async def test_regression_B9_extended_key_usage_is_applied(client: AsyncClient) -> None:
    extensions = {**ROOT_CA, "extended_key_usage": ["ocsp_signing"]}

    _, cert = await _self_signed(client, extensions=extensions)

    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert not eku.critical
    assert list(eku.value) == [x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING]


async def test_regression_B10_path_length_absent_by_default(client: AsyncClient) -> None:
    _, cert = await _self_signed(client, extensions=ROOT_CA)

    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length is None


async def test_regression_B10_path_length_refused_without_ca(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/certificates",
        json={"subject": SUBJECT, "extensions": {"basic_constraints": {"path_length": 0}}},
    )

    assert response.status_code == 422


async def test_regression_B11_common_name_only(client: AsyncClient) -> None:
    signed, cert = await _self_signed(client, subject={"common_name": "Minimal Root"})

    assert signed["subject_dn"] == "CN=Minimal Root"
    assert len(cert.subject) == 1


async def test_regression_B12_aki_validity_and_hash(client: AsyncClient) -> None:
    _, cert = await _self_signed(client, algorithm="ec_p384", body={"validity_days": 730})

    ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    assert aki.key_identifier == ski.digest
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=730)
    assert isinstance(cert.signature_hash_algorithm, hashes.SHA384)


async def test_regression_B17_aware_dates_from_the_current_time(client: AsyncClient) -> None:
    frozen = datetime(2027, 3, 4, 5, 6, 7, 890000, tzinfo=UTC)

    with time_machine.travel(frozen, tick=False):
        signed, cert = await _self_signed(client)

    expected = frozen.replace(microsecond=0) - timedelta(minutes=5)
    assert cert.not_valid_before_utc == expected
    assert datetime.fromisoformat(signed["not_before"]) == expected
    assert datetime.fromisoformat(signed["not_before"]).tzinfo is not None


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


async def test_regression_B28_email_address_in_subject_dn(client: AsyncClient) -> None:
    signed, _ = await _self_signed(client)

    assert signed["subject_dn"].startswith("emailAddress=pki@example.test,CN=h42 Test Root CA")
    assert "1.2.840.113549.1.9.1" not in signed["subject_dn"]
