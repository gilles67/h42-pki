"""Smoke test of the key -> certificate -> self-sign -> download flow on /api/v1."""

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from httpx import AsyncClient

from h42pki.core.names import rfc4514
from tests.conftest import PrivateKeyFactory

SUBJECT = {
    "country_name": "FR",
    "state_or_province_name": "Ile-de-France",
    "locality_name": "Paris",
    "organization_name": "Home42",
    "organizational_unit_name": "PKI",
    "common_name": "h42 Test Root CA",
    "email_address": "pki@example.test",
}
EXTENSIONS = {
    "basic_constraints": {"ca": True, "path_length": 1},
    "key_usage": {"key_cert_sign": True, "crl_sign": True, "digital_signature": True},
}


async def test_self_signed_ca(client: AsyncClient) -> None:
    response = await client.post("/api/v1/private-keys", json={"algorithm": "rsa2048"})
    assert response.status_code == 201, response.text
    key = response.json()
    assert key["algorithm"] == "rsa2048"
    assert key["backend"] == "software"
    assert key["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")
    assert set(key) == {"id", "algorithm", "backend", "public_key_pem", "created_at"}

    response = await client.post(
        "/api/v1/certificates",
        json={"private_key_id": key["id"], "subject": SUBJECT, "extensions": EXTENSIONS},
    )
    assert response.status_code == 201, response.text
    pending = response.json()
    assert pending["status"] == "pending"
    assert pending["subject_dn"] is None
    cert_id = pending["id"]

    response = await client.post(f"/api/v1/certificates/{cert_id}/self-sign")
    assert response.status_code == 200, response.text
    signed = response.json()
    assert signed["status"] == "valid"
    assert signed["serial_hex"] == pending["serial_hex"]

    pem = await client.get(f"/api/v1/certificates/{cert_id}.pem")
    assert pem.status_code == 200
    assert pem.headers["content-type"] == "application/x-pem-file"
    der = await client.get(f"/api/v1/certificates/{cert_id}.crt")
    assert der.status_code == 200
    assert der.headers["content-type"] == "application/pkix-cert"

    from_pem = x509.load_pem_x509_certificate(pem.content)
    from_der = x509.load_der_x509_certificate(der.content)
    assert from_pem == from_der
    from_pem.verify_directly_issued_by(from_pem)

    assert from_der.fingerprint(hashes.SHA256()).hex() == signed["sha256_fingerprint"]
    assert from_der.serial_number == int(signed["serial_hex"], 16)
    assert rfc4514(from_der.subject) == signed["subject_dn"]
    assert from_der.not_valid_before_utc.isoformat() == signed["not_before"].replace("Z", "+00:00")
    assert from_der.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
        "h42 Test Root CA"
    )
    basic = from_der.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic.critical
    assert basic.value.ca is True
    assert basic.value.path_length == 1

    response = await client.get(f"/api/v1/certificates/{cert_id}")
    assert response.status_code == 200
    assert response.json() == signed


async def test_download_pending_certificate_conflicts(
    client: AsyncClient, make_private_key: PrivateKeyFactory
) -> None:
    key = await make_private_key()
    response = await client.post(
        "/api/v1/certificates",
        json={"private_key_id": str(key.id), "subject": SUBJECT, "extensions": EXTENSIONS},
    )
    cert_id = response.json()["id"]

    for suffix in (".pem", ".crt"):
        response = await client.get(f"/api/v1/certificates/{cert_id}{suffix}")
        assert response.status_code == 409
        assert response.headers["content-type"] == "application/problem+json"
        assert response.json()["detail"] == "the certificate is not signed yet"


async def test_self_sign_twice_conflicts(
    client: AsyncClient, make_private_key: PrivateKeyFactory
) -> None:
    key = await make_private_key()
    response = await client.post(
        "/api/v1/certificates",
        json={"private_key_id": str(key.id), "subject": SUBJECT, "extensions": EXTENSIONS},
    )
    cert_id = response.json()["id"]
    assert (await client.post(f"/api/v1/certificates/{cert_id}/self-sign")).status_code == 200

    response = await client.post(f"/api/v1/certificates/{cert_id}/self-sign")

    assert response.status_code == 409
    assert "already signed" in response.json()["detail"]


async def test_self_sign_without_private_key_is_unprocessable(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/certificates", json={"subject": SUBJECT, "extensions": EXTENSIONS}
    )
    assert response.status_code == 201, response.text
    cert_id = response.json()["id"]

    response = await client.post(f"/api/v1/certificates/{cert_id}/self-sign")

    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["detail"] == "the certificate has no private key to self-sign with"
