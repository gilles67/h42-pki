"""Smoke test of the legacy key -> certificate -> self-sign flow (guards the package move)."""

from cryptography import x509
from cryptography.x509.oid import NameOID
from httpx import AsyncClient

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
    response = await client.post("/private_key/generate", json={"key_type": "rsa_2048"})
    assert response.status_code == 200, response.text
    key = response.json()
    assert key["key_type"] == "rsa_2048"
    assert "key" not in key  # the encrypted private key is never returned

    response = await client.post(
        "/certificate/generate",
        json={"privatekey": key["uid"], "subject": SUBJECT, "extensions": EXTENSIONS},
    )
    assert response.status_code == 200, response.text
    cert_id = response.json()["uid"]

    response = await client.post(f"/certificate/{cert_id}/self_sign")
    assert response.status_code == 200, response.text

    response = await client.get(f"/certificate/{cert_id}")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pkix-cert"

    cert = x509.load_pem_x509_certificate(response.content)
    cert.verify_directly_issued_by(cert)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "h42 Test Root CA"
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic.critical
    assert basic.value.ca is True
    assert basic.value.path_length == 1
