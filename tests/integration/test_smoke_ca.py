"""Smoke test of the legacy key -> certificate -> self-sign flow (guards the package move)."""

from cryptography import x509
from cryptography.x509.oid import NameOID
from httpx import AsyncClient

SUBJECT = {
    "CountryName": "FR",
    "ProvinceName": "Ile-de-France",
    "LocalityName": "Paris",
    "OrganizationName": "Home42",
    "OrganizationUnitName": "PKI",
    "CommonName": "h42 Test Root CA",
    "Email": "pki@example.test",
}
EXTENSION = {
    "BasicConstraints": {"CertificateAuthority": True, "PathLength": 1},
    "KeyUsage": {"KeyCertSign": True, "CrlSign": True, "DigitalSignature": True},
}


async def test_self_signed_ca(client: AsyncClient) -> None:
    response = await client.post("/private_key/generate", json={"key_type": "rsa_2048"})
    assert response.status_code == 200, response.text
    key = response.json()
    assert key["key_type"] == "rsa_2048"
    assert "key" not in key  # the encrypted private key is never returned

    response = await client.post(
        "/certificate/generate",
        json={"privatekey": key["uid"], "subject": SUBJECT, "extension": EXTENSION},
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
