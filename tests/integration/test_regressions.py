"""Non-regression tests for the bugs listed in docs/etat-des-lieux.md."""

from cryptography import x509
from httpx import AsyncClient

from tests.integration.test_smoke_ca import EXTENSION, SUBJECT


async def test_regression_B1_unique_serials(client: AsyncClient) -> None:
    response = await client.post("/private_key/generate", json={"key_type": "rsa_2048"})
    key_id = response.json()["uid"]

    certificates = []
    for _ in range(3):
        response = await client.post(
            "/certificate/generate",
            json={"privatekey": key_id, "subject": SUBJECT, "extension": EXTENSION},
        )
        assert response.status_code == 200, response.text
        certificates.append(response.json())

    serials = {cert["serial_hex"] for cert in certificates}
    assert len(serials) == 3

    for cert in certificates:
        response = await client.post(f"/certificate/{cert['uid']}/self_sign")
        assert response.status_code == 200, response.text
        response = await client.get(f"/certificate/{cert['uid']}")
        signed = x509.load_pem_x509_certificate(response.content)
        assert signed.serial_number == int(cert["serial_hex"], 16)


async def test_regression_B6_B7_delete_private_key(client: AsyncClient) -> None:
    response = await client.post("/private_key/generate", json={"key_type": "rsa_2048"})
    key_id = response.json()["uid"]

    response = await client.delete(f"/private_key/{key_id}")
    assert response.status_code == 200, response.text

    response = await client.get(f"/private_key/{key_id}")
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"


async def test_regression_B7_delete_used_private_key_conflicts(client: AsyncClient) -> None:
    response = await client.post("/private_key/generate", json={"key_type": "rsa_2048"})
    key_id = response.json()["uid"]
    await client.post(
        "/certificate/generate",
        json={"privatekey": key_id, "subject": SUBJECT, "extension": EXTENSION},
    )

    response = await client.delete(f"/private_key/{key_id}")
    assert response.status_code == 409
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["detail"] == "the private key is used by at least one certificate"

    response = await client.get(f"/private_key/{key_id}")
    assert response.status_code == 200
