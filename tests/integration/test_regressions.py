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
