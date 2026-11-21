"""Non-regression tests for the bugs listed in docs/etat-des-lieux.md."""

import asyncio
from collections.abc import Callable
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import AsyncClient

from tests.conftest import PrivateKeyFactory
from tests.integration.test_smoke_ca import EXTENSIONS, SUBJECT


async def _create_certificate(client: AsyncClient, private_key_id: str) -> dict[str, Any]:
    response = await client.post(
        "/api/v1/certificates",
        json={"private_key_id": private_key_id, "subject": SUBJECT, "extensions": EXTENSIONS},
    )
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


async def test_regression_B1_unique_serials(
    client: AsyncClient, make_private_key: PrivateKeyFactory
) -> None:
    key = await make_private_key()
    certificates = [await _create_certificate(client, str(key.id)) for _ in range(3)]

    assert len({cert["serial_hex"] for cert in certificates}) == 3

    for cert in certificates:
        response = await client.post(f"/api/v1/certificates/{cert['id']}/self-sign")
        assert response.status_code == 200, response.text
        response = await client.get(f"/api/v1/certificates/{cert['id']}.crt")
        signed = x509.load_der_x509_certificate(response.content)
        assert signed.serial_number == int(cert["serial_hex"], 16)


async def test_regression_B6_B7_delete_private_key(
    client: AsyncClient, make_private_key: PrivateKeyFactory
) -> None:
    key = await make_private_key()

    response = await client.delete(f"/api/v1/private-keys/{key.id}")
    assert response.status_code == 204, response.text
    assert response.content == b""

    response = await client.get(f"/api/v1/private-keys/{key.id}")
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"

    response = await client.delete(f"/api/v1/private-keys/{key.id}")
    assert response.status_code == 404


async def test_regression_B7_delete_used_private_key_conflicts(
    client: AsyncClient, make_private_key: PrivateKeyFactory
) -> None:
    key = await make_private_key()
    await _create_certificate(client, str(key.id))

    response = await client.delete(f"/api/v1/private-keys/{key.id}")

    assert response.status_code == 409
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["detail"] == "the private key is used by at least one certificate"
    assert (await client.get(f"/api/v1/private-keys/{key.id}")).status_code == 200


async def test_crypto_operations_run_in_worker_threads(
    client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    called: list[Callable[..., Any]] = []
    real_to_thread = asyncio.to_thread

    async def spy(func: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
        called.append(func)
        return await real_to_thread(func, *args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", spy)

    response = await client.post("/api/v1/private-keys", json={"algorithm": "rsa2048"})
    assert response.status_code == 201, response.text

    assert rsa.generate_private_key in called
