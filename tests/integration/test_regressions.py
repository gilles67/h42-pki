"""Non-regression tests for the bugs listed in docs/etat-des-lieux.md."""

import asyncio
from collections.abc import Callable
from typing import Any

import pytest
from cryptography import x509
from httpx import AsyncClient

from h42pki.core import keys
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from tests.conftest import IssueFactory, PrivateKeyFactory, RootFactory
from tests.x509_helpers import csr_pem, make_csr, name

KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]


async def test_regression_B1_unique_serials(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    await make_root()
    key = key_for(KeyAlgorithm.EC_P256)
    csr = csr_pem(make_csr(key, name(CN="a.example.test"), sans=["dns:a.example.test"]))
    requests = [await issue("tls_server", csr) for _ in range(3)]

    bodies = [
        (await client.get(f"/api/v1/certificates/{request.certificate_id}")).json()
        for request in requests
    ]
    assert len({body["serial_hex"] for body in bodies}) == 3
    for body in bodies:
        response = await client.get(f"/api/v1/certificates/{body['id']}.crt")
        signed = x509.load_der_x509_certificate(response.content)
        assert signed.serial_number == int(body["serial_hex"], 16)


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
    client: AsyncClient, make_root: RootFactory
) -> None:
    authority = await make_root()

    response = await client.delete(f"/api/v1/private-keys/{authority.private_key_id}")

    assert response.status_code == 409
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["detail"] == "the private key is used by at least one certificate"
    assert (await client.get(f"/api/v1/private-keys/{authority.private_key_id}")).status_code == 200


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

    assert keys.generate_private_key in called
