"""Self-signing: reserved to root CAs, configurable validity."""

from datetime import datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient

from h42pki.models import AuditLog
from tests.conftest import PrivateKeyFactory
from tests.integration.test_smoke_ca import EXTENSIONS, SUBJECT


async def _pending_certificate(
    client: AsyncClient,
    make_private_key: PrivateKeyFactory,
    extensions: dict[str, Any] = EXTENSIONS,
) -> str:
    key = await make_private_key()
    response = await client.post(
        "/api/v1/certificates",
        json={"private_key_id": str(key.id), "subject": SUBJECT, "extensions": extensions},
    )
    assert response.status_code == 201, response.text
    cert_id: str = response.json()["id"]
    return cert_id


def _validity(body: dict[str, Any]) -> timedelta:
    return datetime.fromisoformat(body["not_after"]) - datetime.fromisoformat(body["not_before"])


@pytest.mark.parametrize("request_kwargs", [{}, {"json": {}}], ids=["no body", "empty object"])
async def test_default_validity_is_ten_years(
    client: AsyncClient, make_private_key: PrivateKeyFactory, request_kwargs: dict[str, Any]
) -> None:
    cert_id = await _pending_certificate(client, make_private_key)

    response = await client.post(f"/api/v1/certificates/{cert_id}/self-sign", **request_kwargs)

    assert response.status_code == 200, response.text
    assert _validity(response.json()) == timedelta(days=3650)


async def test_explicit_validity(client: AsyncClient, make_private_key: PrivateKeyFactory) -> None:
    cert_id = await _pending_certificate(client, make_private_key)

    response = await client.post(
        f"/api/v1/certificates/{cert_id}/self-sign", json={"validity_days": 365}
    )

    assert response.status_code == 200, response.text
    assert _validity(response.json()) == timedelta(days=365)
    entry = await AuditLog.get(action="certificate.self_sign", object_id=cert_id)
    assert entry.details["validity_days"] == 365


@pytest.mark.parametrize(
    "body",
    [
        {"validity_days": 0},
        {"validity_days": 10951},
        {"validity_days": "abc"},
        {"validity_days": 365, "days": 365},
    ],
    ids=["zero", "over 30 years", "not a number", "unknown field"],
)
async def test_invalid_self_sign_body_rejected(
    client: AsyncClient, make_private_key: PrivateKeyFactory, body: dict[str, Any]
) -> None:
    cert_id = await _pending_certificate(client, make_private_key)

    response = await client.post(f"/api/v1/certificates/{cert_id}/self-sign", json=body)

    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    # Nothing was signed.
    assert (await client.get(f"/api/v1/certificates/{cert_id}")).json()["status"] == "pending"


@pytest.mark.parametrize(
    "extensions",
    [
        {"basic_constraints": {"ca": False}, "key_usage": {"digital_signature": True}},
        {"basic_constraints": {"ca": True}, "key_usage": {"crl_sign": True}},
        {"extended_key_usage": ["server_auth"]},
    ],
    ids=["end entity", "ca without key_cert_sign", "no basic constraints"],
)
async def test_self_signing_a_non_root_ca_is_rejected(
    client: AsyncClient, make_private_key: PrivateKeyFactory, extensions: dict[str, Any]
) -> None:
    cert_id = await _pending_certificate(client, make_private_key, extensions)

    response = await client.post(f"/api/v1/certificates/{cert_id}/self-sign")

    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["title"] == "Not A Root CA"


async def test_key_usage_incompatible_with_key_is_rejected(client: AsyncClient) -> None:
    response = await client.post("/api/v1/private-keys", json={"algorithm": "ed25519"})
    key_id = response.json()["id"]
    extensions = {
        "basic_constraints": {"ca": True},
        "key_usage": {"key_cert_sign": True, "key_encipherment": True},
    }
    response = await client.post(
        "/api/v1/certificates",
        json={"private_key_id": key_id, "subject": SUBJECT, "extensions": extensions},
    )

    response = await client.post(f"/api/v1/certificates/{response.json()['id']}/self-sign")

    assert response.status_code == 422
    assert "require an RSA key" in response.json()["detail"]


async def test_openapi_documents_the_default(client: AsyncClient) -> None:
    openapi = (await client.get("/openapi.json")).json()

    schema = openapi["components"]["schemas"]["SelfSignRequest"]["properties"]["validity_days"]
    assert schema["default"] == 3650
    assert schema["minimum"] == 1
    assert schema["maximum"] == 10950
    assert schema["examples"] == [365]
    operation = openapi["paths"]["/api/v1/certificates/{certificate_id}/self-sign"]["post"]
    assert operation["requestBody"].get("required", False) is False
