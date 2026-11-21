"""HTTP surface of the admin API: routing, validation and error format."""

import uuid

import pytest
from httpx import AsyncClient

from h42pki import __version__
from tests.integration.test_smoke_ca import EXTENSIONS, SUBJECT


async def test_index(client: AsyncClient) -> None:
    response = await client.get("/")

    assert response.status_code == 200
    assert response.json() == {"name": "h42-pki", "version": __version__}


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/private_key/generate"),
        ("GET", f"/private_key/{uuid.uuid4()}"),
        ("DELETE", f"/private_key/{uuid.uuid4()}"),
        ("POST", "/certificate/generate"),
        ("POST", f"/certificate/{uuid.uuid4()}/self_sign"),
        ("GET", f"/certificate/{uuid.uuid4()}"),
    ],
)
async def test_legacy_routes_are_gone(client: AsyncClient, method: str, path: str) -> None:
    response = await client.request(method, path)

    assert response.status_code == 404


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/private-keys/{id}",
        "/api/v1/certificates/{id}",
        "/api/v1/certificates/{id}.pem",
        "/api/v1/certificates/{id}.crt",
    ],
)
async def test_unknown_object_is_problem_404(client: AsyncClient, path: str) -> None:
    response = await client.get(path.format(id=uuid.uuid4()))

    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "about:blank",
        "title": "Not Found",
        "status": 404,
        "detail": "the requested resource does not exist",
    }


async def test_unknown_algorithm_is_rejected(client: AsyncClient) -> None:
    response = await client.post("/api/v1/private-keys", json={"algorithm": "rsa_2048"})

    assert response.status_code == 422


async def test_extra_field_on_private_key_is_rejected(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/private-keys", json={"algorithm": "rsa2048", "key_type": "rsa_2048"}
    )

    assert response.status_code == 422


async def test_pascal_case_certificate_payload_is_rejected(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/certificates",
        json={
            "subject": {**SUBJECT, "CommonName": "legacy"},
            "extensions": {"BasicConstraints": {"CertificateAuthority": True, "PathLength": 0}},
        },
    )

    assert response.status_code == 422
    types = {error["type"] for error in response.json()["detail"]}
    assert types == {"extra_forbidden"}


async def test_certificate_with_unknown_private_key_is_unprocessable(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/certificates",
        json={"private_key_id": str(uuid.uuid4()), "subject": SUBJECT, "extensions": EXTENSIONS},
    )

    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"


async def test_invalid_uuid_does_not_hit_download_route(client: AsyncClient) -> None:
    response = await client.get("/api/v1/certificates/not-a-uuid.pem")

    assert response.status_code == 422
