"""HTTP surface of the admin API: routing, validation and error format."""

import uuid

import pytest
from httpx import AsyncClient

from h42pki import __version__


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


@pytest.mark.parametrize(
    "path", ["/api/v1/certificates", f"/api/v1/certificates/{uuid.uuid4()}/self-sign"]
)
async def test_self_sign_and_certificate_creation_are_removed(
    client: AsyncClient, path: str
) -> None:  # ADR-0010
    response = await client.post(path, json={})

    assert response.status_code in (404, 405)


async def test_invalid_uuid_does_not_hit_download_route(client: AsyncClient) -> None:
    response = await client.get("/api/v1/certificates/not-a-uuid.pem")

    assert response.status_code == 422


async def test_regression_B29_validation_errors_are_problem_json(client: AsyncClient) -> None:
    submitted = "do-not-echo-this-value"
    response = await client.post(
        "/api/v1/private-keys", json={"algorithm": submitted, "unexpected": submitted}
    )

    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    body = response.json()
    assert body["type"] == "about:blank"
    assert body["title"] == "Unprocessable Content"
    assert body["status"] == 422
    assert body["detail"] == "the request is invalid (2 errors)"
    assert {(tuple(error["loc"]), error["type"]) for error in body["errors"]} == {
        (("body", "algorithm"), "enum"),
        (("body", "unexpected"), "extra_forbidden"),
    }
    for error in body["errors"]:
        assert set(error) == {"loc", "msg", "type"}
    assert submitted not in response.text


async def test_invalid_path_parameter_is_problem_json(client: AsyncClient) -> None:
    response = await client.get("/api/v1/certificates/not-a-uuid")

    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["errors"][0]["loc"] == ["path", "certificate_id"]
