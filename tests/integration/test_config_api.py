"""GET /api/v1/config (read-only) and routing errors in problem+json."""

import pytest
from httpx import AsyncClient

from h42pki.services.settings import SettingsService


async def test_config_lists_the_effective_settings(client: AsyncClient) -> None:
    await SettingsService().set("tls_service.validity_days", 30, actor="cli")

    response = await client.get("/api/v1/config")

    assert response.status_code == 200
    items = {item["key"]: item for item in response.json()["items"]}
    assert len(items) == 16
    assert items["tls_service.validity_days"] == {
        "key": "tls_service.validity_days",
        "value": 30,
        "default": 47,
        "origin": "database",
        "level": "hot",
        "listeners": [],
        "description": items["tls_service.validity_days"]["description"],
        "updated_at": items["tls_service.validity_days"]["updated_at"],
        "updated_by": "cli",
    }
    assert items["tls_service.validity_days"]["updated_at"] is not None
    tls = items["server.tls_min_version"]
    assert (tls["value"], tls["origin"], tls["level"], tls["listeners"]) == (
        "tls1.2",
        "default",
        "listener",
        ["https"],
    )
    assert tls["updated_at"] is None


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
async def test_config_is_read_only(client: AsyncClient, method: str) -> None:
    response = await client.request(method, "/api/v1/config", json={"logging.level": "debug"})

    assert response.status_code == 405
    assert response.headers["content-type"] == "application/problem+json"
    assert response.headers["allow"] == "GET"
    problem = response.json()
    assert problem["title"] == "Method Not Allowed"
    assert "h42pki config set" in problem["detail"]
    assert (await SettingsService().effective()).logging.level == "info"


async def test_profiles_405_is_a_problem(client: AsyncClient) -> None:
    response = await client.post("/api/v1/profiles/tls_server", json={})

    assert response.status_code == 405
    assert response.headers["content-type"] == "application/problem+json"
    assert "read-only" in response.json()["detail"]


async def test_unknown_route_is_a_problem(client: AsyncClient) -> None:
    response = await client.get("/api/v1/nope")

    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "about:blank",
        "title": "Not Found",
        "status": 404,
        "detail": "the requested resource does not exist",
    }


async def test_config_is_in_the_openapi(client: AsyncClient) -> None:
    schema = (await client.get("/openapi.json")).json()

    assert "get" in schema["paths"]["/api/v1/config"]
    assert "SettingOut" in schema["components"]["schemas"]
    assert "HTTPValidationError" not in schema["components"]["schemas"]
