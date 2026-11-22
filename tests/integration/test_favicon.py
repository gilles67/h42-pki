"""GET /favicon.ico: public route on both listeners, cached by ETag, hidden from the OpenAPI."""

from collections.abc import AsyncIterator
from importlib import resources
from pathlib import Path

import pytest
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient

from h42pki.api.listener import LISTENER_EXTENSION
from h42pki.config import Settings
from h42pki.main import create_app
from h42pki.server.protocol import with_extensions

PACKAGED = resources.files("h42pki").joinpath("static", "favicon.ico").read_bytes()
BRAND = Path(__file__).parents[2] / "docs" / "assets" / "brand" / "favicon.ico"


@pytest.fixture
async def listener_client(settings: Settings) -> AsyncIterator[dict[str, AsyncClient]]:
    """One client per listener, the request marked as the launcher protocol marks it."""
    app = create_app(settings)
    async with LifespanManager(app):
        clients = {
            name: AsyncClient(
                transport=ASGITransport(app=with_extensions(app, {LISTENER_EXTENSION: name})),
                base_url=f"{name}://testserver",
            )
            for name in ("http", "https")
        }
        try:
            yield clients
        finally:
            for http in clients.values():
                await http.aclose()


async def test_favicon(client: AsyncClient) -> None:
    response = await client.get("/favicon.ico")

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/x-icon"
    assert response.content == PACKAGED
    assert response.headers["cache-control"] == "public, max-age=86400"
    assert response.headers["etag"].startswith('"') and response.headers["etag"].endswith('"')
    assert "last-modified" not in response.headers


def test_packaged_favicon_is_the_brand_one() -> None:
    """The packaged copy follows docs/assets/brand (charte graphique): ICO 16, 32 and 48 px."""
    assert PACKAGED == BRAND.read_bytes()
    assert PACKAGED[:4] == b"\x00\x00\x01\x00"  # ICO header, type 1 (icon)
    count = int.from_bytes(PACKAGED[4:6], "little")
    sizes = [PACKAGED[6 + 16 * index] for index in range(count)]
    assert sizes == [16, 32, 48]


async def test_if_none_match_gives_304(client: AsyncClient) -> None:
    etag = (await client.get("/favicon.ico")).headers["etag"]

    response = await client.get("/favicon.ico", headers={"If-None-Match": etag})

    assert response.status_code == 304
    assert response.content == b""
    assert response.headers["etag"] == etag
    assert response.headers["cache-control"] == "public, max-age=86400"


async def test_other_etag_gives_the_icon(client: AsyncClient) -> None:
    response = await client.get("/favicon.ico", headers={"If-None-Match": '"other"'})

    assert response.status_code == 200
    assert response.content == PACKAGED


@pytest.mark.parametrize("listener", ["http", "https"])
async def test_served_on_both_listeners(
    listener_client: dict[str, AsyncClient], listener: str
) -> None:
    response = await listener_client[listener].get("/favicon.ico")

    assert response.status_code == 200
    assert response.content == PACKAGED


async def test_admin_api_stays_https_only(listener_client: dict[str, AsyncClient]) -> None:
    """Contrast: the route split still applies to everything else."""
    refused = await listener_client["http"].get("/api/v1/profiles")

    assert refused.status_code == 404
    assert "/favicon.ico" in refused.json()["detail"]
    assert (await listener_client["https"].get("/api/v1/profiles")).status_code == 200


async def test_not_in_the_openapi(client: AsyncClient) -> None:
    schema = (await client.get("/openapi.json")).json()

    assert "/favicon.ico" not in schema["paths"]
    assert "/ca/chain.pem" in schema["paths"]  # the other public routes still are
