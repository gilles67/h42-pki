from httpx import AsyncClient


async def test_health(client: AsyncClient) -> None:
    """Without the launcher (tests): database and CA status only."""
    response = await client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert (body["status"], body["database"], body["authority"]) == ("ok", "ok", "none")
    assert (body["listeners"], body["https"], body["https_certificate"]) == ([], "unknown", None)
    assert body["warnings"] == []


async def test_index(client: AsyncClient) -> None:
    response = await client.get("/")
    assert response.status_code == 200
