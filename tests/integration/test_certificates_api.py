"""GET /api/v1/certificates (filters, pagination) and /certificates/{id}/chain.pem."""

from collections.abc import Callable
from typing import Any

import pytest
from cryptography import x509
from httpx import AsyncClient

from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.models import Certificate
from tests.conftest import IssueFactory, RootFactory
from tests.x509_helpers import csr_pem, make_csr, name

KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]


@pytest.fixture
async def populated(make_root: RootFactory, issue: IssueFactory, key_for: KeyFor) -> list[str]:
    """Root + 3 tls_server (www-0..2) + 2 tls_client (Alice, bob) certificates."""
    await make_root(public_base_url="http://pki.example.test")
    key = key_for(KeyAlgorithm.EC_P256)
    ids = []
    for index in range(3):
        host = f"www-{index}.example.test"
        request = await issue(
            "tls_server", csr_pem(make_csr(key, name(CN=host), sans=[f"dns:{host}"]))
        )
        ids.append(str(request.certificate_id))
    for user in ("Alice", "bob"):
        request = await issue("tls_client", csr_pem(make_csr(key, name(CN=user))))
        ids.append(str(request.certificate_id))
    return ids


async def _list(client: AsyncClient, **params: Any) -> dict[str, Any]:
    response = await client.get("/api/v1/certificates", params=params)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


async def test_list_everything_newest_first(client: AsyncClient, populated: list[str]) -> None:
    body = await _list(client)

    assert body["total"] == 6 and body["limit"] == 50 and body["offset"] == 0
    assert [item["id"] for item in body["items"][:5]] == list(reversed(populated))
    assert body["items"][-1]["profile"] is None  # the root, created first
    leaf = body["items"][0]
    assert leaf["issuer"] == "test-root"
    assert leaf["ca_issuers_url"] == "http://pki.example.test/ca/test-root.crt"


@pytest.mark.parametrize(
    ("params", "total"),
    [
        ({"profile": "tls_server"}, 3),
        ({"profile": "tls_client"}, 2),
        ({"profile": "sub_ca"}, 0),
        ({"channel": "cli"}, 1),
        ({"channel": "api"}, 5),
        ({"status": "valid"}, 6),
        ({"status": "revoked"}, 0),
        ({"q": "www-1"}, 1),
        ({"q": "ALICE"}, 1),  # case-insensitive
        ({"q": "example.test"}, 3),
        ({"q": "example.test", "profile": "tls_client"}, 0),
    ],
)
async def test_filters(
    client: AsyncClient, populated: list[str], params: dict[str, str], total: int
) -> None:
    body = await _list(client, **params)

    assert body["total"] == total
    assert len(body["items"]) == total


async def test_pagination(client: AsyncClient, populated: list[str]) -> None:
    pages = [await _list(client, limit=2, offset=offset) for offset in (0, 2, 4, 6)]

    assert [len(page["items"]) for page in pages] == [2, 2, 2, 0]
    assert {page["total"] for page in pages} == {6}
    seen = [item["id"] for page in pages for item in page["items"]]
    assert len(set(seen)) == 6


@pytest.mark.parametrize(
    "params",
    [{"limit": 501}, {"limit": 0}, {"offset": -1}, {"status": "pending"}, {"channel": "est"}],
)
async def test_invalid_list_parameters(client: AsyncClient, params: dict[str, Any]) -> None:
    response = await client.get("/api/v1/certificates", params=params)

    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"


async def test_limit_500_is_accepted(client: AsyncClient, populated: list[str]) -> None:
    assert (await _list(client, limit=500))["total"] == 6


async def test_chain_of_an_issued_certificate(client: AsyncClient, populated: list[str]) -> None:
    response = await client.get(f"/api/v1/certificates/{populated[0]}/chain.pem")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/x-pem-file"
    leaf, root = x509.load_pem_x509_certificates(response.content)
    leaf.verify_directly_issued_by(root)
    root.verify_directly_issued_by(root)
    stored = await Certificate.get(id=populated[0])
    assert leaf == x509.load_der_x509_certificate(stored.der)


async def test_chain_of_the_root_is_the_root(client: AsyncClient, populated: list[str]) -> None:
    root_id = (await _list(client, channel="cli"))["items"][0]["id"]

    chain = x509.load_pem_x509_certificates(
        (await client.get(f"/api/v1/certificates/{root_id}/chain.pem")).content
    )

    assert len(chain) == 1


async def test_chain_of_an_unknown_certificate(client: AsyncClient) -> None:
    response = await client.get(
        "/api/v1/certificates/00000000-0000-0000-0000-000000000000/chain.pem"
    )

    assert response.status_code == 404
