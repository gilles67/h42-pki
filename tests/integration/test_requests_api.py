"""/api/v1/authority, /profiles and /requests."""

from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from asgi_lifespan import LifespanManager
from cryptography import x509
from httpx import AsyncClient

from h42pki.config import Settings
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.main import create_app
from h42pki.models import Certificate, Profile
from tests.conftest import RootFactory
from tests.integration.test_smoke_ca import download
from tests.x509_helpers import csr_pem, make_csr, name

KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]
HOST = "www.example.test"


def _server_csr(key_for: KeyFor) -> str:
    return csr_pem(make_csr(key_for(KeyAlgorithm.EC_P256), name(CN=HOST), sans=[f"dns:{HOST}"]))


def _sub_ca_csr(key_for: KeyFor) -> str:
    return csr_pem(make_csr(key_for(KeyAlgorithm.EC_P384), name(CN="Issuing CA", O="Home42")))


async def _submit(client: AsyncClient, csr: str, profile: str, **extra: Any) -> Any:
    return await client.post("/api/v1/requests", json={"csr_pem": csr, "profile": profile, **extra})


def _days(cert: x509.Certificate) -> timedelta:
    return cert.not_valid_after_utc - cert.not_valid_before_utc


# --- authority ------------------------------------------------------------------------------


async def test_authority(client: AsyncClient, make_root: RootFactory) -> None:
    authority = await make_root(KeyAlgorithm.EC_P384, path_length=1)
    record = await Certificate.get(authority=authority)

    response = await client.get("/api/v1/authority")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["name"] == "test-root"
    assert body["status"] == "active"
    assert body["certificate_id"] == str(record.id)
    assert body["subject_dn"] == "CN=h42 Test Root CA,O=Home42"
    assert body["path_length"] == 1
    assert body["key_algorithm"] == "ec_p384"
    assert datetime.fromisoformat(body["not_after"]) == record.not_after


async def test_no_authority_is_404(client: AsyncClient) -> None:
    response = await client.get("/api/v1/authority")

    assert response.status_code == 404
    assert "h42pki authority init" in response.json()["detail"]


# --- profiles -------------------------------------------------------------------------------


async def test_profiles(client: AsyncClient) -> None:
    response = await client.get("/api/v1/profiles")

    assert response.status_code == 200
    profiles = {profile["name"]: profile for profile in response.json()}
    assert set(profiles) == {
        "device",
        "ocsp_signer",
        "service_tls",
        "sub_ca",
        "tls_client",
        "tls_server",
    }
    assert profiles["service_tls"]["internal"] is True
    assert profiles["tls_server"]["internal"] is False
    tls = profiles["tls_server"]
    assert (tls["validity_days"], tls["max_validity_days"]) == (90, 200)
    assert tls["builtin"] is True and tls["auto_approve"] is True
    assert "SC-081v3" in tls["description"]


async def test_profile_by_name(client: AsyncClient) -> None:
    response = await client.get("/api/v1/profiles/sub_ca")

    assert response.status_code == 200
    assert response.json()["basic_constraints"] == {"ca": True, "path_length": 0}
    assert (await client.get("/api/v1/profiles/code_signing")).status_code == 404


async def test_profiles_are_read_only(client: AsyncClient) -> None:
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        response = await client.request(method, "/api/v1/profiles/tls_server", json={})
        assert response.status_code == 405


# --- requests -------------------------------------------------------------------------------


async def test_full_tls_server_flow(
    client: AsyncClient, make_root: RootFactory, key_for: KeyFor
) -> None:
    authority = await make_root()
    root = await download(client, (await Certificate.get(authority=authority)).id)

    response = await _submit(client, _server_csr(key_for), "tls_server")

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "issued"
    assert body["profile"] == "tls_server"
    assert body["requester"] == "anonymous" and body["decided_by"] == "auto-approve"
    assert body["validity_truncated"] is False
    assert body["subject_dn"] == f"CN={HOST}"
    leaf = await download(client, body["certificate_id"])
    leaf.verify_directly_issued_by(root)
    assert _days(leaf) == timedelta(days=90)
    assert (await client.get(f"/api/v1/requests/{body['id']}")).json() == body


@pytest.mark.parametrize(("validity_days", "status_code"), [(200, 201), (201, 422), (0, 422)])
async def test_tls_server_validity(
    client: AsyncClient,
    make_root: RootFactory,
    key_for: KeyFor,
    validity_days: int,
    status_code: int,
) -> None:
    await make_root()

    response = await _submit(
        client, _server_csr(key_for), "tls_server", validity_days=validity_days
    )

    assert response.status_code == status_code, response.text
    if status_code == 201:
        leaf = await download(client, response.json()["certificate_id"])
        assert _days(leaf) == timedelta(days=validity_days)
    else:
        assert response.headers["content-type"] == "application/problem+json"


async def test_sub_ca_approval(
    client: AsyncClient, make_root: RootFactory, key_for: KeyFor
) -> None:
    await make_root()
    response = await _submit(client, _sub_ca_csr(key_for), "sub_ca")
    assert response.status_code == 201
    pending = response.json()
    assert pending["status"] == "pending" and pending["certificate_id"] is None

    response = await client.post(f"/api/v1/requests/{pending['id']}/approve")

    assert response.status_code == 200, response.text
    issued = response.json()
    assert issued["status"] == "issued" and issued["decided_by"] == "anonymous"
    cert = await download(client, issued["certificate_id"])
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0

    again = await client.post(f"/api/v1/requests/{pending['id']}/approve")
    assert again.status_code == 409
    assert again.headers["content-type"] == "application/problem+json"


async def test_sub_ca_rejection(
    client: AsyncClient, make_root: RootFactory, key_for: KeyFor
) -> None:
    await make_root()
    pending = (await _submit(client, _sub_ca_csr(key_for), "sub_ca")).json()

    response = await client.post(
        f"/api/v1/requests/{pending['id']}/reject", json={"reason": "not planned"}
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "rejected"
    assert response.json()["rejection_reason"] == "not planned"
    assert (await client.post(f"/api/v1/requests/{pending['id']}/approve")).status_code == 409
    rejected_again = await client.post(
        f"/api/v1/requests/{pending['id']}/reject", json={"reason": "twice"}
    )
    assert rejected_again.status_code == 409


async def test_reject_needs_a_reason(
    client: AsyncClient, make_root: RootFactory, key_for: KeyFor
) -> None:
    await make_root()
    pending = (await _submit(client, _sub_ca_csr(key_for), "sub_ca")).json()

    response = await client.post(f"/api/v1/requests/{pending['id']}/reject", json={})

    assert response.status_code == 422


async def test_list_requests_by_status(
    client: AsyncClient, make_root: RootFactory, key_for: KeyFor
) -> None:
    await make_root()
    await _submit(client, _server_csr(key_for), "tls_server")
    await _submit(client, _sub_ca_csr(key_for), "sub_ca")

    everything = (await client.get("/api/v1/requests")).json()
    pending = (await client.get("/api/v1/requests", params={"status": "pending"})).json()

    assert [request["status"] for request in everything] == ["issued", "pending"]
    assert [request["profile"] for request in pending] == ["sub_ca"]
    assert (await client.get("/api/v1/requests", params={"status": "nope"})).status_code == 422


async def test_requests_without_authority_are_503(client: AsyncClient, key_for: KeyFor) -> None:
    response = await _submit(client, _server_csr(key_for), "tls_server")

    assert response.status_code == 503
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["title"] == "No Active Certificate Authority"


@pytest.mark.parametrize(
    ("csr", "profile", "fragment"),
    [
        ("not a csr", "tls_server", "cannot be parsed"),
        (None, "unknown_profile", "unknown profile"),
        (None, "ocsp_signer", "does not allow subject alternative names"),
    ],
)
async def test_invalid_requests_are_422(
    client: AsyncClient,
    make_root: RootFactory,
    key_for: KeyFor,
    csr: str | None,
    profile: str,
    fragment: str,
) -> None:
    await make_root()

    response = await _submit(client, csr or _server_csr(key_for), profile)

    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    assert fragment in response.json()["detail"]
    assert (await client.get("/api/v1/requests")).json() == []


async def test_ignored_csr_extensions_are_reported(
    client: AsyncClient, make_root: RootFactory, key_for: KeyFor
) -> None:
    await make_root()
    csr = make_csr(
        key_for(KeyAlgorithm.EC_P256),
        sans=["dns:a.example.test"],
        extensions=[(x509.BasicConstraints(ca=True, path_length=None), True)],
    )

    body = (await _submit(client, csr_pem(csr), "tls_server")).json()

    assert body["ignored_extensions"] == ["BasicConstraints (2.5.29.19)"]
    cert = await download(client, body["certificate_id"])
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False


async def test_pascal_case_request_is_rejected(client: AsyncClient) -> None:
    response = await client.post("/api/v1/requests", json={"CsrPem": "x", "Profile": "tls_server"})

    assert response.status_code == 422
    types = {error["type"] for error in response.json()["errors"]}
    assert "extra_forbidden" in types


async def test_builtin_profiles_realigned_at_restart(settings: Settings, tmp_path: Path) -> None:
    file_settings = settings.model_copy(
        update={"database_url": f"sqlite://{(tmp_path / 'h42pki.sqlite3').as_posix()}"}
    )

    async with LifespanManager(create_app(file_settings)):
        await Profile.filter(name="tls_server").update(validity_days=365, max_validity_days=398)
    async with LifespanManager(create_app(file_settings)):  # restart on the same database
        profile = await Profile.get(name="tls_server")

    assert (profile.validity_days, profile.max_validity_days) == (90, 200)
