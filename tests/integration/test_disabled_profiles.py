"""Profiles disabled per CA (issuance.disabled_profiles, complement of ADR-0009)."""

import pytest
from httpx import AsyncClient

from h42pki.core.errors import InvalidSetting
from h42pki.errors import NotFound
from h42pki.models import AuditLog, CertificateRequest
from h42pki.services import ProfileService, SettingsService
from tests.conftest import RootFactory
from tests.integration.test_requests_api import KeyFor, _server_csr, _sub_ca_csr, _submit


async def _disable(*names: str) -> None:
    await SettingsService().set("issuance.disabled_profiles", list(names), actor="cli")


async def test_all_profiles_are_enabled_by_default(client: AsyncClient) -> None:
    profiles = (await client.get("/api/v1/profiles")).json()

    assert all(profile["enabled"] for profile in profiles)


async def test_enabled_field(client: AsyncClient) -> None:
    await _disable("device")

    profiles = {p["name"]: p for p in (await client.get("/api/v1/profiles")).json()}

    assert profiles["device"]["enabled"] is False
    assert profiles["tls_server"]["enabled"] is True
    assert (await client.get("/api/v1/profiles/device")).json()["enabled"] is False


async def test_submission_on_a_disabled_profile_is_refused(
    client: AsyncClient, make_root: RootFactory, key_for: KeyFor
) -> None:
    await make_root()
    await _disable("tls_server")

    response = await _submit(client, _server_csr(key_for), "tls_server")

    assert response.status_code == 422
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["detail"] == "profile 'tls_server' is disabled on this CA"
    assert await CertificateRequest.all().count() == 0
    refusal = await AuditLog.get(action="request.refuse")
    assert refusal.details["reason"] == "profile 'tls_server' is disabled on this CA"


async def test_hot_setting_is_applied_without_restart(
    client: AsyncClient, make_root: RootFactory, key_for: KeyFor
) -> None:
    """The CLI writes in the database; the very next request sees it."""
    await make_root()
    await _disable("tls_server")
    assert (await _submit(client, _server_csr(key_for), "tls_server")).status_code == 422

    await _disable()

    assert (await _submit(client, _server_csr(key_for), "tls_server")).status_code == 201


async def test_pending_request_of_a_disabled_profile_can_only_be_rejected(
    client: AsyncClient, make_root: RootFactory, key_for: KeyFor
) -> None:
    await make_root()
    pending = (await _submit(client, _sub_ca_csr(key_for), "sub_ca")).json()
    await _disable("sub_ca")

    approve = await client.post(f"/api/v1/requests/{pending['id']}/approve")

    assert approve.status_code == 409
    assert approve.headers["content-type"] == "application/problem+json"
    assert "can only be rejected" in approve.json()["detail"]
    request = await CertificateRequest.get(id=pending["id"])
    assert request.status.value == "pending"
    assert await AuditLog.filter(action="request.approve").count() == 0

    reject = await client.post(
        f"/api/v1/requests/{pending['id']}/reject", json={"reason": "profile disabled"}
    )

    assert reject.status_code == 200
    assert reject.json()["status"] == "rejected"


async def test_other_profiles_still_work(
    client: AsyncClient, make_root: RootFactory, key_for: KeyFor
) -> None:
    await make_root()
    await _disable("device", "tls_client")

    response = await _submit(client, _server_csr(key_for), "tls_server")

    assert response.status_code == 201
    assert response.json()["status"] == "issued"


@pytest.mark.usefixtures("client")
async def test_set_enabled_shortcut() -> None:
    service = ProfileService()

    disabled = await service.set_enabled("device", enabled=False, actor="cli")
    again = await service.set_enabled("device", enabled=False, actor="cli")
    enabled = await service.set_enabled("device", enabled=True, actor="cli")

    assert (disabled.previous, disabled.new, disabled.changed) == ([], ["device"], True)
    assert not again.changed
    assert (enabled.new, enabled.changed) == ([], True)
    assert await ProfileService.disabled() == set()
    assert await AuditLog.filter(action="config.set").count() == 2  # "again" wrote nothing


@pytest.mark.usefixtures("client")
async def test_set_enabled_unknown_profile() -> None:
    with pytest.raises(NotFound, match="does not exist"):
        await ProfileService().set_enabled("code_signing", enabled=False, actor="cli")


# The internal service_tls profile (ADR-0013) arrives with the built-in HTTPS server; until then
# the name is simply unknown, and once it exists it can never be disabled (test_settings_schema).
@pytest.mark.usefixtures("client")
async def test_service_tls_cannot_be_disabled_yet() -> None:
    with pytest.raises(InvalidSetting, match="service_tls"):
        await _disable("service_tls")
