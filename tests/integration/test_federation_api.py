"""Federation, parent side, through the API: invitations, enrolment, child CAs (ADR-0015)."""

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
import time_machine
from asgi_lifespan import LifespanManager
from cryptography import x509
from httpx import ASGITransport, AsyncClient, Response

from h42pki.api.listener import LISTENER_EXTENSION
from h42pki.config import Settings
from h42pki.core.federation import hash_secret, new_token
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.keystore import KeyStore
from h42pki.main import create_app
from h42pki.models import (
    AuditLog,
    Authority,
    AuthorityKind,
    AuthorityStatus,
    Certificate,
    CertificateRequest,
    FederationInvitation,
)
from h42pki.server.protocol import with_extensions
from h42pki.services import SettingsService
from h42pki.services.authority import AuthorityService
from h42pki.services.issuance import IssuanceService
from tests.conftest import RootFactory
from tests.x509_helpers import csr_pem, make_csr, name

API = "/api/v1/federation"
KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]
Invite = Callable[..., Awaitable[dict[str, Any]]]


@pytest.fixture
def ca_csr(key_for: KeyFor) -> str:
    return csr_pem(make_csr(key_for(KeyAlgorithm.EC_P384), name(CN="Child CA", O="Home42")))


@pytest.fixture
def invite(client: AsyncClient) -> Invite:
    async def make(**body: Any) -> dict[str, Any]:
        response = await client.post(f"{API}/invitations", json=body)
        assert response.status_code == 201, response.text
        created: dict[str, Any] = response.json()
        return created

    return make


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def enroll(
    client: AsyncClient, token: str, csr: str, ca_name: str = "child", **extra: Any
) -> Response:
    return await client.post(
        f"{API}/enroll", json={"csr_pem": csr, "name": ca_name, **extra}, headers=bearer(token)
    )


async def status(client: AsyncClient, token: str, enrollment_id: str) -> Response:
    return await client.get(f"{API}/enroll/{enrollment_id}", headers=bearer(token))


def path_length(pem: str) -> int | None:
    cert = x509.load_pem_x509_certificate(pem.encode())
    return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length


# --- invitations ---------------------------------------------------------------------------


async def test_invitation_defaults_and_token_shown_once(
    client: AsyncClient, make_root: RootFactory, invite: Invite, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    root = await make_root()
    response = await client.post(f"{API}/invitations", json={"label": "issuing"})
    created = response.json()

    token = created["token"]
    secret = token.partition(".")[2]
    assert response.headers["cache-control"] == "no-store"
    invitation = created["invitation"]
    assert invitation["auto_approve"] is False
    assert invitation["status"] == "active"
    assert created["parent_url"] is None  # no hostname in the tests
    assert created["effective_path_length"] is None
    certificate = await Certificate.get(authority=root)
    assert created["parent_fingerprint"] == certificate.sha256_fingerprint
    left = datetime.fromisoformat(created["expires_at"]) - datetime.now(UTC)
    assert timedelta(days=6, hours=23) < left <= timedelta(days=7)

    listed = await client.get(f"{API}/invitations")
    detail = await client.get(f"{API}/invitations/{invitation['id']}")
    assert listed.json() == [invitation] and detail.json() == invitation
    audit = [str(entry.details) for entry in await AuditLog.all()]
    stored = await FederationInvitation.get(id=invitation["id"])
    for text in (listed.text, detail.text, caplog.text, stored.secret_hash, *audit):
        assert secret not in text
    entry = await AuditLog.get(action="federation.invite")
    assert entry.object_id == invitation["id"] and entry.details["label"] == "issuing"


async def test_suggested_parent_url(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    assert settings.https_url is None
    monkeypatch.setattr(settings, "server_hostname", "root.pki.test")
    assert settings.https_url == "https://root.pki.test:8443"


async def test_invitation_needs_a_ca(client: AsyncClient) -> None:
    assert (await client.post(f"{API}/invitations", json={})).status_code == 503


@pytest.mark.parametrize(
    "body",
    [
        {"expires_in_hours": 0},
        {"expires_in_hours": 721},
        {"path_length": -1},
        {"validity_days": 3651},
        {"validity_days": 0},
        {"token": "x"},
    ],
)
async def test_invalid_invitations(
    client: AsyncClient, make_root: RootFactory, body: dict[str, Any]
) -> None:
    await make_root()
    assert (await client.post(f"{API}/invitations", json=body)).status_code == 422
    assert await FederationInvitation.all().count() == 0


async def test_expired_invitation(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    await make_root()
    created = await invite(expires_in_hours=2, auto_approve=True)
    later = datetime.now(UTC) + timedelta(hours=2, seconds=1)

    with time_machine.travel(later, tick=False):
        detail = await client.get(f"{API}/invitations/{created['invitation']['id']}")
        response = await enroll(client, created["token"], ca_csr)

    assert detail.json()["status"] == "expired"
    assert response.status_code == 401
    assert (await FederationInvitation.get(id=created["invitation"]["id"])).status == "active"


async def test_revoke_invitation(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    await make_root()
    created = await invite(auto_approve=True)
    url = f"{API}/invitations/{created['invitation']['id']}"

    response = await client.delete(url)

    assert response.status_code == 200 and response.json()["status"] == "revoked"
    assert (await enroll(client, created["token"], ca_csr)).status_code == 401
    assert (await client.delete(url)).status_code == 409
    assert await AuditLog.filter(action="federation.invitation_revoke").count() == 1
    assert (await client.delete(f"{API}/invitations/{uuid4()}")).status_code == 404


async def test_used_invitation_cannot_be_revoked(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    await make_root()
    created = await invite()
    await enroll(client, created["token"], ca_csr)

    response = await client.delete(f"{API}/invitations/{created['invitation']['id']}")

    assert response.status_code == 409
    assert response.json()["detail"] == "the invitation is already used"


# --- enrolment -----------------------------------------------------------------------------


async def test_auto_approved_enrolment(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    root = await make_root(path_length=2)
    created = await invite(auto_approve=True)

    response = await enroll(
        client, created["token"], ca_csr, "issuing", public_base_url="http://Issuing.test/"
    )

    assert response.status_code == 201, response.text
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["status"] == "issued"
    cert = x509.load_pem_x509_certificate(body["certificate_pem"].encode())
    chain = x509.load_pem_x509_certificates(body["chain_pem"].encode())
    cert.verify_directly_issued_by(chain[0])
    assert len(chain) == 1
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert basic.critical and basic.value.ca and basic.value.path_length == 1

    child = await Authority.get(name="issuing").prefetch_related("certificate")
    assert (child.kind, child.status) == (AuthorityKind.CHILD, AuthorityStatus.ACTIVE)
    assert child.parent_id == root.id and child.path_length == 1
    assert child.public_base_url == "http://issuing.test"
    assert child.certificate.serial_hex == format(cert.serial_number, "x")
    request = (await client.get(f"/api/v1/requests/{body['enrollment_id']}")).json()
    assert request["channel"] == "federation" and request["profile"] == "sub_ca"
    assert request["invitation_id"] == created["invitation"]["id"]
    assert request["child_name"] == "issuing"
    assert request["requester"] == f"invitation:{created['invitation']['id']}"
    used = (await client.get(f"{API}/invitations/{created['invitation']['id']}")).json()
    assert used["status"] == "used" and used["request_id"] == body["enrollment_id"]
    actions = [entry.action for entry in await AuditLog.all()]
    for action in ("federation.enroll", "request.submit", "certificate.issue"):
        assert action in actions


async def test_manual_approval(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    await make_root()
    token = (await invite())["token"]

    pending = await enroll(client, token, ca_csr)

    assert pending.status_code == 202 and pending.json()["status"] == "pending"
    assert int(pending.headers["retry-after"]) > 0
    enrollment_id = pending.json()["enrollment_id"]
    polled = await status(client, token, enrollment_id)
    assert polled.status_code == 200 and polled.json()["status"] == "pending"
    assert "retry-after" in polled.headers
    assert not await Authority.exists(kind=AuthorityKind.CHILD)

    approved = await client.post(f"/api/v1/requests/{enrollment_id}/approve")
    assert approved.status_code == 200, approved.text

    issued = await status(client, token, enrollment_id)
    assert issued.json()["status"] == "issued" and issued.json()["certificate_pem"]
    assert "retry-after" not in issued.headers
    assert await Authority.exists(kind=AuthorityKind.CHILD, name="child")


async def test_rejection(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    await make_root()
    token = (await invite())["token"]
    enrollment_id = (await enroll(client, token, ca_csr)).json()["enrollment_id"]

    await client.post(f"/api/v1/requests/{enrollment_id}/reject", json={"reason": "not planned"})

    body = (await status(client, token, enrollment_id)).json()
    assert (body["status"], body["reason"]) == ("rejected", "not planned")
    assert body["certificate_pem"] is None
    replay = await enroll(client, token, ca_csr)
    assert replay.status_code == 200 and replay.json()["status"] == "rejected"


async def test_same_enrolment_is_idempotent(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    await make_root()
    token = (await invite(auto_approve=True))["token"]

    first = await enroll(client, token, ca_csr, public_base_url="http://child.test")
    second = await enroll(client, token, ca_csr, public_base_url="http://child.test/")

    assert first.status_code == second.status_code == 201
    assert first.json() == second.json()
    assert await CertificateRequest.all().count() == 1


async def test_token_outlives_the_invitation_then_24_hours_after_the_decision(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    await make_root()
    token = (await invite(expires_in_hours=1))["token"]
    enrollment_id = (await enroll(client, token, ca_csr)).json()["enrollment_id"]
    decision = datetime.now(UTC) + timedelta(days=3)

    with time_machine.travel(decision, tick=False):
        assert (await status(client, token, enrollment_id)).status_code == 200  # still pending
        await client.post(f"/api/v1/requests/{enrollment_id}/approve")
    with time_machine.travel(decision + timedelta(hours=23, minutes=59), tick=False):
        assert (await status(client, token, enrollment_id)).json()["status"] == "issued"
    with time_machine.travel(decision + timedelta(hours=24), tick=False):
        assert (await status(client, token, enrollment_id)).status_code == 401
        assert (await enroll(client, token, ca_csr)).status_code == 401


async def test_every_refused_token_gets_the_same_answer(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str, key_for: KeyFor
) -> None:
    await make_root()
    url = f"{API}/enroll"
    body = {"csr_pem": ca_csr, "name": "child"}
    other_csr = csr_pem(make_csr(key_for(KeyAlgorithm.EC_P384), name(CN="Another CA")))
    used, revoked, short, unused = [await invite() for _ in range(4)]
    enrolled = (await enroll(client, used["token"], ca_csr, "used")).json()["enrollment_id"]
    other = await enroll(client, unused["token"], other_csr, "other")
    await client.delete(f"{API}/invitations/{revoked['invitation']['id']}")
    await FederationInvitation.filter(id=short["invitation"]["id"]).update(
        expires_at=datetime.now(UTC) - timedelta(seconds=1)
    )
    wrong_secret = short["token"].partition(".")[0] + "." + used["token"].partition(".")[2]

    answers = [
        await client.post(url, json=body),
        await client.post(url, json=body, headers={"Authorization": "Basic YTpi"}),
        await enroll(client, "", ca_csr),
        await enroll(client, "garbage", ca_csr),
        await enroll(client, new_token(uuid4()).reveal(), ca_csr),  # unknown invitation
        await enroll(client, wrong_secret, ca_csr),
        await enroll(client, revoked["token"], ca_csr),
        await enroll(client, short["token"], ca_csr),  # expired
        await enroll(client, used["token"], other_csr, "used"),  # another CSR
        await enroll(client, used["token"], ca_csr, "renamed"),
        await enroll(client, used["token"], ca_csr, "used", public_base_url="ftp://x"),
        await enroll(client, used["token"], "garbage", "used"),
        await status(client, used["token"], other.json()["enrollment_id"]),
        await status(client, used["token"], str(uuid4())),
        await client.get(f"{url}/{enrolled}"),
    ]

    assert {answer.status_code for answer in answers} == {401}
    assert len({answer.content for answer in answers}) == 1
    for answer in answers:
        assert answer.headers["www-authenticate"] == "Bearer"
        assert answer.headers["content-type"] == "application/problem+json"
    assert await CertificateRequest.all().count() == 2


async def test_concurrent_use_of_one_token(
    client: AsyncClient, make_root: RootFactory, invite: Invite, key_for: KeyFor
) -> None:
    await make_root()
    token = (await invite(auto_approve=True))["token"]
    key = key_for(KeyAlgorithm.EC_P384)

    answers = await asyncio.gather(
        *(
            enroll(client, token, csr_pem(make_csr(key, name(CN=f"CA {i}"))), f"ca-{i}")
            for i in range(4)
        )
    )

    assert sorted(answer.status_code for answer in answers) == [201, 401, 401, 401]
    assert await CertificateRequest.all().count() == 1
    assert await Authority.filter(kind=AuthorityKind.CHILD).count() == 1


# --- constraints ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("parent", "invited", "expected"),
    [(None, None, None), (None, 3, 3), (2, None, 1), (2, 5, 1), (2, 0, 0), (1, None, 0)],
)
async def test_path_length(
    client: AsyncClient,
    make_root: RootFactory,
    invite: Invite,
    ca_csr: str,
    parent: int | None,
    invited: int | None,
    expected: int | None,
) -> None:
    await make_root(path_length=parent)
    created = await invite(auto_approve=True, path_length=invited)

    body = (await enroll(client, created["token"], ca_csr)).json()

    assert created["effective_path_length"] == expected
    assert path_length(body["certificate_pem"]) == expected


async def test_path_length_is_kept_by_manual_approval(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    await make_root(path_length=4)
    token = (await invite(path_length=2, validity_days=30))["token"]
    enrollment_id = (await enroll(client, token, ca_csr)).json()["enrollment_id"]

    await client.post(f"/api/v1/requests/{enrollment_id}/approve")

    pem = (await status(client, token, enrollment_id)).json()["certificate_pem"]
    cert = x509.load_pem_x509_certificate(pem.encode())
    assert path_length(pem) == 2
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=30)


async def test_plain_request_keeps_the_profile_path_length(
    client: AsyncClient, make_root: RootFactory, ca_csr: str
) -> None:
    await make_root()
    pending = await client.post("/api/v1/requests", json={"csr_pem": ca_csr, "profile": "sub_ca"})
    issued = await client.post(f"/api/v1/requests/{pending.json()['id']}/approve")
    pem = await client.get(f"/api/v1/certificates/{issued.json()['certificate_id']}.pem")

    assert path_length(pem.text) == 0
    assert issued.json()["invitation_id"] is None
    assert not await Authority.exists(kind=AuthorityKind.CHILD)


async def test_parent_with_path_length_zero_refuses(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    await make_root(path_length=0)

    response = await client.post(f"{API}/invitations", json={})

    assert response.status_code == 422 and "pathLen 0" in response.json()["detail"]
    # Even with an invitation already there, the enrolment itself is refused.
    token = new_token(uuid4())
    await FederationInvitation.create(
        id=token.invitation_id,
        secret_hash=hash_secret(token.secret),
        auto_approve=True,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        created_by="test",
    )
    assert (await enroll(client, token.reveal(), ca_csr)).status_code == 422


async def test_validity_is_cut_to_the_parent(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    root = await make_root(validity_days=100)
    token = (await invite(auto_approve=True, validity_days=365))["token"]

    body = (await enroll(client, token, ca_csr)).json()

    cert = x509.load_pem_x509_certificate(body["certificate_pem"].encode())
    assert cert.not_valid_after_utc == (await Certificate.get(authority=root)).not_after


async def test_disabled_profile_blocks_federation(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    await make_root()
    token = (await invite(auto_approve=True))["token"]
    await SettingsService().set("issuance.disabled_profiles", ["sub_ca"], actor="cli")

    refused = await enroll(client, token, ca_csr)

    assert refused.status_code == 422 and "disabled" in refused.json()["detail"]
    await SettingsService().unset("issuance.disabled_profiles", actor="cli")
    assert (await enroll(client, token, ca_csr)).status_code == 201  # nothing was consumed


@pytest.mark.parametrize(
    ("ca_name", "code"), [("chain", 422), ("Home 42", 422), ("a/b", 422), ("test-root", 409)]
)
async def test_regression_B37_enrolment_names(
    client: AsyncClient,
    make_root: RootFactory,
    invite: Invite,
    ca_csr: str,
    ca_name: str,
    code: int,
) -> None:
    await make_root()
    token = (await invite(auto_approve=True))["token"]

    assert (await enroll(client, token, ca_csr, ca_name)).status_code == code
    assert (await enroll(client, token, ca_csr, "fine")).status_code == 201  # not consumed


async def test_name_of_a_pending_enrolment_is_taken(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    await make_root()
    await enroll(client, (await invite())["token"], ca_csr, "twin")

    response = await enroll(client, (await invite())["token"], ca_csr, "twin")

    assert response.status_code == 409 and "already pending" in response.json()["detail"]


async def test_name_taken_before_the_approval(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    await make_root()
    token = (await invite())["token"]
    enrollment_id = (await enroll(client, token, ca_csr, "taken")).json()["enrollment_id"]
    await Authority.create(name="taken", kind=AuthorityKind.CHILD)

    approve = await client.post(f"/api/v1/requests/{enrollment_id}/approve")

    assert approve.status_code == 409
    assert (await status(client, token, enrollment_id)).json()["status"] == "pending"
    reject = await client.post(f"/api/v1/requests/{enrollment_id}/reject", json={"reason": "name"})
    assert reject.status_code == 200


async def test_refused_csr_is_audited_and_consumes_nothing(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    await make_root()
    token = (await invite(auto_approve=True))["token"]

    assert (await enroll(client, token, "garbage")).status_code == 422

    entry = await AuditLog.get(action="request.refuse")
    assert entry.details["channel"] == "federation"
    assert token.partition(".")[2] not in str(entry.details)
    assert (await enroll(client, token, ca_csr)).status_code == 201


async def test_failed_issuance_is_reported(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    await make_root(validity_days=10)
    token = (await invite())["token"]
    enrollment_id = (await enroll(client, token, ca_csr)).json()["enrollment_id"]

    with time_machine.travel(datetime.now(UTC) + timedelta(days=11), tick=False):
        assert (await client.post(f"/api/v1/requests/{enrollment_id}/approve")).status_code == 503
        body = (await status(client, token, enrollment_id)).json()

    assert body["status"] == "failed" and "expired" in body["reason"]


# --- child CAs -----------------------------------------------------------------------------


async def test_children_and_revocation(
    client: AsyncClient, make_root: RootFactory, invite: Invite, ca_csr: str
) -> None:
    await make_root()
    body = (await enroll(client, (await invite(auto_approve=True))["token"], ca_csr)).json()
    [child] = (await client.get(f"{API}/children")).json()
    assert (child["name"], child["status"], child["revoked_at"]) == ("child", "active", None)

    response = await client.post(f"{API}/children/child/revoke", json={"reason": "ca_compromise"})

    assert response.status_code == 200, response.text
    revoked = response.json()
    assert (revoked["status"], revoked["revocation_reason"]) == ("revoked", "ca_compromise")
    assert revoked["revoked_at"] is not None
    certificate = (await client.get(f"/api/v1/certificates/{child['certificate_id']}")).json()
    assert certificate["status"] == "revoked"
    entry = await AuditLog.get(action="federation.child_revoke")
    assert entry.details["reason"] == "ca_compromise"
    again = await client.post(f"{API}/children/child/revoke", json={"reason": "superseded"})
    assert again.status_code == 409
    # The name stays taken: a revoked CA keeps its record.
    other = await enroll(client, (await invite(auto_approve=True))["token"], ca_csr)
    assert other.status_code == 409
    assert body["enrollment_id"]


@pytest.mark.parametrize("reason", ["certificate_hold", "remove_from_crl", "keyCompromise", ""])
async def test_unsupported_revocation_reasons(
    client: AsyncClient, make_root: RootFactory, reason: str
) -> None:
    await make_root()
    response = await client.post(f"{API}/children/child/revoke", json={"reason": reason})
    assert response.status_code == 422


async def test_only_child_cas_can_be_revoked(client: AsyncClient, make_root: RootFactory) -> None:
    await make_root()
    for ca_name in ("test-root", "nobody", "a" * 65):
        response = await client.post(
            f"{API}/children/{ca_name}/revoke", json={"reason": "unspecified"}
        )
        assert response.status_code in (404, 422)
    assert (await Authority.get(name="test-root")).status is AuthorityStatus.ACTIVE


# --- surface -------------------------------------------------------------------------------


@pytest.fixture
async def http_client(settings: Settings) -> AsyncIterator[AsyncClient]:
    app = create_app(settings)
    async with (
        LifespanManager(app),
        AsyncClient(
            transport=ASGITransport(app=with_extensions(app, {LISTENER_EXTENSION: "http"})),
            base_url="http://testserver",
        ) as http,
    ):
        yield http


async def test_federation_is_https_only(http_client: AsyncClient) -> None:
    for method, path in (
        ("POST", "/invitations"),
        ("GET", "/invitations"),
        ("POST", "/enroll"),
        ("GET", f"/enroll/{uuid4()}"),
        ("GET", "/children"),
        ("POST", "/children/x/revoke"),
    ):
        response = await http_client.request(method, API + path, json={})
        assert response.status_code == 404
        assert "only served over HTTPS" in response.json()["detail"]


async def test_openapi(client: AsyncClient) -> None:
    schema = (await client.get("/openapi.json")).json()

    assert "401" in schema["paths"][f"{API}/enroll"]["post"]["responses"]
    assert "HTTPValidationError" not in schema["components"]["schemas"]


async def test_lookup_of_the_service_without_keystore(
    client: AsyncClient, make_root: RootFactory, keystore: KeyStore
) -> None:
    """Reads and rejections need no passphrase (B32)."""
    await make_root()
    assert await IssuanceService().list() == []
    assert await AuthorityService().find_local() is not None
