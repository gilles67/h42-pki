"""Data model integrity: foreign keys, uniqueness, audit trail, no secret in responses."""

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from tortoise.exceptions import IntegrityError

from h42pki.config import Settings
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.core.profiles import BUILTIN_PROFILES, ProfileSpec
from h42pki.db import tortoise_config
from h42pki.models import (
    AuditLog,
    Authority,
    AuthorityKind,
    Certificate,
    CertificateRequest,
    Channel,
    PrivateKey,
    Profile,
    RequestStatus,
)
from tests.conftest import IssueFactory, PrivateKeyFactory, RootFactory
from tests.x509_helpers import csr_pem, make_csr

KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]


def _certificate_values() -> dict[str, object]:
    """Columns of a stored certificate (model-level tests: the DER content does not matter)."""
    now = datetime.now(UTC)
    return {
        "der": b"\x30\x00",
        "public_key_der": b"\x30\x00",
        "sha256_fingerprint": uuid.uuid4().hex * 2,
        "subject_dn": "CN=test",
        "not_before": now,
        "not_after": now + timedelta(days=1),
    }


def test_tortoise_is_timezone_aware(settings: Settings) -> None:
    config = tortoise_config(settings)

    assert config["use_tz"] is True
    assert config["timezone"] == "UTC"
    assert config["apps"]["models"]["models"] == ["h42pki.models"]


async def test_restrict_prevents_deleting_used_private_key(
    make_private_key: PrivateKeyFactory,
) -> None:
    key = await make_private_key()
    await Certificate.create(private_key=key, **_certificate_values())

    with pytest.raises(IntegrityError):
        await key.delete()

    assert await PrivateKey.exists(id=key.id)


async def test_restrict_prevents_deleting_private_key_of_authority(
    make_private_key: PrivateKeyFactory,
) -> None:
    key = await make_private_key()
    await Authority.create(name="root", kind=AuthorityKind.LOCAL, private_key=key)

    with pytest.raises(IntegrityError):
        await key.delete()


async def test_private_key_of_authority_cannot_be_deleted_through_api(
    client: AsyncClient, make_private_key: PrivateKeyFactory
) -> None:
    key = await make_private_key()
    await Authority.create(name="root", kind=AuthorityKind.LOCAL, private_key=key)

    response = await client.delete(f"/api/v1/private-keys/{key.id}")

    assert response.status_code == 409
    assert response.json()["detail"] == "the private key is used by a certificate authority"


async def test_sha256_fingerprint_is_unique(client: AsyncClient) -> None:
    await Certificate.create(**{**_certificate_values(), "sha256_fingerprint": "ab" * 32})

    with pytest.raises(IntegrityError):
        await Certificate.create(**{**_certificate_values(), "sha256_fingerprint": "ab" * 32})


async def test_serial_is_unique_per_issuer(client: AsyncClient) -> None:
    root = await Authority.create(name="root", kind=AuthorityKind.LOCAL)
    other = await Authority.create(name="other", kind=AuthorityKind.PARENT)
    await Certificate.create(issuer=root, serial_hex="1f", **_certificate_values())
    await Certificate.create(issuer=other, serial_hex="1f", **_certificate_values())

    with pytest.raises(IntegrityError):
        await Certificate.create(issuer=root, serial_hex="1f", **_certificate_values())


async def test_audit_log_records_anonymous_actor(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    authority = await make_root()
    csr = make_csr(key_for(KeyAlgorithm.EC_P256), sans=["dns:a.example.test"])
    request = await issue("tls_server", csr_pem(csr))
    response = await client.post("/api/v1/private-keys", json={"algorithm": "ec_p256"})
    unused_key_id = response.json()["id"]
    await client.delete(f"/api/v1/private-keys/{unused_key_id}")

    entries = await AuditLog.exclude(object_type="profile").order_by("timestamp")

    assert [(entry.action, entry.object_id) for entry in entries] == [
        ("authority.init", str(authority.id)),
        ("request.submit", str(request.id)),
        ("certificate.issue", str(request.id)),
        ("private_key.generate", unused_key_id),
        ("private_key.delete", unused_key_id),
    ]
    assert {entry.actor for entry in entries} == {"anonymous"}
    for entry in entries:
        assert "PRIVATE KEY" not in str(entry.details)
        assert "encrypted_key" not in entry.details


async def test_no_response_exposes_encrypted_key(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    authority = await make_root()
    root = await Certificate.get(authority=authority)
    request = await issue(
        "tls_server", csr_pem(make_csr(key_for(KeyAlgorithm.EC_P256), sans=["dns:a.test"]))
    )
    bodies = []
    response = await client.post("/api/v1/private-keys", json={"algorithm": "rsa2048"})
    bodies.append(response.text)
    bodies.append((await client.get(f"/api/v1/private-keys/{response.json()['id']}")).text)
    bodies.append((await client.get(f"/api/v1/private-keys/{authority.private_key_id}")).text)
    for cert_id in (root.id, request.certificate_id):
        bodies.append((await client.get(f"/api/v1/certificates/{cert_id}")).text)
        bodies.append((await client.get(f"/api/v1/certificates/{cert_id}.pem")).text)
    bodies.append((await client.get("/openapi.json")).text)

    for body in bodies:
        assert "encrypted_key" not in body
        assert "PRIVATE KEY" not in body


async def test_authority_certificate_relation(client: AsyncClient) -> None:
    root = await Authority.create(name="root", kind=AuthorityKind.LOCAL)
    cert = await Certificate.create(authority=root, **_certificate_values())

    fetched = await Authority.get(id=root.id).prefetch_related("certificate")

    assert fetched.certificate.id == cert.id
    with pytest.raises(IntegrityError):
        await Certificate.create(authority=root, **_certificate_values())


async def test_builtin_profiles_are_stored_at_start_up(client: AsyncClient) -> None:
    names = [profile.name for profile in await Profile.all()]

    assert names == sorted(BUILTIN_PROFILES)
    for name in names:
        stored = await Profile.get(name=name)
        assert stored.builtin
        assert ProfileSpec.model_validate(stored.spec_values()) == BUILTIN_PROFILES[name]


async def test_certificate_request_relations(client: AsyncClient) -> None:
    profile = await Profile.get(name="tls_client")
    request = await CertificateRequest.create(
        csr_der=b"\x30\x00",
        profile=profile,
        requester="anonymous",
        channel=Channel.API,
        subject_dn="CN=alice",
    )

    fetched = await CertificateRequest.get(id=request.id).prefetch_related("profile")

    assert fetched.status is RequestStatus.PENDING
    assert fetched.profile.name == "tls_client"
    assert fetched.certificate_id is None
    with pytest.raises(IntegrityError):  # RESTRICT: a profile with requests stays
        await profile.delete()
