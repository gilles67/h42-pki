"""Data model integrity: foreign keys, uniqueness, audit trail, no secret in responses."""

import pytest
from httpx import AsyncClient
from tortoise.exceptions import IntegrityError

from h42pki.ca.pki_models import Extensions
from h42pki.config import Settings
from h42pki.core.names import Subject
from h42pki.db import tortoise_config
from h42pki.models import (
    AuditLog,
    Authority,
    AuthorityKind,
    Certificate,
    PrivateKey,
)
from tests.conftest import PrivateKeyFactory
from tests.integration.test_smoke_ca import EXTENSIONS, SUBJECT


def _certificate_values() -> dict[str, object]:
    return {
        "subject": Subject.model_validate(SUBJECT),
        "extensions": Extensions.model_validate(EXTENSIONS),
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
    await Certificate.create(sha256_fingerprint="ab" * 32, **_certificate_values())

    with pytest.raises(IntegrityError):
        await Certificate.create(sha256_fingerprint="ab" * 32, **_certificate_values())


async def test_serial_is_unique_per_issuer(client: AsyncClient) -> None:
    root = await Authority.create(name="root", kind=AuthorityKind.LOCAL)
    other = await Authority.create(name="other", kind=AuthorityKind.PARENT)
    await Certificate.create(issuer=root, serial_hex="1f", **_certificate_values())
    await Certificate.create(issuer=other, serial_hex="1f", **_certificate_values())

    with pytest.raises(IntegrityError):
        await Certificate.create(issuer=root, serial_hex="1f", **_certificate_values())


async def test_audit_log_records_anonymous_actor(client: AsyncClient) -> None:
    response = await client.post("/api/v1/private-keys", json={"algorithm": "rsa2048"})
    key_id = response.json()["id"]
    response = await client.post(
        "/api/v1/certificates",
        json={"private_key_id": key_id, "subject": SUBJECT, "extensions": EXTENSIONS},
    )
    cert_id = response.json()["id"]
    await client.post(f"/api/v1/certificates/{cert_id}/self-sign")
    response = await client.post("/api/v1/private-keys", json={"algorithm": "rsa2048"})
    unused_key_id = response.json()["id"]
    await client.delete(f"/api/v1/private-keys/{unused_key_id}")

    entries = await AuditLog.all().order_by("timestamp")

    assert [(entry.action, entry.object_id) for entry in entries] == [
        ("private_key.generate", key_id),
        ("certificate.create", cert_id),
        ("certificate.self_sign", cert_id),
        ("private_key.generate", unused_key_id),
        ("private_key.delete", unused_key_id),
    ]
    assert {entry.actor for entry in entries} == {"anonymous"}
    for entry in entries:
        assert "PRIVATE KEY" not in str(entry.details)
        assert "encrypted_key" not in entry.details


async def test_no_response_exposes_encrypted_key(client: AsyncClient) -> None:
    bodies = []
    response = await client.post("/api/v1/private-keys", json={"algorithm": "rsa2048"})
    bodies.append(response.text)
    key_id = response.json()["id"]
    bodies.append((await client.get(f"/api/v1/private-keys/{key_id}")).text)
    response = await client.post(
        "/api/v1/certificates",
        json={"private_key_id": key_id, "subject": SUBJECT, "extensions": EXTENSIONS},
    )
    bodies.append(response.text)
    cert_id = response.json()["id"]
    bodies.append((await client.post(f"/api/v1/certificates/{cert_id}/self-sign")).text)
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


async def test_audit_of_certificate_without_key_has_null_key_id(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/certificates", json={"subject": SUBJECT, "extensions": EXTENSIONS}
    )

    entry = await AuditLog.get(object_id=response.json()["id"])

    assert entry.details["private_key_id"] is None
