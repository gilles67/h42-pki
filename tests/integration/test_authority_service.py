"""AuthorityService.init_root and ProfileService.sync_builtin."""

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from httpx import AsyncClient

from h42pki.core.errors import InvalidValidity
from h42pki.core.keys import KeyAlgorithm, public_key_algorithm
from h42pki.core.profiles import BUILTIN_PROFILES
from h42pki.errors import Conflict, NoActiveAuthority
from h42pki.keystore import KeyStore
from h42pki.models import (
    AuditLog,
    Authority,
    AuthorityKind,
    AuthorityStatus,
    Certificate,
    Channel,
    PrivateKey,
    Profile,
)
from h42pki.services import AuthorityService, ProfileService
from tests.conftest import RootFactory


async def _root_certificate(authority: Authority) -> tuple[Certificate, x509.Certificate]:
    record = await Certificate.get(authority=authority)
    assert record.der is not None
    return record, x509.load_der_x509_certificate(record.der)


@pytest.mark.parametrize(
    "algorithm", [KeyAlgorithm.RSA2048, KeyAlgorithm.EC_P384, KeyAlgorithm.ED25519]
)
async def test_init_root(make_root: RootFactory, algorithm: KeyAlgorithm) -> None:
    authority = await make_root(algorithm)

    assert authority.kind is AuthorityKind.LOCAL
    assert authority.status is AuthorityStatus.ACTIVE
    assert authority.path_length is None
    record, cert = await _root_certificate(authority)
    cert.verify_directly_issued_by(cert)
    assert record.channel is Channel.CLI
    assert record.issuer_id is None and record.profile_id is None
    assert record.private_key_id == authority.private_key_id
    assert public_key_algorithm(cert.public_key()) is algorithm
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=3650)
    assert record.sha256_fingerprint == cert.fingerprint(hashes.SHA256()).hex()

    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca and basic.path_length is None
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.key_cert_sign and usage.crl_sign and usage.digital_signature

    entry = await AuditLog.get(action="authority.init")
    assert entry.actor == "anonymous"
    assert entry.details["validity_days"] == 3650
    assert entry.details["key_algorithm"] == algorithm.value


async def test_init_root_options(make_root: RootFactory) -> None:
    authority = await make_root(
        validity_days=365, path_length=1, public_base_url="http://pki.example.test"
    )

    _, cert = await _root_certificate(authority)
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=365)
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 1
    assert authority.public_base_url == "http://pki.example.test"
    assert (await AuditLog.get(action="authority.init")).details["validity_days"] == 365


@pytest.mark.parametrize("validity_days", [0, 10951])
async def test_init_root_validity_bounds(make_root: RootFactory, validity_days: int) -> None:
    with pytest.raises(InvalidValidity):
        await make_root(validity_days=validity_days)

    assert await PrivateKey.all().count() == 0  # refused before generating anything
    assert await Authority.all().count() == 0


async def test_second_init_conflicts(make_root: RootFactory) -> None:
    await make_root()

    with pytest.raises(Conflict, match="already exists"):
        await make_root(name="another-root")


async def test_regression_B31_each_root_gets_its_own_key(
    make_root: RootFactory, client: AsyncClient
) -> None:
    first = await make_root(name="first-root")
    await Authority.filter(id=first.id).update(status=AuthorityStatus.RETIRED)
    second = await make_root(name="second-root")

    assert first.private_key_id != second.private_key_id
    _, first_cert = await _root_certificate(first)
    _, second_cert = await _root_certificate(second)
    assert first_cert.public_key() != second_cert.public_key()

    response = await client.delete(f"/api/v1/private-keys/{second.private_key_id}")
    assert response.status_code == 409


async def test_get_local_without_authority(client: AsyncClient, keystore: KeyStore) -> None:
    with pytest.raises(NoActiveAuthority, match="h42pki authority init"):
        await AuthorityService(keystore).get_local()


async def test_expired_root_cannot_sign(make_root: RootFactory, keystore: KeyStore) -> None:
    service = AuthorityService(keystore)
    await make_root()
    authority = await service.get_local()
    later = datetime.now(UTC) + timedelta(days=3651)

    with pytest.raises(NoActiveAuthority, match="expired"):
        await service.signing_material(authority, now=later)


# --- built-in profiles ------------------------------------------------------------------------


async def test_profiles_are_realigned_on_the_code(client: AsyncClient) -> None:
    await Profile.filter(name="tls_server").update(validity_days=999, max_validity_days=999)

    await ProfileService().sync_builtin()  # what every start-up does

    profile = await Profile.get(name="tls_server")
    assert (profile.validity_days, profile.max_validity_days) == (47, 100)
    entry = await AuditLog.get(action="profile.realign")
    assert entry.actor == "system"
    assert entry.details == {
        "name": "tls_server",
        "changed_fields": ["max_validity_days", "validity_days"],
    }


async def test_unchanged_profiles_are_left_alone(client: AsyncClient) -> None:
    await ProfileService().sync_builtin()

    assert not await AuditLog.exists(action="profile.realign")
    assert await AuditLog.filter(action="profile.create").count() == len(BUILTIN_PROFILES)
