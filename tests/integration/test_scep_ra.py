"""The dedicated SCEP RA certificate (ADR-0019): issued, renewed, purged; never the CA key."""

from datetime import timedelta

import pytest
import time_machine
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import AsyncClient

from h42pki.core.keys import KeyAlgorithm
from h42pki.keystore import KeyStore
from h42pki.models import Authority, AuthorityStatus, Certificate, KeyPurpose, PrivateKey
from h42pki.services import scep_ra
from h42pki.services.maintenance import MaintenanceService
from h42pki.services.scep_ra import ScepRaManager
from h42pki.services.settings import SettingsService
from h42pki.tasks.maintenance import scep_ra_task
from tests.conftest import RootFactory


async def enable_scep() -> None:
    await SettingsService().set("scep.enabled", True, actor="cli")


def test_the_real_key_is_rsa_3072(monkeypatch: pytest.MonkeyPatch) -> None:
    assert scep_ra.RA_KEY_ALGORITHM is KeyAlgorithm.RSA2048  # lowered by tests/conftest.py

    monkeypatch.undo()

    assert scep_ra.RA_KEY_ALGORITHM is KeyAlgorithm.RSA3072


async def test_no_ra_while_scep_is_disabled(make_root: RootFactory, keystore: KeyStore) -> None:
    await make_root()

    result = await ScepRaManager(keystore).ensure()

    assert (result.certificate, result.issued) == (None, False)


async def test_ra_issued_once_scep_is_enabled(
    client: AsyncClient, make_root: RootFactory, keystore: KeyStore
) -> None:
    authority = await make_root()
    await enable_scep()

    result = await ScepRaManager(keystore).ensure()
    again = await ScepRaManager(keystore).ensure()

    assert result.issued and result.certificate is not None
    assert not again.issued and again.certificate is not None
    assert again.certificate.id == result.certificate.id
    certificate = x509.load_der_x509_certificate(result.certificate.der)
    assert certificate.subject.rfc4514_string() == "CN=test-root SCEP RA"
    assert isinstance(certificate.public_key(), rsa.RSAPublicKey)
    usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature and usage.key_encipherment and not usage.key_cert_sign
    oids = {extension.oid for extension in certificate.extensions}
    assert x509.oid.ExtensionOID.EXTENDED_KEY_USAGE not in oids
    assert certificate.not_valid_after_utc - certificate.not_valid_before_utc == timedelta(days=365)
    stored = await PrivateKey.get(id=result.certificate.private_key_id)
    assert stored.purpose is KeyPurpose.SCEP_RA
    assert stored.id != authority.private_key_id  # never the CA key
    body = (await client.get("/api/v1/authority")).json()
    assert body["scep_ra"]["serial_hex"] == result.certificate.serial_hex


async def test_ra_renewed_and_old_key_kept_for_decryption(
    make_root: RootFactory, keystore: KeyStore
) -> None:
    await make_root()
    await enable_scep()
    manager = ScepRaManager(keystore)
    first = (await manager.ensure()).certificate
    assert first is not None

    with time_machine.travel(first.not_after - timedelta(days=30, seconds=1), tick=False):
        assert not (await manager.ensure()).issued
    with time_machine.travel(first.not_after - timedelta(days=30), tick=False):
        renewed = await manager.ensure()
        keys = await manager.decryption_keys()
    with time_machine.travel(first.not_after + timedelta(seconds=1), tick=False):
        later = await manager.decryption_keys()
        purged = await MaintenanceService.purge_service_tls()

    assert renewed.issued and renewed.certificate is not None
    assert [key.certificate.id for key in keys] == [renewed.certificate.id, first.id]
    assert [key.certificate.id for key in later] == [renewed.certificate.id]
    assert purged.certificates == [first.id]
    assert not await PrivateKey.exists(id=first.private_key_id)


async def test_settings_decide_validity(make_root: RootFactory, keystore: KeyStore) -> None:
    await make_root()
    await enable_scep()
    await SettingsService().set("scep.ra_validity_days", 90, actor="cli")

    ra = (await ScepRaManager(keystore).ensure()).certificate

    assert ra is not None and ra.not_after - ra.not_before == timedelta(days=90)


async def test_revoked_ca_issues_no_ra(make_root: RootFactory, keystore: KeyStore) -> None:
    authority = await make_root()
    await enable_scep()
    await Authority.filter(id=authority.id).update(status=AuthorityStatus.REVOKED)

    assert not (await ScepRaManager(keystore).ensure()).issued
    assert await Certificate.filter(profile__name="scep_ra").count() == 0


async def test_task_issues_the_ra(make_root: RootFactory, keystore: KeyStore) -> None:
    await make_root()
    task = scep_ra_task(keystore)
    assert await task.run_once()
    assert await Certificate.filter(profile__name="scep_ra").count() == 0

    await enable_scep()
    assert await task.run_once()

    assert await Certificate.filter(profile__name="scep_ra").count() == 1


@pytest.mark.parametrize("enabled", [False, True])
async def test_health(
    client: AsyncClient, make_root: RootFactory, keystore: KeyStore, enabled: bool
) -> None:
    await make_root()
    if enabled:
        await enable_scep()
    waiting = (await client.get("/health")).json()
    await ScepRaManager(keystore).ensure()

    body = (await client.get("/health")).json()

    if not enabled:
        assert body["scep"] == "disabled"
        return
    assert "SCEP is enabled but has no RA certificate yet" in waiting["warnings"]
    assert body["scep"]["ra_not_after"] is not None and body["warnings"] == []
