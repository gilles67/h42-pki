"""Revocation of certificates and the CRL of the local CA (ADR-0017)."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from cryptography import x509

from h42pki.core.errors import InvalidRevocation
from h42pki.core.federation import SubCaConstraints
from h42pki.core.keys import KeyAlgorithm
from h42pki.errors import Conflict, MissingPassphrase
from h42pki.keystore import KeyStore
from h42pki.models import (
    AuditLog,
    Authority,
    AuthorityStatus,
    Certificate,
    CertificateRequest,
    CertificateStatus,
    Crl,
)
from h42pki.services import IssuanceService
from h42pki.services.crl import CrlService
from h42pki.services.issuance import ChildCa
from h42pki.services.revocation import RevocationService
from h42pki.services.tls_service import TlsServiceManager
from tests.conftest import IssueFactory, RootFactory
from tests.x509_helpers import csr_pem, make_csr, name

KeyFor = Callable[[KeyAlgorithm], Any]


def server_csr(key_for: KeyFor, host: str = "www.example.test") -> str:
    return csr_pem(make_csr(key_for(KeyAlgorithm.EC_P256), name(CN=host), sans=[f"dns:{host}"]))


async def leaf(issue: IssueFactory, key_for: KeyFor) -> Certificate:
    request = await issue("tls_server", server_csr(key_for))
    return await Certificate.get(id=request.certificate_id)


def parsed(crl: Crl) -> x509.CertificateRevocationList:
    return x509.load_der_x509_crl(crl.der)


def serials(crl: Crl) -> set[int]:
    return {entry.serial_number for entry in parsed(crl)}


async def child_ca(keystore: KeyStore, key_for: KeyFor) -> Certificate:
    async def recorded(request: CertificateRequest) -> None:
        return None

    request = await IssuanceService(keystore).submit_child(
        csr=csr_pem(make_csr(key_for(KeyAlgorithm.EC_P384), name(CN="Child CA"))),
        child=ChildCa(name="child", public_base_url=None),
        constraints=SubCaConstraints(path_length=None, validity_days=None, auto_approve=True),
        actor="anonymous",
        on_recorded=recorded,
    )
    return await Certificate.get(id=request.certificate_id)


# --- revocation -------------------------------------------------------------------------------


async def test_revoke_records_audits_and_regenerates_the_crl(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor, keystore: KeyStore
) -> None:
    authority = await make_root(crl=True)
    first = await CrlService(keystore).ensure_fresh(authority)
    certificate = await leaf(issue, key_for)
    compromised = datetime.now(UTC) - timedelta(days=1)
    seen: list[tuple[UUID, str]] = []

    revoked = await RevocationService(keystore, on_revoked=lambda *a: seen.append(a)).revoke(
        certificate.id, reason="key_compromise", invalidity_date=compromised, actor="anonymous"
    )

    assert revoked.status is CertificateStatus.REVOKED
    assert revoked.revocation_reason is x509.ReasonFlags.key_compromise
    assert revoked.revoked_at is not None and revoked.invalidity_date == compromised
    entry = await AuditLog.get(action="certificate.revoke")
    assert entry.details["reason"] == "key_compromise" and entry.object_id == str(certificate.id)
    assert seen == [(authority.id, certificate.serial_hex)]
    current = await CrlService.current(authority)
    assert first is not None and current is not None
    assert current.crl_number == first.crl_number + 1
    assert serials(current) == {int(certificate.serial_hex, 16)}
    assert (await AuditLog.filter(action="crl.generate").count()) == 2


@pytest.mark.parametrize(
    "reason", ["certificate_hold", "remove_from_crl", "on_hold", "keyCompromise"]
)
async def test_bad_reasons_are_refused(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor, keystore: KeyStore, reason: str
) -> None:
    await make_root()
    certificate = await leaf(issue, key_for)

    with pytest.raises(InvalidRevocation):
        await RevocationService(keystore).revoke(certificate.id, reason=reason, actor="anonymous")
    with pytest.raises(InvalidRevocation):
        await RevocationService(keystore).revoke(
            certificate.id, reason=x509.ReasonFlags.certificate_hold, actor="anonymous"
        )
    assert (await Certificate.get(id=certificate.id)).status is CertificateStatus.VALID


async def test_future_invalidity_date_is_refused(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor, keystore: KeyStore
) -> None:
    await make_root()
    certificate = await leaf(issue, key_for)

    with pytest.raises(InvalidRevocation, match="future"):
        await RevocationService(keystore).revoke(
            certificate.id,
            reason="superseded",
            invalidity_date=datetime.now(UTC) + timedelta(days=1),
            actor="anonymous",
        )


async def test_double_revocation_conflicts(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor, keystore: KeyStore
) -> None:
    await make_root(crl=True)
    certificate = await leaf(issue, key_for)
    service = RevocationService(keystore)
    await service.revoke(certificate.id, reason="superseded", actor="anonymous")

    with pytest.raises(Conflict, match="already revoked"):
        await service.revoke(certificate.id, reason="key_compromise", actor="anonymous")


async def test_local_ca_certificate_cannot_be_revoked(
    make_root: RootFactory, keystore: KeyStore
) -> None:
    authority = await make_root()
    own = await Certificate.get(authority_id=authority.id)

    with pytest.raises(Conflict, match="certificate of the local CA"):
        await RevocationService(keystore).revoke(own.id, reason="superseded", actor="anonymous")


async def test_service_tls_certificate_cannot_be_revoked(
    make_root: RootFactory, keystore: KeyStore
) -> None:
    await make_root()
    https = (await TlsServiceManager(keystore, ["pki.home42.test"]).ensure()).certificate
    assert https is not None

    with pytest.raises(Conflict, match="built-in HTTPS server"):
        await RevocationService(keystore).revoke(https.id, reason="superseded", actor="anonymous")


async def test_revoking_a_child_ca_certificate_revokes_the_child(
    make_root: RootFactory, keystore: KeyStore, key_for: KeyFor
) -> None:
    await make_root()
    certificate = await child_ca(keystore, key_for)

    await RevocationService(keystore).revoke(
        certificate.id, reason="ca_compromise", actor="anonymous"
    )

    child = await Authority.get(name="child")
    assert child.status is AuthorityStatus.REVOKED


async def test_without_crl_no_passphrase_is_needed(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    authority = await make_root()
    certificate = await leaf(issue, key_for)

    revoked = await RevocationService().revoke(certificate.id, reason="superseded", actor="cli")

    assert revoked.status is CertificateStatus.REVOKED
    assert await CrlService.current(authority) is None


async def test_with_crl_the_passphrase_is_checked_first(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    await make_root(crl=True)
    certificate = await leaf(issue, key_for)

    with pytest.raises(MissingPassphrase, match="CRL of test-root"):
        await RevocationService().revoke(certificate.id, reason="superseded", actor="cli")
    assert (await Certificate.get(id=certificate.id)).status is CertificateStatus.VALID
    assert not await AuditLog.exists(action="certificate.revoke")


# --- CRL --------------------------------------------------------------------------------------


async def test_no_crl_when_disabled(make_root: RootFactory, keystore: KeyStore) -> None:
    authority = await make_root()

    assert await CrlService(keystore).ensure_fresh(authority, force=True) is None
    assert await CrlService(keystore).refresh_all() == []


async def test_crl_is_kept_until_due(make_root: RootFactory, keystore: KeyStore) -> None:
    authority = await make_root(crl=True)
    service = CrlService(keystore)
    first = await service.ensure_fresh(authority)
    assert first is not None

    again = await service.ensure_fresh(authority)
    later = await service.ensure_fresh(authority, now=first.next_update - timedelta(hours=48))

    assert again is not None and again.crl_number == first.crl_number
    assert later is not None and later.crl_number == first.crl_number + 1
    signed = parsed(first)
    root = x509.load_der_x509_certificate((await Certificate.get(authority_id=authority.id)).der)
    assert signed.is_signature_valid(root.public_key())  # type: ignore[arg-type]
    assert first.next_update - first.this_update == timedelta(hours=168)


async def test_crl_validity_follows_the_settings(
    make_root: RootFactory, keystore: KeyStore
) -> None:
    from h42pki.services.settings import SettingsService

    authority = await make_root(crl=True)
    await SettingsService().set("crl.validity_hours", 4380, actor="cli")
    await SettingsService().set("crl.regenerate_before_hours", 720, actor="cli")

    crl = await CrlService(keystore).ensure_fresh(authority)

    assert crl is not None and crl.next_update - crl.this_update == timedelta(hours=4380)


async def test_uncovered_revocation_is_caught_up(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor, keystore: KeyStore
) -> None:
    """A revocation whose CRL could not be signed shows at the next scheduled check."""
    authority = await make_root(crl=True)
    first = await CrlService(keystore).ensure_fresh(authority)
    certificate = await leaf(issue, key_for)
    await Certificate.filter(id=certificate.id).update(
        status=CertificateStatus.REVOKED,
        revoked_at=datetime.now(UTC),
        revocation_reason=x509.ReasonFlags.superseded,
    )

    [refreshed] = await CrlService(keystore).refresh_all()

    assert first is not None and refreshed.crl_number == first.crl_number + 1
    assert serials(refreshed) == {int(certificate.serial_hex, 16)}


async def test_revoked_local_ca_keeps_its_crl(make_root: RootFactory, keystore: KeyStore) -> None:
    authority = await make_root(crl=True)
    await Authority.filter(id=authority.id).update(status=AuthorityStatus.REVOKED)

    [crl] = await CrlService(keystore).refresh_all()

    assert crl.authority_id == authority.id


async def test_retired_ca_is_kept_while_its_certificates_last(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    authority = await make_root(crl=True)
    await Authority.filter(id=authority.id).update(status=AuthorityStatus.RETIRED)
    now = datetime.now(UTC)
    assert await CrlService.authorities(now) == []  # nothing issued: nothing to publish

    await Authority.filter(id=authority.id).update(status=AuthorityStatus.ACTIVE)
    certificate = await leaf(issue, key_for)
    await Authority.filter(id=authority.id).update(status=AuthorityStatus.RETIRED)

    assert [ca.id for ca in await CrlService.authorities(now)] == [authority.id]
    assert await CrlService.authorities(certificate.not_after + timedelta(seconds=1)) == []
