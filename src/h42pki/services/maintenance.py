"""Housekeeping of the scheduled tasks: expired status (B34), purge of old internal keys (B44)."""

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID

from tortoise.transactions import in_transaction

from h42pki.core.profiles import SCEP_RA_PROFILE, SERVICE_TLS_PROFILE
from h42pki.models import (
    AuditLog,
    Certificate,
    CertificateRequest,
    CertificateStatus,
    KeyPurpose,
    PrivateKey,
    ScepNonce,
)

log = logging.getLogger(__name__)

SYSTEM_ACTOR = "system"
# Internal certificates purged once replaced and expired, with the purpose of their key.
INTERNAL_KEYS = {SERVICE_TLS_PROFILE: KeyPurpose.TLS, SCEP_RA_PROFILE: KeyPurpose.SCEP_RA}
SCEP_NONCE_RETENTION = timedelta(days=30)
# The audit entry of an expiry run lists at most this many certificate ids.
MAX_AUDITED_IDS = 100


@dataclass(frozen=True)
class PurgeResult:
    certificates: list[UUID] = field(default_factory=list)
    keys: list[UUID] = field(default_factory=list)


class MaintenanceService:
    @staticmethod
    async def expire(now: datetime | None = None) -> int:
        """Write ``expired`` on valid certificates past their notAfter (B34).

        Reading still computes the effective status, in case this has not run yet.
        """
        now = now or datetime.now(UTC)
        async with in_transaction():
            ids = await Certificate.filter(
                status=CertificateStatus.VALID, not_after__lte=now
            ).values_list("id", flat=True)
            if not ids:
                return 0
            count = await Certificate.filter(id__in=ids, status=CertificateStatus.VALID).update(
                status=CertificateStatus.EXPIRED
            )
            await AuditLog.record(
                actor=SYSTEM_ACTOR,
                action="certificate.expire",
                object_type="certificate",
                object_id=str(ids[0]) if count == 1 else "batch",
                details={
                    "count": count,
                    "certificate_ids": [str(value) for value in ids[:MAX_AUDITED_IDS]],
                },
            )
        log.info("%d certificate(s) marked expired", count)
        return count

    @staticmethod
    async def purge_service_tls(now: datetime | None = None) -> PurgeResult:
        """Delete the internal certificates replaced since and expired, with their key (B44).

        The built-in HTTPS server certificates and the SCEP RA certificates (ADR-0019; an old RA
        keeps decrypting until it expires, so only then is it deleted). The latest certificate of
        each CA and profile is always kept, even expired.
        """
        now = now or datetime.now(UTC)
        result = PurgeResult()
        for profile, purpose in INTERNAL_KEYS.items():
            await MaintenanceService._purge(profile, purpose, now, result)
        # SCEP senderNonces: a replay of an old message is refused by its expired signer anyway.
        await ScepNonce.filter(created_at__lt=now - SCEP_NONCE_RETENTION).delete()
        if result.certificates:
            log.info(
                "purged %d replaced internal certificate(s) and %d key(s)",
                len(result.certificates),
                len(result.keys),
            )
        return result

    @staticmethod
    async def _purge(profile: str, purpose: KeyPurpose, now: datetime, result: PurgeResult) -> None:
        records = await Certificate.filter(profile__name=profile).order_by(
            "issuer_id", "-created_at"
        )
        latest: set[UUID | None] = set()
        doomed: list[Certificate] = []
        for record in records:
            if record.issuer_id not in latest:
                latest.add(record.issuer_id)  # the newest of this CA
                continue
            if record.not_after <= now:
                doomed.append(record)
        for record in doomed:
            async with in_transaction():
                key_id = record.private_key_id
                await CertificateRequest.filter(certificate_id=record.id).delete()
                await Certificate.filter(id=record.id).delete()
                await AuditLog.record(
                    actor=SYSTEM_ACTOR,
                    action="certificate.purge",
                    object_type="certificate",
                    object_id=record.id,
                    details={
                        "profile": profile,
                        "serial_hex": record.serial_hex,
                        "not_after": record.not_after.isoformat(),
                    },
                )
                result.certificates.append(record.id)
                if key_id is not None and not await Certificate.exists(private_key_id=key_id):
                    deleted = await PrivateKey.filter(id=key_id, purpose=purpose).delete()
                    if deleted:
                        await AuditLog.record(
                            actor=SYSTEM_ACTOR,
                            action="private_key.delete",
                            object_type="private_key",
                            object_id=key_id,
                            details={"purpose": purpose.value, "reason": "purge"},
                        )
                        result.keys.append(key_id)
