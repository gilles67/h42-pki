"""The SCEP registration authority certificate (ADR-0019): SCEP never uses the CA key.

A dedicated RSA key (``PrivateKey.purpose = scep_ra``) and its certificate (internal profile
``scep_ra``, KU digitalSignature + keyEncipherment) are issued by the local CA once SCEP is
enabled, and renewed before they expire. Clients encrypt their requests for the RA, which also
signs the answers. Previous RA keys keep decrypting until their certificate expires, for the
transactions started before a renewal.
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from h42pki.core.keys import KeyAlgorithm
from h42pki.core.profiles import SCEP_RA_PROFILE
from h42pki.keystore import KeyStore
from h42pki.models import Authority, Certificate, CertificateStatus, KeyPurpose, PrivateKey
from h42pki.services.authority import AuthorityService
from h42pki.services.issuance import IssuanceService
from h42pki.services.settings import SettingsService

log = logging.getLogger(__name__)

# RSA is required (key transport); 3072 bits leaves margin beyond 2030, issued once a year.
RA_KEY_ALGORITHM = KeyAlgorithm.RSA3072


@dataclass(frozen=True)
class RaKey:
    """A usable RA: its certificate record and the stored form of its key."""

    certificate: Certificate
    encrypted_key: bytes


@dataclass(frozen=True)
class RaResult:
    certificate: Certificate | None
    issued: bool
    reason: str | None


def ra_common_name(authority: Authority) -> str:
    return f"{authority.name} SCEP RA"


class ScepRaManager:
    def __init__(self, keystore: KeyStore | None = None) -> None:
        """``keystore`` is only needed to issue a new RA certificate."""
        self._keystore = keystore

    @staticmethod
    async def _records(authority: Authority) -> list[Certificate]:
        """RA certificates of ``authority``, newest first."""
        return (
            await Certificate.filter(issuer_id=authority.id, profile__name=SCEP_RA_PROFILE)
            .exclude(status=CertificateStatus.REVOKED)
            .order_by("-created_at")
        )

    async def current(self, now: datetime | None = None) -> Certificate | None:
        """The newest RA certificate of the local CA, if it is still valid."""
        now = now or datetime.now(UTC)
        authority = await AuthorityService().find_local()
        if authority is None:
            return None
        for record in await self._records(authority):
            if record.not_before <= now < record.not_after:
                return record
        return None

    async def ensure(self, now: datetime | None = None) -> RaResult:
        """Issue an RA certificate when SCEP is enabled and none is valid or it is due."""
        now = now or datetime.now(UTC)
        settings = (await SettingsService().effective()).scep
        if not settings.enabled:
            return RaResult(None, issued=False, reason=None)
        authority = await AuthorityService().find_local()
        if authority is None or authority.status.value != "active":
            return RaResult(await self.current(now), issued=False, reason=None)
        current = await self.current(now)
        if current is None:
            reason = "no valid RA certificate"
        elif current.not_after - now <= timedelta(days=settings.ra_renew_before_days):
            reason = f"renewal due ({settings.ra_renew_before_days} days or fewer left)"
        else:
            return RaResult(current, issued=False, reason=None)
        if self._keystore is None:  # pragma: no cover - the launcher always has one
            raise ValueError("a key store is needed to issue the RA certificate")
        request = await IssuanceService(self._keystore).issue_internal_certificate(
            SCEP_RA_PROFILE,
            key_algorithm=RA_KEY_ALGORITHM,
            purpose=KeyPurpose.SCEP_RA,
            common_name=ra_common_name(authority),
            names=[],
            validity_days=settings.ra_validity_days,
        )
        certificate = await Certificate.get(id=request.certificate_id)
        log.info(
            "SCEP RA certificate issued (%s): serial %s, valid until %s",
            reason,
            certificate.serial_hex,
            certificate.not_after.isoformat(),
        )
        return RaResult(certificate, issued=True, reason=reason)

    async def decryption_keys(self, now: datetime | None = None) -> list[RaKey]:
        """Every RA of the local CA still within its validity: the current one first."""
        now = now or datetime.now(UTC)
        authority = await AuthorityService().find_local()
        if authority is None:
            return []
        keys: list[RaKey] = []
        for record in await self._records(authority):
            if record.private_key_id is None or not record.not_before <= now < record.not_after:
                continue
            stored = await PrivateKey.get(id=record.private_key_id)
            if stored.purpose is KeyPurpose.SCEP_RA:  # never any other key (ADR-0019)
                keys.append(RaKey(record, stored.encrypted_key))
        return keys
