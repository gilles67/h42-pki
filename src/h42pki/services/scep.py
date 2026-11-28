"""SCEP (RFC 8894, ADR-0019): availability, profile of a label, GetCACaps, GetCACert.

SCEP never uses the CA key: the RA certificate (``services/scep_ra.py``) decrypts the requests and
signs the answers, through the key store.
"""

import re

from cryptography import x509

from h42pki.core.cms import capabilities, certs_only
from h42pki.core.settings_schema import ScepSettings
from h42pki.errors import NotFound, ServiceUnavailable
from h42pki.models import Profile
from h42pki.services.profiles import spec_of
from h42pki.services.publication import PublicationService
from h42pki.services.scep_ra import ScepRaManager
from h42pki.services.settings import SettingsService

PROFILE_NAME = re.compile(r"^[a-z0-9_]{1,64}$")


class ScepService:
    @staticmethod
    async def settings() -> ScepSettings:
        """SCEP settings; 404 while ``scep.enabled`` is false (disabled by default, ADR-0018)."""
        settings = (await SettingsService().effective()).scep
        if not settings.enabled:
            raise NotFound("SCEP is not enabled on this CA")
        return settings

    @staticmethod
    async def profile(label: str | None, settings: ScepSettings) -> str:
        """Profile of a label (a profile name), or ``scep.default_profile`` without label."""
        name = label if label is not None else settings.default_profile
        if not name:
            raise NotFound(
                "no default SCEP profile: use /scep/{profile} (or set scep.default_profile)"
            )
        profile = await Profile.get_or_none(name=name) if PROFILE_NAME.fullmatch(name) else None
        if profile is None or spec_of(profile).internal:
            raise NotFound(f"no SCEP profile named {name!r}")
        return profile.name

    @staticmethod
    def capabilities(settings: ScepSettings) -> str:
        return "\n".join(capabilities(settings.allow_legacy_crypto)) + "\n"

    @staticmethod
    async def ca_certificates() -> bytes:
        """GetCACert: degenerate SignedData with the CA, the RA, then the ancestors of the CA."""
        ra = await ScepRaManager().current()
        if ra is None:
            raise ServiceUnavailable("the SCEP RA certificate is not issued yet: try again soon")
        chain = [
            x509.load_der_x509_certificate(record.der)
            for record in await PublicationService().chain()
        ]
        return certs_only([chain[0], x509.load_der_x509_certificate(ra.der), *chain[1:]])
