"""What every ACME request needs: the settings and the absolute URLs (``acme.base_url``)."""

from dataclasses import dataclass
from uuid import UUID

from h42pki.config import Settings
from h42pki.core.profiles import BUILTIN_PROFILES
from h42pki.core.settings_schema import AcmeSettings
from h42pki.errors import NotFound
from h42pki.services.profiles import ProfileService
from h42pki.services.settings import SettingsService

PREFIX = "/acme"
LAB_MODE_WARNING = (
    "ACME lab mode (acme.insecure_skip_validation): every challenge is declared valid without "
    "any check, so anyone can get a certificate for any name; never outside a lab"
)


def origin(acme: AcmeSettings, server: Settings) -> str:
    """``acme.base_url``, or https://H42_PKI_SERVER_HOSTNAME[:H42_PKI_HTTPS_PORT]."""
    if acme.base_url:
        return acme.base_url
    host = server.server_hostname or "localhost"
    return f"https://{host}" + ("" if server.https_port == 443 else f":{server.https_port}")


@dataclass(frozen=True)
class AcmeContext:
    settings: AcmeSettings
    base: str  # origin, without trailing slash

    def url(self, path: str) -> str:
        """Absolute URL of ``path`` (``/acme/...``)."""
        return self.base + path

    def directory_url(self, profile: str | None = None) -> str:
        if profile is None or profile == self.settings.default_profile:
            if self.settings.default_profile:
                return self.url(f"{PREFIX}/directory")
        return self.url(f"{PREFIX}/{profile}/directory")

    def new_order_url(self, profile: str) -> str:
        if profile == self.settings.default_profile:
            return self.url(f"{PREFIX}/new-order")
        return self.url(f"{PREFIX}/{profile}/new-order")

    def account_url(self, account_id: UUID) -> str:
        return self.url(f"{PREFIX}/acct/{account_id}")

    def orders_url(self, account_id: UUID) -> str:
        return self.url(f"{PREFIX}/acct/{account_id}/orders")

    def order_url(self, order_id: UUID) -> str:
        return self.url(f"{PREFIX}/order/{order_id}")

    def finalize_url(self, order_id: UUID) -> str:
        return self.url(f"{PREFIX}/order/{order_id}/finalize")

    def authz_url(self, authz_id: UUID) -> str:
        return self.url(f"{PREFIX}/authz/{authz_id}")

    def challenge_url(self, challenge_id: UUID) -> str:
        return self.url(f"{PREFIX}/chall/{challenge_id}")

    def certificate_url(self, order_id: UUID) -> str:
        return self.url(f"{PREFIX}/cert/{order_id}")

    def account_id_of(self, kid: str) -> UUID | None:
        """The account of a ``kid`` (its account URL on this server), or None."""
        prefix = self.url(f"{PREFIX}/acct/")
        if not kid.startswith(prefix):
            return None
        try:
            return UUID(kid[len(prefix) :])
        except ValueError:
            return None


async def acme_context(server: Settings) -> AcmeContext:
    """The context, or ``NotFound`` when ACME is disabled (every route answers 404)."""
    acme = (await SettingsService().effective()).acme
    if not acme.enabled:
        raise NotFound("ACME is not enabled on this CA")
    return AcmeContext(acme, origin(acme, server))


async def directory_profile(context: AcmeContext, label: str | None) -> str:
    """The profile of a directory (``None``: the default one), or ``NotFound``."""
    name = context.settings.default_profile if label is None else label
    if not name:
        raise NotFound("no default ACME profile: use /acme/{profile}/directory")
    spec = BUILTIN_PROFILES.get(name)
    if spec is None or spec.internal:
        raise NotFound(f"no ACME directory for {name!r}")
    if name in await ProfileService.disabled():
        raise NotFound(f"the profile {name} is disabled on this CA")
    return name
