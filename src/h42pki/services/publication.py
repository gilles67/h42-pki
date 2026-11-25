"""Public certificates of the local CA (AIA caIssuers target, chain). Read-only, no key involved."""

from h42pki.core.publication import AUTHORITY_NAME
from h42pki.errors import NotFound
from h42pki.models import Authority, AuthorityKind, AuthorityStatus, Certificate
from h42pki.services.authority import AuthorityService

# A CA certificate stays published after a rollover so that what it issued can still be verified.
PUBLISHED_STATUSES = (AuthorityStatus.ACTIVE, AuthorityStatus.ROLLING_OVER, AuthorityStatus.RETIRED)


class PublicationService:
    async def ca_certificate(self, name: str) -> Certificate:
        """Certificate of the local CA called ``name`` (current or retired)."""
        # Checked first: Tortoise raises on a filter value longer than the column (B48).
        if not AUTHORITY_NAME.fullmatch(name):
            raise NotFound("no published certificate authority with this name")
        authority = await Authority.get_or_none(
            name=name, kind=AuthorityKind.LOCAL, status__in=PUBLISHED_STATUSES
        )
        if authority is None:
            raise NotFound(f"no published certificate authority named {name!r}")
        return await Certificate.get(authority=authority)

    async def chain(self) -> list[Certificate]:
        """Certificates of the active local CA and of its ancestors, root included."""
        authority: Authority | None = await AuthorityService().get_local()
        chain: list[Certificate] = []
        while authority is not None:
            certificate = await Certificate.get_or_none(authority=authority)
            if certificate is None:  # ancestor known without its certificate (phase 2)
                break
            chain.append(certificate)
            parent_id = authority.parent_id
            authority = await Authority.get_or_none(id=parent_id) if parent_id else None
        return chain
