"""``/api/v1/acme/accounts``: ACME accounts, no authentication until the release (ADR-0008)."""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter
from pydantic import Field

from h42pki.api.admin.deps import Actor
from h42pki.api.admin.schemas import Schema
from h42pki.api.problems import PROBLEM_RESPONSES
from h42pki.models import AccountStatus, AcmeAccount, AcmeOrder
from h42pki.services.acme.accounts import AccountService

router = APIRouter(prefix="/api/v1/acme/accounts", tags=["acme"], responses=PROBLEM_RESPONSES)


class AcmeAccountOut(Schema):
    id: UUID
    status: AccountStatus
    contact: list[str]
    jwk_thumbprint: str = Field(description="RFC 7638 thumbprint of the account key.")
    key_type: str = Field(description="kty of the account key (RSA, EC, OKP).")
    orders: int = Field(description="Number of orders of the account.")
    tos_agreed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    async def from_model(cls, account: AcmeAccount) -> "AcmeAccountOut":
        return cls(
            id=account.id,
            status=account.status,
            contact=list(account.contact),
            jwk_thumbprint=account.jwk_thumbprint,
            key_type=str(account.jwk.get("kty", "?")),
            orders=await AcmeOrder.filter(account_id=account.id).count(),
            tos_agreed_at=account.tos_agreed_at,
            created_at=account.created_at,
            updated_at=account.updated_at,
        )


@router.get("")
async def list_accounts() -> list[AcmeAccountOut]:
    return [await AcmeAccountOut.from_model(a) for a in await AccountService.list()]


@router.get("/{account_id}")
async def get_account(account_id: UUID) -> AcmeAccountOut:
    return await AcmeAccountOut.from_model(await AccountService.get(account_id))


@router.post("/{account_id}/deactivate")
async def deactivate_account(account_id: UUID, actor: Actor) -> AcmeAccountOut:
    """The account can no longer sign any request (RFC 8555 section 7.3.6); final."""
    return await AcmeAccountOut.from_model(
        await AccountService().deactivate(account_id, actor=actor)
    )
