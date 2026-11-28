"""ACME accounts (RFC 8555 section 7.3): open to every client in lot 6a (EAB in 6b)."""

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from tortoise.exceptions import IntegrityError
from tortoise.transactions import in_transaction

from h42pki.core.acme.errors import AcmeError
from h42pki.core.acme.jws import thumbprint
from h42pki.errors import NotFound
from h42pki.models import AccountStatus, AcmeAccount, AcmeOrder, AuditLog
from h42pki.services.acme.auth import AcmeRequest
from h42pki.services.acme.context import AcmeContext
from h42pki.services.acme.payloads import AccountUpdate, NewAccount, payload

MAX_CONTACTS = 10
# One address per mailto URI, without header fields (RFC 8555 section 7.3).
_MAILTO = re.compile(r"^mailto:[^@\s?,;<>\"]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}$")


def actor_of(account: AcmeAccount) -> str:
    return f"acme:{account.id}"


def _contacts(values: list[str] | None) -> list[str]:
    contacts = list(values or [])
    if len(contacts) > MAX_CONTACTS:
        raise AcmeError("malformed", f"at most {MAX_CONTACTS} contacts")
    for contact in contacts:
        if not isinstance(contact, str) or not contact.startswith("mailto:"):
            raise AcmeError("unsupportedContact", "only mailto: contacts are supported")
        if not _MAILTO.fullmatch(contact):
            raise AcmeError("invalidContact", "a mailto: contact holds one e-mail address")
    return contacts


@dataclass(frozen=True)
class AccountResult:
    account: AcmeAccount
    created: bool


class AccountService:
    @staticmethod
    def document(context: AcmeContext, account: AcmeAccount) -> dict[str, Any]:
        document: dict[str, Any] = {
            "status": account.status.value,
            "contact": list(account.contact),
            "orders": context.orders_url(account.id),
        }
        if account.tos_agreed_at is not None:
            document["termsOfServiceAgreed"] = True
        return document

    async def new_account(self, context: AcmeContext, request: AcmeRequest) -> AccountResult:
        """Create the account of the key, or return the existing one (200, RFC 8555 7.3.1)."""
        body = payload(NewAccount, request.payload)
        key_thumbprint = thumbprint(request.jwk)
        existing = await AcmeAccount.get_or_none(jwk_thumbprint=key_thumbprint)
        if existing is not None:
            if existing.status is not AccountStatus.VALID:
                raise AcmeError("unauthorized", f"the account is {existing.status.value}")
            return AccountResult(existing, False)
        if body.onlyReturnExisting:
            raise AcmeError("accountDoesNotExist", "no account has this key")
        terms = context.settings.terms_of_service_url
        if terms and not body.termsOfServiceAgreed:
            raise AcmeError("malformed", "the terms of service must be agreed to")
        contacts = _contacts(body.contact)
        try:
            async with in_transaction():
                account = await AcmeAccount.create(
                    jwk=request.jwk,
                    jwk_thumbprint=key_thumbprint,
                    contact=contacts,
                    tos_agreed_at=datetime.now(UTC)
                    if terms and body.termsOfServiceAgreed
                    else None,
                )
                await AuditLog.record(
                    actor=actor_of(account),
                    action="acme.account.create",
                    object_type="acme_account",
                    object_id=account.id,
                    details={"jwk_thumbprint": key_thumbprint, "contacts": len(contacts)},
                )
        except IntegrityError:  # created meanwhile by the same key
            return AccountResult(await AcmeAccount.get(jwk_thumbprint=key_thumbprint), False)
        return AccountResult(account, True)

    @staticmethod
    def _own(request: AcmeRequest, account_id: UUID) -> AcmeAccount:
        account = request.signed_account
        if account.id != account_id:
            raise AcmeError("unauthorized", "this is not the account of the key")
        return account

    async def update(
        self, context: AcmeContext, request: AcmeRequest, account_id: UUID
    ) -> AcmeAccount:
        """POST-as-GET reads; ``contact`` replaces the contacts; ``status: deactivated``."""
        account = self._own(request, account_id)
        if request.payload is None:
            return account
        body = payload(AccountUpdate, request.payload)
        changes: dict[str, Any] = {}
        if body.contact is not None:
            account.contact = _contacts(body.contact)
            changes["contacts"] = len(account.contact)
        if body.status == "deactivated":
            account.status = AccountStatus.DEACTIVATED
            changes["status"] = "deactivated"
        if changes:
            async with in_transaction():
                await account.save()
                await AuditLog.record(
                    actor=actor_of(account),
                    action="acme.account.deactivate"
                    if body.status == "deactivated"
                    else "acme.account.update",
                    object_type="acme_account",
                    object_id=account.id,
                    details=changes,
                )
        return account

    async def orders(
        self, context: AcmeContext, request: AcmeRequest, account_id: UUID
    ) -> list[str]:
        """URLs of the orders of the account (RFC 8555 7.1.2.1), most recent first."""
        account = self._own(request, account_id)
        orders = await AcmeOrder.filter(account_id=account.id).order_by("-created_at").limit(1000)
        return [context.order_url(order.id) for order in orders]

    # --- administration (API, CLI) --------------------------------------------------------

    @staticmethod
    async def list() -> list[AcmeAccount]:
        return await AcmeAccount.all().order_by("-created_at")

    @staticmethod
    async def get(account_id: UUID) -> AcmeAccount:
        account = await AcmeAccount.get_or_none(id=account_id)
        if account is None:
            raise NotFound(f"no ACME account {account_id}")
        return account

    async def deactivate(self, account_id: UUID, *, actor: str) -> AcmeAccount:
        account = await self.get(account_id)
        if account.status is AccountStatus.VALID:
            async with in_transaction():
                account.status = AccountStatus.DEACTIVATED
                await account.save()
                await AuditLog.record(
                    actor=actor,
                    action="acme.account.deactivate",
                    object_type="acme_account",
                    object_id=account.id,
                    details={"status": "deactivated"},
                )
        return account
