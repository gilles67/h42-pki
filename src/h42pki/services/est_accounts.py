"""EST accounts (HTTP Basic, ADR-0018): created and managed by the CLI and the admin API.

A password is hashed with scrypt (core/passwords.py) in a thread; it is never stored, logged,
audited nor returned, except a generated one, shown once to whoever created it.
"""

import asyncio
import builtins
from dataclasses import dataclass
from datetime import UTC, datetime

from tortoise.transactions import in_transaction

from h42pki.core.passwords import (
    USERNAME,
    InvalidPassword,
    check_password,
    generate_password,
    hash_password,
    verify_password,
)
from h42pki.errors import Conflict, InvalidRequest, NotFound
from h42pki.models import AuditLog, CredentialKind, CredentialStatus, EnrollmentCredential


@dataclass(frozen=True, repr=False)
class AccountSecret:
    """An account and the password generated for it (None when the caller chose it)."""

    account: EnrollmentCredential
    generated_password: str | None

    def __repr__(self) -> str:
        return f"AccountSecret({self.account!r}, generated={self.generated_password is not None})"


def _check_username(username: str) -> str:
    if not USERNAME.fullmatch(username):
        raise InvalidRequest(
            "an EST user name has 1 to 64 letters, digits, dots, hyphens or underscores"
        )
    return username


def _password(password: str | None) -> tuple[str, str | None]:
    """The password to hash, and the generated one to show (None when chosen)."""
    if password is None:
        generated = generate_password()
        return generated, generated
    try:
        return check_password(password), None
    except InvalidPassword as exc:
        raise InvalidRequest(str(exc)) from None


def is_usable(account: EnrollmentCredential, now: datetime) -> bool:
    return account.status is CredentialStatus.ACTIVE and (
        account.expires_at is None or account.expires_at > now
    )


class EstAccountService:
    KIND = CredentialKind.EST_BASIC

    async def list(self) -> builtins.list[EnrollmentCredential]:
        return await EnrollmentCredential.filter(kind=self.KIND).order_by("identifier")

    async def get(self, username: str) -> EnrollmentCredential:
        account = await EnrollmentCredential.get_or_none(kind=self.KIND, identifier=username)
        if account is None:
            raise NotFound(f"no EST account named {username!r}")
        return account

    async def create(
        self,
        username: str,
        *,
        password: str | None = None,
        expires_at: datetime | None = None,
        description: str | None = None,
        actor: str,
    ) -> AccountSecret:
        _check_username(username)
        if expires_at is not None and expires_at <= datetime.now(UTC):
            raise InvalidRequest("expires_at must be in the future")
        secret, generated = _password(password)
        if await EnrollmentCredential.exists(kind=self.KIND, identifier=username):
            raise Conflict(f"an EST account named {username!r} already exists")
        digest = await asyncio.to_thread(hash_password, secret)
        async with in_transaction():
            account = await EnrollmentCredential.create(
                kind=self.KIND,
                identifier=username,
                secret_hash=digest,
                expires_at=expires_at,
                description=description,
                created_by=actor,
            )
            await self._audit(
                actor,
                "est.account.create",
                account,
                {
                    "expires_at": expires_at.isoformat() if expires_at is not None else None,
                    "password": "generated" if generated is not None else "chosen",
                },
            )
        return AccountSecret(account, generated)

    async def set_status(
        self, username: str, status: CredentialStatus, *, actor: str
    ) -> EnrollmentCredential:
        account = await self.get(username)
        action = (
            "est.account.enable" if status is CredentialStatus.ACTIVE else "est.account.disable"
        )
        async with in_transaction():
            await EnrollmentCredential.filter(id=account.id).update(status=status)
            await self._audit(actor, action, account, {})
        return await self.get(username)

    async def set_password(
        self, username: str, password: str | None = None, *, actor: str
    ) -> AccountSecret:
        account = await self.get(username)
        secret, generated = _password(password)
        digest = await asyncio.to_thread(hash_password, secret)
        async with in_transaction():
            await EnrollmentCredential.filter(id=account.id).update(secret_hash=digest)
            await self._audit(
                actor,
                "est.account.password",
                account,
                {"password": "generated" if generated is not None else "chosen"},
            )
        return AccountSecret(await self.get(username), generated)

    async def delete(self, username: str, *, actor: str) -> None:
        account = await self.get(username)
        async with in_transaction():
            await EnrollmentCredential.filter(id=account.id).delete()
            await self._audit(actor, "est.account.delete", account, {})

    async def authenticate(self, username: str, password: str) -> EnrollmentCredential | None:
        """The usable account with this password, or None; same cost whatever the reason."""
        account = (
            await EnrollmentCredential.get_or_none(kind=self.KIND, identifier=username)
            if USERNAME.fullmatch(username)
            else None
        )
        stored = account.secret_hash if account is not None else None
        valid = await asyncio.to_thread(verify_password, password, stored)
        now = datetime.now(UTC)
        if account is None or not valid or not is_usable(account, now):
            return None
        await EnrollmentCredential.filter(id=account.id).update(last_used_at=now)
        account.last_used_at = now
        return account

    @staticmethod
    async def _audit(
        actor: str, action: str, account: EnrollmentCredential, details: dict[str, object]
    ) -> None:
        await AuditLog.record(
            actor=actor,
            action=action,
            object_type="enrollment_credential",
            object_id=account.id,
            details={"kind": account.kind.value, "username": account.identifier, **details},
        )
