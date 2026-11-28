"""Validation of ACME challenges (RFC 8555 section 8), in the background.

A challenge the client responded to is ``processing`` with ``next_attempt_at``; a worker claims
an attempt by a conditional update (``attempts``, a lease in ``next_attempt_at``), checks, then
stores ``valid`` or, after the last attempt, ``invalid``. Three attempts: at once, then 5 and 15
seconds later. A restart loses no validation: the ``acme_validation`` task of the launcher resumes
every ``processing`` challenge whose attempt is due (lease expired included).

Lab mode (``acme.insecure_skip_validation``, never in production): no check at all, the challenge
is ``valid`` and marked ``lab_validated`` (the issuance audit says so).
"""

import asyncio
import ipaddress
import logging
from datetime import UTC, datetime, timedelta
from typing import Protocol
from urllib.parse import urljoin, urlsplit
from uuid import UUID

import httpx

from h42pki.core.acme.errors import AcmeError
from h42pki.core.acme.jws import key_authorization
from h42pki.models import (
    AcmeAuthorization,
    AcmeChallenge,
    AuditLog,
    AuthorizationStatus,
    ChallengeStatus,
    ChallengeType,
    IdentifierType,
)
from h42pki.services.settings import SettingsService

log = logging.getLogger(__name__)

RETRY_DELAYS_SECONDS = (5.0, 15.0)  # after the first and the second failed attempt
ATTEMPTS = len(RETRY_DELAYS_SECONDS) + 1
LEASE = timedelta(seconds=60)  # an attempt not finished by then is resumed
HTTP_TIMEOUT_SECONDS = 10.0
MAX_REDIRECTS = 10
MAX_BODY_BYTES = 8 * 1024
USER_AGENT = "h42pki-acme-validator"
REDIRECT_PORTS = (80, 443)


class ChallengeChecker(Protocol):
    """Checks a challenge; raises ``AcmeError`` (connection, incorrectResponse, dns…)."""

    async def http01(self, host: str, token: str, expected: str) -> None: ...


def _host(identifier_type: IdentifierType, value: str) -> str:
    if identifier_type is IdentifierType.IP and ipaddress.ip_address(value).version == 6:
        return f"[{value}]"
    return value


class NetworkChecker:
    """http-01 over the network (port 80, at most 10 redirections to ports 80 and 443)."""

    async def http01(self, host: str, token: str, expected: str) -> None:
        url = f"http://{host}/.well-known/acme-challenge/{token}"
        try:
            async with asyncio.timeout(HTTP_TIMEOUT_SECONDS):
                body = await self._fetch(url)
        except TimeoutError:
            raise AcmeError("connection", f"no answer from {host} within 10 seconds") from None
        if body.rstrip() != expected:
            raise AcmeError("incorrectResponse", f"{host} did not answer the key authorization")

    @staticmethod
    async def _fetch(url: str) -> str:
        # verify=False: RFC 8555 section 8.3 (a redirection to https is not checked).
        async with httpx.AsyncClient(
            follow_redirects=False,
            verify=False,  # noqa: S501 - RFC 8555 section 8.3
            trust_env=False,
            headers={"User-Agent": USER_AGENT},
        ) as client:
            for _ in range(MAX_REDIRECTS + 1):
                host = urlsplit(url).hostname or "?"
                try:
                    async with client.stream("GET", url) as response:
                        if response.is_redirect:
                            url = _redirect(url, response.headers.get("location", ""))
                            continue
                        if response.status_code != 200:
                            raise AcmeError(
                                "unauthorized", f"{host} answered HTTP {response.status_code}"
                            )
                        data = b""
                        async for chunk in response.aiter_bytes():
                            data += chunk
                            if len(data) > MAX_BODY_BYTES:
                                raise AcmeError("incorrectResponse", f"{host} answered too much")
                        return data.decode("utf-8", errors="replace")
                except httpx.HTTPError as exc:
                    raise AcmeError(
                        "connection",
                        f"cannot fetch the challenge from {host}: {type(exc).__name__}",
                    ) from None
        raise AcmeError("connection", f"more than {MAX_REDIRECTS} redirections")


def _redirect(current: str, location: str) -> str:
    target = urljoin(current, location)
    parts = urlsplit(target)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if parts.scheme not in ("http", "https") or port not in REDIRECT_PORTS or not parts.hostname:
        raise AcmeError(
            "connection", "redirection refused: only http and https on ports 80 and 443"
        )
    return target


class AcmeValidation:
    """The validations of this process (one per application, ``app.state.acme_validation``)."""

    def __init__(self, checker: ChallengeChecker | None = None) -> None:
        self.checker: ChallengeChecker = checker or NetworkChecker()
        self._running: dict[UUID, asyncio.Task[None]] = {}

    async def start(self, challenge_id: UUID) -> None:
        if challenge_id in self._running:
            return
        task = asyncio.create_task(self._run(challenge_id), name=f"acme-validation-{challenge_id}")
        self._running[challenge_id] = task
        task.add_done_callback(lambda _: self._running.pop(challenge_id, None))

    async def drain(self) -> None:
        """Wait for the running validations (tests, shutdown)."""
        while self._running:
            await asyncio.gather(*self._running.values(), return_exceptions=True)

    async def resume(self) -> int:
        """Start the due validations (at start-up and periodically): the number started."""
        due = await AcmeChallenge.filter(
            status=ChallengeStatus.PROCESSING, next_attempt_at__lte=datetime.now(UTC)
        ).values_list("id", flat=True)
        started = 0
        for challenge_id in due:
            if challenge_id not in self._running:
                await self.start(challenge_id)  # type: ignore[arg-type]
                started += 1
        return started

    async def _run(self, challenge_id: UUID) -> None:
        try:
            while await self._attempt(challenge_id):
                pass
        except Exception:  # pragma: no cover - logged, resumed by the task after the lease
            log.exception("ACME validation of challenge %s failed unexpectedly", challenge_id)

    async def _attempt(self, challenge_id: UUID) -> bool:
        """One attempt when due; True when another one follows."""
        challenge = await AcmeChallenge.get_or_none(id=challenge_id).prefetch_related(
            "authorization__order__account"
        )
        if challenge is None or challenge.status is not ChallengeStatus.PROCESSING:
            return False
        now = datetime.now(UTC)
        due = challenge.next_attempt_at or now
        if due > now:
            await asyncio.sleep((due - now).total_seconds())
            return True
        attempt = challenge.attempts + 1
        claimed = await AcmeChallenge.filter(
            id=challenge.id, status=ChallengeStatus.PROCESSING, attempts=challenge.attempts
        ).update(attempts=attempt, next_attempt_at=now + LEASE)
        if not claimed:
            return False  # another worker has it
        authorization = challenge.authorization
        lab = (await SettingsService().effective()).acme.insecure_skip_validation
        try:
            if lab:
                log.warning(
                    "ACME lab mode: challenge %s for %s declared valid without any check",
                    challenge.id,
                    authorization.identifier_value,
                )
            else:
                await self._check(challenge)
        except AcmeError as exc:
            if attempt < ATTEMPTS:
                await AcmeChallenge.filter(id=challenge.id, attempts=attempt).update(
                    next_attempt_at=datetime.now(UTC)
                    + timedelta(seconds=RETRY_DELAYS_SECONDS[attempt - 1]),
                    error=exc.document(),
                )
                log.info(
                    "ACME challenge %s for %s: attempt %d failed (%s)",
                    challenge.id, authorization.identifier_value, attempt, exc.detail,
                )  # fmt: skip
                return True
            await self._finish(challenge, valid=False, error=exc.document(), lab=False)
            return False
        await self._finish(challenge, valid=True, error=None, lab=lab)
        return False

    async def _check(self, challenge: AcmeChallenge) -> None:
        authorization = challenge.authorization
        account = authorization.order.account
        expected = key_authorization(challenge.token, account.jwk)
        if challenge.type is ChallengeType.HTTP_01:
            host = _host(authorization.identifier_type, authorization.identifier_value)
            await self.checker.http01(host, challenge.token, expected)
            return
        raise AcmeError("malformed", f"challenge type {challenge.type.value} is not supported")

    @staticmethod
    async def _finish(
        challenge: AcmeChallenge, *, valid: bool, error: dict[str, object] | None, lab: bool
    ) -> None:
        authorization = challenge.authorization
        now = datetime.now(UTC)
        status = ChallengeStatus.VALID if valid else ChallengeStatus.INVALID
        await AcmeChallenge.filter(id=challenge.id, status=ChallengeStatus.PROCESSING).update(
            status=status,
            validated_at=now if valid else None,
            error=None if valid else error,
            next_attempt_at=None,
            lab_validated=lab,
        )
        await AcmeAuthorization.filter(
            id=authorization.id, status=AuthorizationStatus.PENDING
        ).update(status=AuthorizationStatus.VALID if valid else AuthorizationStatus.INVALID)
        await AuditLog.record(
            actor="system",
            action="acme.challenge.validate",
            object_type="acme_challenge",
            object_id=challenge.id,
            details={
                "type": challenge.type.value,
                "identifier": authorization.identifier_value,
                "status": status.value,
                "insecure_skip_validation": lab,
                **({"error": error.get("detail")} if error else {}),
            },
        )
        log.info(
            "ACME challenge %s (%s) for %s: %s",
            challenge.id, challenge.type.value, authorization.identifier_value, status.value,
        )  # fmt: skip
