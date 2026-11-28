"""ACME orders, authorizations, challenges, finalize and certificate (RFC 8555 section 7.1, 7.4,
7.5).

Statuses are recomputed from the facts on every read (``core.acme.states``): authorizations from
their challenges and expiry, orders from their authorizations, then, after finalize, from their
certificate request (approval of the profile, or ``acme.manual_approval``).
"""

import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from tortoise.transactions import in_transaction

from h42pki.core.acme import states
from h42pki.core.acme.errors import AcmeError
from h42pki.core.acme.identifiers import (
    Identifier,
    check_csr,
    identifiers_of,
    parse_identifiers,
)
from h42pki.core.acme.jws import b64url_decode, public_key, public_key_der
from h42pki.core.csr import parse_csr
from h42pki.errors import H42Error, ServiceUnavailable, Unprocessable
from h42pki.keystore import KeyStore
from h42pki.models import (
    AcmeAccount,
    AcmeAuthorization,
    AcmeChallenge,
    AcmeOrder,
    AuditLog,
    AuthorizationStatus,
    Certificate,
    CertificateRequest,
    ChallengeStatus,
    ChallengeType,
    Channel,
    IdentifierType,
    OrderStatus,
    Profile,
)
from h42pki.services.acme.accounts import actor_of
from h42pki.services.acme.auth import AcmeRequest
from h42pki.services.acme.context import AcmeContext
from h42pki.services.acme.payloads import AuthorizationUpdate, Finalize, NewOrder, payload
from h42pki.services.certificates import CertificateService
from h42pki.services.issuance import IssuanceService
from h42pki.services.profiles import spec_of

TOKEN_BYTES = 32
StartValidation = Callable[[UUID], Awaitable[None]]


def rfc3339(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def challenge_types(identifier: Identifier) -> list[ChallengeType]:
    """Challenges offered (ADR-0020): a wildcard needs dns-01, an IP address http-01 (RFC 8738);
    a DNS name both (one valid challenge is enough)."""
    if identifier.wildcard:
        return [ChallengeType.DNS_01]
    if identifier.type == "ip":
        return [ChallengeType.HTTP_01]
    return [ChallengeType.HTTP_01, ChallengeType.DNS_01]


@dataclass(frozen=True)
class OrderView:
    order: AcmeOrder
    document: dict[str, Any]

    @property
    def processing(self) -> bool:
        return self.order.status is OrderStatus.PROCESSING


class OrderService:
    def __init__(self, keystore: KeyStore | None = None) -> None:
        self._keystore = keystore

    # --- newOrder -------------------------------------------------------------------------

    async def new_order(
        self, context: AcmeContext, request: AcmeRequest, profile: str
    ) -> OrderView:
        account = request.signed_account
        body = payload(NewOrder, request.payload)
        if body.notBefore is not None or body.notAfter is not None:
            raise AcmeError(
                "malformed", "notBefore and notAfter are not supported: the profile decides"
            )
        record = await Profile.get(name=profile)
        spec = spec_of(record)
        identifiers = parse_identifiers(body.identifiers, allow_wildcard=True, allow_ip=True)
        for identifier in identifiers:
            if identifier.type not in spec.san_policy.types:
                raise AcmeError(
                    "rejectedIdentifier",
                    f"the profile {profile} does not allow {identifier.type} identifiers",
                )
        now = datetime.now(UTC)
        expires = now + timedelta(hours=context.settings.order_lifetime_hours)
        authz_expires = min(
            expires, now + timedelta(hours=context.settings.authorization_lifetime_hours)
        )
        async with in_transaction():
            order = await AcmeOrder.create(
                account=account,
                profile=record,
                expires_at=expires,
                identifiers=[identifier.document() for identifier in identifiers],
            )
            for identifier in identifiers:
                authorization = await AcmeAuthorization.create(
                    order=order,
                    identifier_type=IdentifierType(identifier.type),
                    identifier_value=identifier.authorized_value,
                    wildcard=identifier.wildcard,
                    expires_at=authz_expires,
                )
                for kind in challenge_types(identifier):
                    await AcmeChallenge.create(
                        authorization=authorization,
                        type=kind,
                        token=secrets.token_urlsafe(TOKEN_BYTES),
                    )
            await AuditLog.record(
                actor=actor_of(account),
                action="acme.order.create",
                object_type="acme_order",
                object_id=order.id,
                details={"profile": profile, "identifiers": [i.value for i in identifiers]},
            )
        return await self.view(context, order)

    # --- reading --------------------------------------------------------------------------

    @staticmethod
    async def _owned_order(request: AcmeRequest, order_id: UUID) -> AcmeOrder:
        order = await AcmeOrder.get_or_none(id=order_id)
        if order is None or order.account_id != request.signed_account.id:
            raise AcmeError("unauthorized", "no such order for this account", status=404)
        return order

    @staticmethod
    async def _owned_authorization(request: AcmeRequest, authz_id: UUID) -> AcmeAuthorization:
        authorization = await AcmeAuthorization.get_or_none(id=authz_id).prefetch_related("order")
        if authorization is None or authorization.order.account_id != request.signed_account.id:
            raise AcmeError("unauthorized", "no such authorization for this account", status=404)
        return authorization

    async def order(self, context: AcmeContext, request: AcmeRequest, order_id: UUID) -> OrderView:
        return await self.view(context, await self._owned_order(request, order_id))

    async def view(self, context: AcmeContext, order: AcmeOrder) -> OrderView:
        order = await self.refresh(order)
        authorizations = await AcmeAuthorization.filter(order_id=order.id).order_by("created_at")
        document: dict[str, Any] = {
            "status": order.status.value,
            "expires": rfc3339(order.expires_at),
            "identifiers": list(order.identifiers),
            "authorizations": [context.authz_url(a.id) for a in authorizations],
            "finalize": context.finalize_url(order.id),
        }
        if order.status is OrderStatus.VALID and order.certificate_id is not None:
            document["certificate"] = context.certificate_url(order.id)
        if order.error:
            document["error"] = order.error
        return OrderView(order, document)

    @staticmethod
    async def refresh_authorization(authorization: AcmeAuthorization) -> AcmeAuthorization:
        challenges = await AcmeChallenge.filter(authorization_id=authorization.id)
        status = states.authorization_status(
            authorization.status.value,
            [c.status.value for c in challenges],
            expires_at=authorization.expires_at,
            now=datetime.now(UTC),
        )
        if status != authorization.status.value:
            await AcmeAuthorization.filter(id=authorization.id, status=authorization.status).update(
                status=AuthorizationStatus(status)
            )
            authorization.status = AuthorizationStatus(status)
        return authorization

    async def refresh(self, order: AcmeOrder) -> AcmeOrder:
        """Recompute and store the status of ``order``."""
        now = datetime.now(UTC)
        if order.status in (OrderStatus.PENDING, OrderStatus.READY):
            authorizations = await AcmeAuthorization.filter(order_id=order.id)
            statuses = [(await self.refresh_authorization(a)).status.value for a in authorizations]
            status = states.order_status(
                order.status.value, statuses, expires_at=order.expires_at, now=now
            )
            if status != order.status.value:
                error = None
                if status == "invalid":
                    error = (
                        AcmeError("unauthorized", "an authorization of the order failed").document()
                        if any(s in states.FAILED_AUTHORIZATIONS for s in statuses)
                        else AcmeError("malformed", "the order expired").document()
                    )
                await self._set(order, OrderStatus(status), error=error)
        elif order.status is OrderStatus.PROCESSING and order.request_id is not None:
            request = await CertificateRequest.get(id=order.request_id)
            status = states.order_status_of_request(request.status.value)
            if status == "valid":
                await self._set(order, OrderStatus.VALID, certificate_id=request.certificate_id)
            elif status == "invalid":
                reason = request.rejection_reason or (request.metadata or {}).get("failure")
                detail = "the certificate request was rejected" + (f": {reason}" if reason else "")
                await self._set(
                    order,
                    OrderStatus.INVALID,
                    error=AcmeError("unauthorized", detail).document(),
                )
        return order

    @staticmethod
    async def _set(
        order: AcmeOrder,
        status: OrderStatus,
        *,
        error: dict[str, Any] | None = None,
        certificate_id: UUID | None = None,
    ) -> None:
        changes: dict[str, Any] = {"status": status}
        if error is not None:
            changes["error"] = error
        if certificate_id is not None:
            changes["certificate_id"] = certificate_id
        await AcmeOrder.filter(id=order.id, status=order.status).update(**changes)
        order.status = status
        order.error = error if error is not None else order.error
        order.certificate_id = certificate_id or order.certificate_id

    # --- authorizations and challenges ----------------------------------------------------

    async def authorization(
        self, context: AcmeContext, request: AcmeRequest, authz_id: UUID
    ) -> dict[str, Any]:
        authorization = await self._owned_authorization(request, authz_id)
        if request.payload is not None:
            body = payload(AuthorizationUpdate, request.payload)
            if body.status == "deactivated" and authorization.status in (
                AuthorizationStatus.PENDING,
                AuthorizationStatus.VALID,
            ):
                await AcmeAuthorization.filter(id=authorization.id).update(
                    status=AuthorizationStatus.DEACTIVATED
                )
                authorization.status = AuthorizationStatus.DEACTIVATED
        return await self.authorization_document(context, authorization)

    async def authorization_document(
        self, context: AcmeContext, authorization: AcmeAuthorization
    ) -> dict[str, Any]:
        authorization = await self.refresh_authorization(authorization)
        challenges = await AcmeChallenge.filter(authorization_id=authorization.id).order_by("type")
        document: dict[str, Any] = {
            "identifier": {
                "type": authorization.identifier_type.value,
                "value": authorization.identifier_value,
            },
            "status": authorization.status.value,
            "expires": rfc3339(authorization.expires_at),
            "challenges": [self.challenge_document(context, c) for c in challenges],
        }
        if authorization.wildcard:
            document["wildcard"] = True
        return document

    @staticmethod
    def challenge_document(context: AcmeContext, challenge: AcmeChallenge) -> dict[str, Any]:
        document: dict[str, Any] = {
            "type": challenge.type.value,
            "url": context.challenge_url(challenge.id),
            "status": challenge.status.value,
            "token": challenge.token,
        }
        if challenge.validated_at is not None:
            document["validated"] = rfc3339(challenge.validated_at)
        if challenge.error:
            document["error"] = challenge.error
        return document

    async def challenge(
        self,
        context: AcmeContext,
        request: AcmeRequest,
        challenge_id: UUID,
        start: StartValidation,
    ) -> tuple[dict[str, Any], UUID]:
        """POST-as-GET reads; any JSON object (``{}``) asks for the validation (7.5.1)."""
        challenge = await AcmeChallenge.get_or_none(id=challenge_id).prefetch_related(
            "authorization__order"
        )
        if challenge is None or (
            challenge.authorization.order.account_id != request.signed_account.id
        ):
            raise AcmeError("unauthorized", "no such challenge for this account", status=404)
        if request.payload is not None:
            if not isinstance(request.payload, dict):
                raise AcmeError("malformed", "the payload must be a JSON object")
            authorization = await self.refresh_authorization(challenge.authorization)
            if authorization.status is not AuthorizationStatus.PENDING:
                if challenge.status is ChallengeStatus.PENDING:
                    raise AcmeError(
                        "malformed", f"the authorization is {authorization.status.value}"
                    )
            elif challenge.status is ChallengeStatus.PENDING:
                updated = await AcmeChallenge.filter(
                    id=challenge.id, status=ChallengeStatus.PENDING
                ).update(
                    status=ChallengeStatus.PROCESSING, attempts=0, next_attempt_at=datetime.now(UTC)
                )
                if updated:
                    await AuditLog.record(
                        actor=actor_of(request.signed_account),
                        action="acme.challenge.respond",
                        object_type="acme_challenge",
                        object_id=challenge.id,
                        details={
                            "type": challenge.type.value,
                            "identifier": challenge.authorization.identifier_value,
                        },
                    )
                    await start(challenge.id)
            challenge = await AcmeChallenge.get(id=challenge.id)
        return self.challenge_document(context, challenge), challenge.authorization_id

    # --- finalize and certificate ---------------------------------------------------------

    async def finalize(
        self, context: AcmeContext, request: AcmeRequest, order_id: UUID
    ) -> OrderView:
        account = request.signed_account
        order = await self.refresh(await self._owned_order(request, order_id))
        if order.status is not OrderStatus.READY:
            raise AcmeError("orderNotReady", f"the order is {order.status.value}, not ready")
        body = payload(Finalize, request.payload)
        der = b64url_decode(body.csr, "csr")
        try:
            parsed = parse_csr(der)
        except H42Error as exc:
            raise AcmeError("badCSR", exc.detail) from None
        if public_key_der(parsed.public_key) == public_key_der(public_key(account.jwk)):  # type: ignore[arg-type]
            raise AcmeError("badCSR", "the CSR key must not be the key of the account")
        check_csr(parsed, identifiers_of(order.identifiers))
        lab = await AcmeChallenge.filter(
            authorization__order_id=order.id, lab_validated=True
        ).exists()
        claimed = await AcmeOrder.filter(id=order.id, status=OrderStatus.READY).update(
            status=OrderStatus.PROCESSING
        )
        if not claimed:
            raise AcmeError("orderNotReady", "the order is already being finalized")
        order.status = OrderStatus.PROCESSING
        await order.fetch_related("profile")
        actor = actor_of(account)
        metadata: dict[str, Any] = {
            "acme": {"order_id": str(order.id), "account_id": str(account.id)}
        }
        if lab:
            metadata["insecure_skip_validation"] = True
        try:
            certificate_request = await IssuanceService(self._keystore).submit(
                csr=der,
                profile_name=order.profile.name,
                validity_days=None,
                actor=actor,
                channel=Channel.ACME,
                metadata=metadata,
                force_manual=context.settings.manual_approval,
            )
        except (Unprocessable, ServiceUnavailable) as exc:
            problem = AcmeError("badCSR", exc.detail).document()
            await self._set(order, OrderStatus.INVALID, error=problem)
            await self._audit_finalize(actor, order, None, lab, problem["detail"])
            if isinstance(exc, ServiceUnavailable):
                raise AcmeError("serverInternal", exc.detail, status=503) from None
            raise AcmeError("badCSR", exc.detail) from None
        await AcmeOrder.filter(id=order.id).update(request_id=certificate_request.id)
        order.request_id = certificate_request.id
        await self._audit_finalize(actor, order, certificate_request, lab, None)
        return await self.view(context, order)

    @staticmethod
    async def _audit_finalize(
        actor: str,
        order: AcmeOrder,
        request: CertificateRequest | None,
        lab: bool,
        failure: str | None,
    ) -> None:
        details: dict[str, Any] = {
            "request_id": str(request.id) if request is not None else None,
            "status": request.status.value if request is not None else "refused",
            "insecure_skip_validation": lab,
        }
        if failure is not None:
            details["failure"] = failure
        await AuditLog.record(
            actor=actor,
            action="acme.order.finalize",
            object_type="acme_order",
            object_id=order.id,
            details=details,
        )

    async def certificate_chain(
        self, context: AcmeContext, request: AcmeRequest, order_id: UUID
    ) -> bytes:
        """``application/pem-certificate-chain``: the certificate, then its issuers, no root."""
        order = await self.refresh(await self._owned_order(request, order_id))
        if order.status is not OrderStatus.VALID or order.certificate_id is None:
            raise AcmeError("malformed", "the order has no certificate", status=404)
        certificate = await Certificate.get(id=order.certificate_id)
        chain = [
            c for c in await CertificateService().chain(certificate) if c.issuer_id is not None
        ]
        return b"".join(
            x509.load_der_x509_certificate(c.der).public_bytes(serialization.Encoding.PEM)
            for c in chain
        )


async def account_of_order(order: AcmeOrder) -> AcmeAccount:
    return await AcmeAccount.get(id=order.account_id)
