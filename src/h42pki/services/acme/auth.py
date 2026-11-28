"""Authentication of an ACME POST (RFC 8555 section 6.2), in the order of the RFC.

1. ``Content-Type: application/jose+json`` (415 otherwise);
2. flattened JWS and header rules (``core.acme.jws.parse``);
3. ``url`` equal to the URL of the request (built from ``acme.base_url``, never from ``Host``);
4. nonce consumed (single use);
5. ``jwk`` (new account, revocation by the key of the certificate) or ``kid`` of a valid account;
6. signature.
"""

from dataclasses import dataclass
from typing import Any

from h42pki.core.acme import jws as acme_jws
from h42pki.core.acme.errors import AcmeError
from h42pki.models import AccountStatus, AcmeAccount
from h42pki.services.acme.context import AcmeContext
from h42pki.services.acme.nonces import NonceService

JOSE_JSON = "application/jose+json"


@dataclass(frozen=True)
class AcmeRequest:
    jws: acme_jws.Jws
    account: AcmeAccount | None  # signed with the kid of this account
    jwk: dict[str, Any]  # the key that signed the request (canonical public JWK)
    payload: Any  # None for POST-as-GET

    @property
    def signed_account(self) -> AcmeAccount:
        if self.account is None:  # pragma: no cover - routes that need kid ask for it
            raise AcmeError("malformed", "this request must be signed with kid")
        return self.account


async def authenticate(
    context: AcmeContext,
    body: bytes,
    *,
    content_type: str | None,
    path: str,
    jwk_allowed: bool = False,
    kid_allowed: bool = True,
) -> AcmeRequest:
    media_type = (content_type or "").split(";")[0].strip().lower()
    if media_type != JOSE_JSON:
        raise AcmeError("malformed", f"the Content-Type must be {JOSE_JSON}", status=415)
    parsed = acme_jws.parse(body)
    if parsed.url != context.url(path):
        raise AcmeError("unauthorized", "the url of the JWS is not the URL of the request")
    await NonceService.consume(parsed.nonce)
    if parsed.jwk is not None:
        if not jwk_allowed:
            raise AcmeError("malformed", "this request must be signed with the kid of an account")
        key = acme_jws.public_key(parsed.jwk)
        acme_jws.verify(parsed, key)
        return AcmeRequest(parsed, None, acme_jws.jwk_of(key), parsed.json_payload())
    if not kid_allowed:
        raise AcmeError("malformed", "this request must be signed with a jwk")
    account_id = context.account_id_of(parsed.kid or "")
    account = await AcmeAccount.get_or_none(id=account_id) if account_id is not None else None
    if account is None:
        raise AcmeError("accountDoesNotExist", "no account has this kid")
    if account.status is not AccountStatus.VALID:
        raise AcmeError("unauthorized", f"the account is {account.status.value}")
    acme_jws.verify(parsed, acme_jws.public_key(account.jwk))
    return AcmeRequest(parsed, account, account.jwk, parsed.json_payload())
