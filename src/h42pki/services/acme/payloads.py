"""Payloads of ACME requests: RFC 8555 names (camelCase), unknown members ignored (section 7)."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from h42pki.core.acme.errors import AcmeError


class _Payload(BaseModel):
    # RFC 8555 section 7.3 (and others): clients may send fields this server does not know.
    model_config = ConfigDict(extra="ignore", frozen=True)


class NewAccount(_Payload):
    contact: list[str] | None = None
    termsOfServiceAgreed: bool = False  # noqa: N815 - RFC 8555 name
    onlyReturnExisting: bool = False  # noqa: N815
    externalAccountBinding: dict[str, Any] | None = None  # noqa: N815 - lot 6b (ignored)


class AccountUpdate(_Payload):
    contact: list[str] | None = None
    status: Literal["deactivated"] | None = None


class NewOrder(_Payload):
    identifiers: list[Any]
    notBefore: str | None = None  # noqa: N815
    notAfter: str | None = None  # noqa: N815


class AuthorizationUpdate(_Payload):
    status: Literal["deactivated"] | None = None


class Finalize(_Payload):
    csr: str


class RevokeCert(_Payload):
    certificate: str
    reason: int | None = None


def payload[M: _Payload](model: type[M], value: Any) -> M:
    """``value`` (a JSON payload) checked by ``model``; ``malformed`` otherwise, values left out."""
    if not isinstance(value, dict):
        raise AcmeError("malformed", "the payload must be a JSON object")
    try:
        return model.model_validate(value)
    except ValidationError as exc:
        fields = sorted({".".join(str(p) for p in error["loc"]) for error in exc.errors()})
        raise AcmeError("malformed", f"invalid payload: {', '.join(fields)}") from None
