"""ACME problems (RFC 8555 section 6.7): ``urn:ietf:params:acme:error:<code>``.

Details never contain key material, tokens or nonces.
"""

from dataclasses import dataclass, field
from typing import Any

ERROR_NAMESPACE = "urn:ietf:params:acme:error:"

# Codes of RFC 8555 section 6.7 used by this server, with their HTTP status.
STATUS = {
    "accountDoesNotExist": 400,
    "alreadyRevoked": 400,
    "badCSR": 400,
    "badNonce": 400,
    "badPublicKey": 400,
    "badRevocationReason": 400,
    "badSignatureAlgorithm": 400,
    "connection": 400,
    "dns": 400,
    "incorrectResponse": 400,
    "invalidContact": 400,
    "malformed": 400,
    "orderNotReady": 403,
    "rejectedIdentifier": 400,
    "serverInternal": 500,
    "unauthorized": 403,
    "unsupportedContact": 400,
    "unsupportedIdentifier": 400,
}

# Algorithms announced in badSignatureAlgorithm problems (RFC 8555 section 6.2).
SIGNATURE_ALGORITHMS = ("RS256", "ES256", "ES384", "EdDSA")


@dataclass
class AcmeError(Exception):
    """An ACME problem document; ``status`` defaults to the one of the code."""

    code: str
    detail: str
    status: int | None = None
    subproblems: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.code not in STATUS:
            raise ValueError(f"unknown ACME error code {self.code!r}")
        super().__init__(self.detail)

    @property
    def http_status(self) -> int:
        return self.status or STATUS[self.code]

    def document(self) -> dict[str, Any]:
        problem: dict[str, Any] = {
            "type": ERROR_NAMESPACE + self.code,
            "detail": self.detail,
            "status": self.http_status,
        }
        if self.code == "badSignatureAlgorithm":
            problem["algorithms"] = list(SIGNATURE_ALGORITHMS)
        if self.subproblems:
            problem["subproblems"] = self.subproblems
        return problem
