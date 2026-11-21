"""Typed business errors.

They carry an HTTP status and title so that the API layer can render them as
``application/problem+json`` (RFC 9457) without this module depending on FastAPI.
Messages must never contain secrets.
"""

from typing import ClassVar


class H42Error(Exception):
    """Base class of business errors."""

    status_code: ClassVar[int] = 500
    title: ClassVar[str] = "Internal Server Error"

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class NotFound(H42Error):
    status_code = 404
    title = "Not Found"


class Conflict(H42Error):
    status_code = 409
    title = "Conflict"


class Unprocessable(H42Error):
    status_code = 422
    title = "Unprocessable Content"


class InvalidRequest(Unprocessable):
    """The request is well-formed but violates a domain rule (base of the core errors)."""


class ServiceUnavailable(H42Error):
    """The service cannot work right now (e.g. no active certificate authority)."""

    status_code = 503
    title = "Service Unavailable"


class NoActiveAuthority(ServiceUnavailable):
    title = "No Active Certificate Authority"
