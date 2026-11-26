"""OCSP responder ``/ocsp`` (RFC 6960, RFC 5019), on both listeners."""

from h42pki.api.ocsp.routes import router

__all__ = ["router"]
