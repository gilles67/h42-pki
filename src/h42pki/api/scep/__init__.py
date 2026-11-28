"""SCEP (RFC 8894): ``/scep``, HTTP and HTTPS, disabled by default (ADR-0018, ADR-0019)."""

from h42pki.api.scep.routes import ScepHttpError, router, scep_error_handler

__all__ = ["ScepHttpError", "router", "scep_error_handler"]
