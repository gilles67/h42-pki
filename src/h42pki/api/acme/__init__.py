"""ACME routes (RFC 8555, ADR-0020)."""

from h42pki.api.acme.routes import acme_error_handler, router

__all__ = ["acme_error_handler", "router"]
