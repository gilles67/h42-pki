"""Federation API (``/api/v1/federation``), HTTPS only like the rest of ``/api/v1``."""

from h42pki.api.federation.routes import router

__all__ = ["router"]
