"""Admin API (``/api/v1``)."""

from fastapi import APIRouter

from h42pki.api.admin import acme, est, routes, scep

router = APIRouter()
router.include_router(routes.router)
router.include_router(est.router)
router.include_router(scep.router)
router.include_router(acme.router)

__all__ = ["router"]
