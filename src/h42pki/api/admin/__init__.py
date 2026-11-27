"""Admin API (``/api/v1``)."""

from fastapi import APIRouter

from h42pki.api.admin import est, routes

router = APIRouter()
router.include_router(routes.router)
router.include_router(est.router)

__all__ = ["router"]
