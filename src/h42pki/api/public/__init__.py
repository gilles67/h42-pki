"""Public endpoints, served on both listeners: /ca/* (AIA caIssuers, chain) and /favicon.ico."""

from fastapi import APIRouter

from h42pki.api.public import favicon, routes

router = APIRouter()
router.include_router(routes.router)
router.include_router(favicon.router)

__all__ = ["router"]
