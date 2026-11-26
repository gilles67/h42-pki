"""Public endpoints, on both listeners: /ca/* (AIA caIssuers, chain), /crl/*, /favicon.ico."""

from fastapi import APIRouter

from h42pki.api.public import crl, favicon, routes

router = APIRouter()
router.include_router(routes.router)
router.include_router(crl.router)
router.include_router(favicon.router)

__all__ = ["router"]
