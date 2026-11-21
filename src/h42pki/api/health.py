"""Service metadata and the liveness endpoint used by the container healthcheck."""

from fastapi import APIRouter

from h42pki import __version__

router = APIRouter(tags=["health"])


@router.get("/")
async def index() -> dict[str, str]:
    return {"name": "h42-pki", "version": __version__}


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
