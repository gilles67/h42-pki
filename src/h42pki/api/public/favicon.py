"""``GET /favicon.ico``: public, on both listeners, hidden from the OpenAPI."""

from fastapi import APIRouter, Request, Response

from h42pki.api.public.assets import FAVICON
from h42pki.api.public.cache import cacheable

# The favicon only changes with a release: one day.
FAVICON_CACHE_CONTROL = "public, max-age=86400"

router = APIRouter(tags=["public"])


@router.get("/favicon.ico", response_class=Response, include_in_schema=False)
async def favicon(request: Request) -> Response:
    return cacheable(
        request,
        body=FAVICON.body,
        media_type=FAVICON.media_type,
        etag=FAVICON.etag,
        cache_control=FAVICON_CACHE_CONTROL,
    )
