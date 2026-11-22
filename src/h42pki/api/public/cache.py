"""HTTP caching of public responses: ``ETag`` / ``If-None-Match`` → 304, ``Cache-Control``."""

from datetime import UTC, datetime
from email.utils import format_datetime

from fastapi import Request, Response

# Published CA certificates may change with a rollover: one hour.
DEFAULT_CACHE_CONTROL = "public, max-age=3600"


def etag_matches(request: Request, etag: str) -> bool:
    header = request.headers.get("if-none-match")
    if header is None:
        return False
    candidates = {candidate.strip().removeprefix("W/") for candidate in header.split(",")}
    return "*" in candidates or etag in candidates


def cacheable(
    request: Request,
    *,
    body: bytes,
    media_type: str,
    etag: str,
    last_modified: datetime | None = None,
    cache_control: str = DEFAULT_CACHE_CONTROL,
) -> Response:
    """``body`` with its cache headers, or an empty 304 when the client already has it."""
    headers = {"ETag": etag, "Cache-Control": cache_control}
    if last_modified is not None:
        # Tortoise returns ZoneInfo("UTC") datetimes; format_datetime(usegmt) wants datetime.UTC.
        headers["Last-Modified"] = format_datetime(last_modified.astimezone(UTC), usegmt=True)
    if etag_matches(request, etag):
        return Response(status_code=304, headers=headers)
    return Response(content=body, media_type=media_type, headers=headers)
