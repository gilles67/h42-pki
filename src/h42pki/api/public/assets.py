"""Static files shipped in the package (``h42pki/static``), read once at import time."""

import hashlib
from dataclasses import dataclass
from importlib import resources

STATIC_PACKAGE = "h42pki"
STATIC_DIRECTORY = "static"


@dataclass(frozen=True, repr=False)
class StaticAsset:
    body: bytes
    media_type: str
    etag: str

    def __repr__(self) -> str:
        return f"StaticAsset({self.media_type}, {len(self.body)} bytes, etag={self.etag})"


def load_asset(name: str, media_type: str) -> StaticAsset:
    """Read ``h42pki/static/<name>`` through importlib.resources (works from a wheel as well)."""
    body = resources.files(STATIC_PACKAGE).joinpath(STATIC_DIRECTORY, name).read_bytes()
    return StaticAsset(body, media_type, f'"{hashlib.sha256(body).hexdigest()}"')


# Loaded at start-up (import of the application), never read from disk per request.
FAVICON = load_asset("favicon.ico", "image/x-icon")
