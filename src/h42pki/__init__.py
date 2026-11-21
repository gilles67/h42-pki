"""h42-pki: containerised certificate authority server."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("h42-pki")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0"
