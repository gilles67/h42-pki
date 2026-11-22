"""Routes served on each listener (ADR-0012): public routes on HTTP, everything on HTTPS.

The launcher marks each request with ``scope["extensions"]["h42pki.listener"]`` (``"http"`` or
``"https"``). On the HTTP listener only the public routes answer; any other path gets a 404
problem explaining that it is only served over HTTPS (no redirect: AIA and, later, CRL and OCSP
must stay plain HTTP, CLAUDE.md section 6.9).

Without the extension (application called directly, e.g. by ``httpx.ASGITransport`` in tests)
every route answers: this mode is meant for tests only, the launcher always sets it.
"""

from starlette.types import ASGIApp, Receive, Scope, Send

from h42pki.api.problems import problem

LISTENER_EXTENSION = "h42pki.listener"

# Public routes, also served over HTTP. /crl/*, /ocsp and /scep join them with their phase.
HTTP_EXACT_ROUTES = frozenset({"/", "/health", "/favicon.ico"})
HTTP_ROUTE_PREFIXES = ("/ca/",)


def listener_of(scope: Scope) -> str | None:
    """``"http"``, ``"https"``, or None when the application is not run by the launcher."""
    extensions = scope.get("extensions") or {}
    listener = extensions.get(LISTENER_EXTENSION)
    return listener if isinstance(listener, str) else None


def served_over_http(path: str) -> bool:
    return path in HTTP_EXACT_ROUTES or path.startswith(HTTP_ROUTE_PREFIXES)


class ListenerRoutesMiddleware:
    """Pure ASGI middleware: refuse non-public routes on the HTTP listener."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] in ("http", "websocket")
            and listener_of(scope) == "http"
            and not served_over_http(scope["path"])
        ):
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            response = problem(
                404,
                "Not Found",
                "this route is only served over HTTPS (the HTTP listener serves /, /health, "
                "/favicon.ico and /ca/* only)",
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)
