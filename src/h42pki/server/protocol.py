"""Uvicorn HTTP protocol of the launcher: marks each request with its listener (and TLS data).

Subclass of the **internal** ``H11Protocol`` of Uvicorn (hence the pinned version, ADR-0012).
Once the connection is made (after the TLS handshake for HTTPS), the application is wrapped *per
connection* to add ``scope["extensions"]["h42pki.listener"]`` and, over TLS,
``scope["extensions"]["tls"]``.
"""

import asyncio
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any, ClassVar

from uvicorn.protocols.http.h11_impl import H11Protocol

from h42pki.api.listener import LISTENER_EXTENSION
from h42pki.server.tls import tls_extension

type Scope = MutableMapping[str, Any]
type ASGIApplication = Callable[[Scope, Any, Any], Awaitable[None]]


def with_extensions(app: ASGIApplication, extensions: dict[str, Any]) -> ASGIApplication:
    async def wrapped(scope: Scope, receive: Any, send: Any) -> None:
        if scope["type"] in ("http", "websocket"):
            scope = {**scope, "extensions": {**(scope.get("extensions") or {}), **extensions}}
        await app(scope, receive, send)

    return wrapped


class ListenerProtocol(H11Protocol):
    listener: ClassVar[str]

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        extensions: dict[str, Any] = {LISTENER_EXTENSION: self.listener}
        ssl_object = transport.get_extra_info("ssl_object")
        if ssl_object is not None:
            extensions["tls"] = tls_extension(ssl_object)
        self.app = with_extensions(self.app, extensions)


class HttpListenerProtocol(ListenerProtocol):
    listener = "http"


class HttpsListenerProtocol(ListenerProtocol):
    listener = "https"
