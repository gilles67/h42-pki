"""The launcher: one process, one event loop, up to two Uvicorn servers on the same application.

- **HTTP** (``H42_PKI_HTTP_*``) starts at once and serves the public routes only.
- **HTTPS** (``H42_PKI_HTTPS_*``) starts as soon as the local CA is active and has issued the
  ``service_tls`` certificate of this server (ADR-0013); it waits otherwise, without restart.
- A renewed certificate is reloaded into the same ``SSLContext`` (new connections get it).
- A ``listener`` level setting restarts only the listeners it concerns; ``logging.level`` is
  applied hot; a ``tls_service`` change triggers a certificate check.
- Idle mode: no listener at all; the settings watcher, the scheduled tasks and the heartbeat
  keep running and the CLI stays usable (``podman exec``).

Signals are handled by the caller (``h42pki serve``), not by Uvicorn: the embedded servers do not
install handlers, the launcher stops them all.
"""

import asyncio
import contextlib
import logging
import ssl
from collections.abc import Coroutine, Generator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import uvicorn
from fastapi import FastAPI

from h42pki.config import Settings
from h42pki.core.settings_schema import SETTINGS, ApplyLevel, RuntimeSettings, value_of
from h42pki.heartbeat import (
    HEARTBEAT_INTERVAL_SECONDS,
    heartbeat_path,
    remove_heartbeat,
    write_heartbeat,
)
from h42pki.keystore import KeyStore
from h42pki.logs import set_log_level
from h42pki.models import Certificate
from h42pki.server.protocol import HttpListenerProtocol, HttpsListenerProtocol
from h42pki.server.ssl_context import build_context, load_certificate
from h42pki.services.authority import AuthorityService
from h42pki.services.settings import SettingsWatcher
from h42pki.services.tls_service import TlsMaterial, TlsServiceManager
from h42pki.tasks.tls_service import TlsRenewalTask

log = logging.getLogger(__name__)

ListenerName = Literal["http", "https"]

# How often the launcher looks for an active CA before opening HTTPS.
TLS_WAIT_SECONDS = 5.0
# Graceful shutdown of a listener (restart or stop): open connections get this long.
GRACEFUL_SHUTDOWN_SECONDS = 5
STARTUP_TIMEOUT_SECONDS = 10.0


class ListenerError(RuntimeError):
    """A listener could not start (port in use, invalid TLS settings)."""


class EmbeddedServer(uvicorn.Server):
    """Uvicorn server that leaves signal handling to the launcher."""

    @contextlib.contextmanager
    def capture_signals(self) -> Generator[None]:
        yield


@dataclass
class LauncherStatus:
    """What ``GET /health`` reports about the launcher (statuses only, never a secret)."""

    listeners: set[str] = field(default_factory=set)
    https_waiting: bool = False
    https_certificate_serial: str | None = None
    https_certificate_not_after: datetime | None = None
    renewal_failing: bool = False
    heartbeat_path: Path | None = None


def changed_listeners(previous: RuntimeSettings, current: RuntimeSettings) -> set[str]:
    """Listeners to restart after a settings change (``listener`` level settings)."""
    listeners: set[str] = set()
    for key, info in SETTINGS.items():
        if info.apply is ApplyLevel.LISTENER and value_of(previous, key) != value_of(current, key):
            listeners.update(info.listeners)
    return listeners


class Launcher:
    def __init__(
        self,
        settings: Settings,
        app: FastAPI,
        keystore: KeyStore,
        *,
        watcher: SettingsWatcher | None = None,
        tls_wait_seconds: float | None = None,
        heartbeat_interval: float | None = None,
        renewal_interval: float | None = None,
    ) -> None:
        self._settings = settings
        self._app = app
        self._watcher = watcher or SettingsWatcher()
        self._tls_wait = TLS_WAIT_SECONDS if tls_wait_seconds is None else tls_wait_seconds
        self._beat_interval = (
            HEARTBEAT_INTERVAL_SECONDS if heartbeat_interval is None else heartbeat_interval
        )
        self.status = LauncherStatus(heartbeat_path=heartbeat_path(settings.database_url))
        app.state.launcher = self.status
        self._servers: dict[str, EmbeddedServer] = {}
        self._server_tasks: dict[str, asyncio.Task[None]] = {}
        self._lock = asyncio.Lock()
        self._context: ssl.SSLContext | None = None
        self._material: TlsMaterial | None = None
        self._manager: TlsServiceManager | None = None
        self._renewal: TlsRenewalTask | None = None
        if settings.https_enabled:
            self._manager = TlsServiceManager(keystore, settings.server_names)
            self._renewal = TlsRenewalTask(
                self._manager, self._certificate_renewed, interval=renewal_interval
            )
        self.https_started = asyncio.Event()

    # --- main loop ------------------------------------------------------------------------

    async def run(self, stop: asyncio.Event) -> None:
        """Serve until ``stop`` is set, then stop every listener and task."""
        await self._watcher.load()
        self._watcher.subscribe(self._settings_changed)
        await self._warn_at_start()
        tasks = [
            self._spawn(self._watcher.run(stop), "settings-watcher"),
            self._spawn(self._beat(stop), "heartbeat"),
        ]
        try:
            if self._settings.http_enabled:
                await self._start("http")
            if self._settings.https_enabled:
                tasks.append(self._spawn(self._https_supervisor(stop), "https-supervisor"))
            if not (self._settings.http_enabled or self._settings.https_enabled):
                log.warning(
                    "idle mode: H42_PKI_HTTP_ENABLED and H42_PKI_HTTPS_ENABLED are both false, "
                    "nothing is served on the network; scheduled tasks keep running and the CLI "
                    "is available (podman exec ... h42pki ...)"
                )
            await stop.wait()
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            async with self._lock:
                for name in list(self._servers):
                    await self._stop(name)
            if self.status.heartbeat_path is not None:
                remove_heartbeat(self.status.heartbeat_path)
            log.info("launcher stopped")

    @staticmethod
    def _spawn(coroutine: Coroutine[Any, Any, None], name: str) -> asyncio.Task[None]:
        return asyncio.create_task(coroutine, name=f"h42pki-{name}")

    @staticmethod
    async def _sleep(stop: asyncio.Event, seconds: float) -> bool:
        """Wait ``seconds``; True if ``stop`` was set meanwhile."""
        try:
            await asyncio.wait_for(stop.wait(), timeout=seconds)
        except TimeoutError:
            return False
        return True

    async def _beat(self, stop: asyncio.Event) -> None:
        path = self.status.heartbeat_path
        if path is None:  # pragma: no cover - always set
            return
        while True:
            try:
                await asyncio.to_thread(write_heartbeat, path)
            except OSError as exc:
                log.warning("cannot write the heartbeat file %s: %s", path, exc.strerror)
            if await self._sleep(stop, self._beat_interval):
                return

    async def _warn_at_start(self) -> None:
        settings = self._settings
        if settings.https_enabled and not settings.http_enabled:
            log.warning(
                "HTTP is disabled while HTTPS is enabled: clients that check revocation or fetch "
                "the CA certificate over HTTPS may loop (CLAUDE.md section 6.9)"
            )
        if not settings.http_enabled:
            authority = await AuthorityService().find_local()
            url = authority.public_base_url if authority is not None else None
            if url is not None and url.startswith("http://"):
                log.warning(
                    "HTTP is disabled but the public base URL %s is http://: the AIA URLs written "
                    "in issued certificates cannot be reached",
                    url,
                )

    # --- HTTPS certificate ----------------------------------------------------------------

    async def _https_supervisor(self, stop: asyncio.Event) -> None:
        """Open HTTPS once the certificate exists, then keep it renewed."""
        manager, renewal = self._manager, self._renewal
        if manager is None or renewal is None:  # pragma: no cover - set with https_enabled
            return
        certificate: Certificate | None = None
        waiting_logged = False
        self.status.https_waiting = True
        while certificate is None:
            result = await renewal.check()
            certificate = result.certificate if result is not None else None
            self.status.renewal_failing = renewal.state.failing
            if certificate is not None:
                break
            if not waiting_logged and result is not None:
                log.warning(
                    "HTTPS waits for an active CA (run `h42pki authority init`); only HTTP is "
                    "served meanwhile"
                )
                waiting_logged = True
            if await self._sleep(stop, self._tls_wait):
                return
        self._material = await manager.material(certificate)
        self._set_certificate_status()
        async with self._lock:
            await self._start("https")
        self.status.https_waiting = False
        self.https_started.set()
        await renewal.run(stop)

    async def _certificate_renewed(self, certificate: Certificate) -> None:
        """Hot reload: same SSLContext, new certificate for new connections."""
        if self._manager is None:  # pragma: no cover
            return
        material = await self._manager.material(certificate)
        if self._context is not None:
            await asyncio.to_thread(load_certificate, self._context, material)
            log.info("HTTPS certificate reloaded (serial %s)", material.serial_hex)
        self._material = material
        self._set_certificate_status()

    def _set_certificate_status(self) -> None:
        if self._material is not None:
            self.status.https_certificate_serial = self._material.serial_hex
            self.status.https_certificate_not_after = self._material.not_after
        if self._renewal is not None:
            self.status.renewal_failing = self._renewal.state.failing

    # --- settings -------------------------------------------------------------------------

    async def _settings_changed(self, previous: RuntimeSettings, current: RuntimeSettings) -> None:
        if previous.logging.level != current.logging.level:
            set_log_level(current.logging.level)
            log.info("log level set to %s", current.logging.level)
        if previous.tls_service != current.tls_service and self._renewal is not None:
            self._renewal.check_soon()
        for name in sorted(changed_listeners(previous, current)):
            async with self._lock:
                if name in self._servers:
                    await self._restart(name)

    # --- listeners ------------------------------------------------------------------------

    def _config(self, name: ListenerName) -> tuple[uvicorn.Config, ssl.SSLContext | None]:
        """Uvicorn configuration of a listener, and its new SSLContext for HTTPS."""
        runtime = self._watcher.current.server
        options: dict[str, Any] = {
            "host": self._settings.bind_address,
            "port": self._settings.http_port if name == "http" else self._settings.https_port,
            "http": HttpListenerProtocol if name == "http" else HttpsListenerProtocol,
            "lifespan": "off",  # the launcher owns the database and the tasks
            "log_config": None,  # logging configured by h42pki.logs
            "proxy_headers": False,  # the peer address is the TCP peer (trusted proxies)
            "server_header": False,
            "timeout_graceful_shutdown": GRACEFUL_SHUTDOWN_SECONDS,
        }
        if runtime.keep_alive_timeout is not None:
            options["timeout_keep_alive"] = runtime.keep_alive_timeout
        if runtime.limit_concurrency is not None:
            options["limit_concurrency"] = runtime.limit_concurrency
        if runtime.backlog is not None:
            options["backlog"] = runtime.backlog
        if runtime.max_header_size is not None:
            options["h11_max_incomplete_event_size"] = runtime.max_header_size
        context: ssl.SSLContext | None = None
        if name == "https":
            if self._material is None:  # pragma: no cover - checked by the supervisor
                raise ListenerError("no HTTPS certificate yet")
            context = build_context(self._material, runtime)
            options["ssl_context_factory"] = lambda _config, _default: context
        return uvicorn.Config(self._app, **options), context

    async def _prepare(self, name: ListenerName) -> tuple[uvicorn.Config, ssl.SSLContext | None]:
        try:
            return await asyncio.to_thread(self._config, name)
        except (ssl.SSLError, ValueError) as exc:
            raise ListenerError(f"cannot configure the {name.upper()} listener: {exc}") from None

    async def _start(
        self,
        name: ListenerName,
        prepared: tuple[uvicorn.Config, ssl.SSLContext | None] | None = None,
    ) -> None:
        config, context = prepared if prepared is not None else await self._prepare(name)
        server = EmbeddedServer(config)
        task = self._spawn(self._serve(name, server), f"{name}-listener")
        deadline = asyncio.get_running_loop().time() + STARTUP_TIMEOUT_SECONDS
        while not server.started and not task.done():
            if asyncio.get_running_loop().time() > deadline:
                server.should_exit = True
                break
            await asyncio.sleep(0.01)
        if not server.started:
            await asyncio.gather(task, return_exceptions=True)
            raise ListenerError(
                f"the {name.upper()} listener cannot listen on "
                f"{config.host}:{config.port} (see the log)"
            )
        if context is not None:
            self._context = context
        self._servers[name] = server
        self._server_tasks[name] = task
        self.status.listeners.add(name)
        log.warning("%s listening on %s:%d", name.upper(), config.host, config.port)

    async def _serve(self, name: str, server: EmbeddedServer) -> None:
        try:
            await server.serve()
        except SystemExit:  # Uvicorn exits the process when it cannot bind
            log.error("the %s listener stopped: cannot listen", name.upper())

    async def _stop(self, name: str) -> None:
        server = self._servers.pop(name, None)
        task = self._server_tasks.pop(name, None)
        self.status.listeners.discard(name)
        if server is None or task is None:
            return
        server.should_exit = True
        await asyncio.gather(task, return_exceptions=True)

    async def _restart(self, name: str) -> None:
        """Restart one listener with the current settings; the old one stays if they fail."""
        listener: ListenerName = "https" if name == "https" else "http"
        try:
            prepared = await self._prepare(listener)  # validated before stopping the old one
        except ListenerError as exc:
            log.error("%s listener not restarted: %s", name.upper(), exc)
            return
        log.warning("restarting the %s listener (settings changed)", name.upper())
        await self._stop(name)
        try:
            await self._start(listener, prepared)
        except ListenerError as exc:
            log.error("%s", exc)
