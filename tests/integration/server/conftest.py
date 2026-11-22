"""Real launcher on real sockets (free ports), with the test database and a test PKI.

The launcher runs in the test event loop, against the in-memory database opened by the ``client``
fixture. Scenarios U1 to U14 of docs/spikes/2026-11-tls-launcher.md are regression tests of the
protocol, which subclasses an internal class of Uvicorn (pinned version, ADR-0012).
"""

import asyncio
import socket
import ssl
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI, Request
from httpx import AsyncClient

from h42pki.config import Settings
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.keystore import KeyStore
from h42pki.main import create_app
from h42pki.models import Certificate
from h42pki.server.launcher import Launcher
from h42pki.services import settings as settings_module
from h42pki.services.issuance import IssuanceService
from h42pki.services.publication import PublicationService
from tests.conftest import TEST_PASSPHRASE
from tests.x509_helpers import csr_pem, make_csr, name

HOSTNAME = "pki.home42.test"
ALT_NAMES = ["localhost", "127.0.0.1"]
WAIT_SECONDS = 10.0


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


async def wait_for(condition: Callable[[], bool], what: str) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + WAIT_SECONDS
    while not condition():
        if loop.time() > deadline:
            raise AssertionError(f"timeout waiting for {what}")
        await asyncio.sleep(0.02)


def whoami_app(settings: Settings) -> FastAPI:
    """The real application plus a route that shows what it sees of the connection.

    ``/ca/whoami-test`` is under the public prefix, so that it answers on both listeners.
    """
    app = create_app(settings, manage_database=False)

    async def whoami(request: Request) -> dict[str, Any]:
        extensions = request.scope.get("extensions") or {}
        return {
            "scheme": request.url.scheme,
            "listener": extensions.get("h42pki.listener"),
            "tls": extensions.get("tls"),
        }

    app.add_api_route("/ca/whoami-test", whoami, methods=["GET"])
    return app


@dataclass
class Running:
    launcher: Launcher
    settings: Settings
    stop: asyncio.Event
    task: "asyncio.Task[None]"

    def http(self, path: str) -> str:
        return f"http://127.0.0.1:{self.settings.http_port}{path}"

    def https(self, path: str) -> str:
        return f"https://127.0.0.1:{self.settings.https_port}{path}"

    async def wait_https(self) -> None:
        await asyncio.wait_for(self.launcher.https_started.wait(), WAIT_SECONDS)


RunLauncher = Callable[..., Any]


@pytest.fixture(autouse=True)
def fast_cycles(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(settings_module, "SETTINGS_POLL_SECONDS", 0.05)
    # Heartbeat file of this test only.
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))


@pytest.fixture
def server_settings() -> Callable[..., Settings]:
    def make(**overrides: Any) -> Settings:
        values: dict[str, Any] = {
            "environment": "test",
            "database_url": "sqlite://:memory:",
            "ca_passphrase": TEST_PASSPHRASE,
            "server_hostname": HOSTNAME,
            "server_alt_names": ALT_NAMES,
            "http_port": free_port(),
            "https_port": free_port(),
        }
        values.update(overrides)
        return Settings(**values)

    return make


@pytest.fixture
def run_launcher(client: AsyncClient, keystore: KeyStore) -> Callable[..., Any]:
    """``async with run_launcher(settings) as running:`` (database of the ``client`` fixture)."""

    @asynccontextmanager
    async def run(settings: Settings, **options: Any) -> AsyncIterator[Running]:
        options.setdefault("tls_wait_seconds", 0.05)
        options.setdefault("heartbeat_interval", 0.1)
        launcher = Launcher(settings, whoami_app(settings), keystore, **options)
        stop = asyncio.Event()
        task = asyncio.create_task(launcher.run(stop))
        running = Running(launcher, settings, stop, task)
        if settings.http_enabled:
            await wait_for(lambda: "http" in launcher.status.listeners or task.done(), "HTTP")
        if task.done():
            await task  # raise the start-up error
        try:
            yield running
        finally:
            stop.set()
            await asyncio.wait_for(task, WAIT_SECONDS)

    return run


@dataclass
class Pki:
    root_pem: str
    client_cert: Path
    client_key: Path

    def context(self, *, with_client_cert: bool = False) -> ssl.SSLContext:
        context = ssl.create_default_context(cadata=self.root_pem)
        if with_client_cert:
            context.load_cert_chain(self.client_cert, self.client_key)
        return context


async def root_pem() -> str:
    chain = await PublicationService().chain()
    return "".join(
        x509.load_der_x509_certificate(record.der)
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
        for record in chain
    )


@pytest.fixture
def make_pki(
    make_root: Callable[..., Awaitable[Any]],
    keystore: KeyStore,
    key_for: Callable[[KeyAlgorithm], SupportedPrivateKey],
    tmp_path: Path,
) -> Callable[[], Awaitable[Pki]]:
    """Root CA (EC P-256) and a tls_client certificate issued by it, as files for ssl."""

    async def make() -> Pki:
        await make_root()
        key = key_for(KeyAlgorithm.EC_P256)
        request = await IssuanceService(keystore).submit(
            csr=csr_pem(make_csr(key, name(CN="test-client"))),
            profile_name="tls_client",
            validity_days=None,
            actor="anonymous",
        )
        record = await Certificate.get(id=request.certificate_id)
        cert_path = tmp_path / "client.pem"
        key_path = tmp_path / "client.key"
        cert_path.write_bytes(
            x509.load_der_x509_certificate(record.der).public_bytes(serialization.Encoding.PEM)
        )
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),  # test key, temporary file of this test only
            )
        )
        return Pki(await root_pem(), cert_path, key_path)

    return make
