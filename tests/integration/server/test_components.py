"""Parts of the launcher: Client-Cert from trusted proxies, renewal task, health, SSL context."""

import base64
import ipaddress
import ssl
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import time_machine
from asgi_lifespan import LifespanManager
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from starlette.requests import Request

from h42pki.api.client_cert import client_certificate, parse_client_cert_header
from h42pki.cli.health import check
from h42pki.config import Settings
from h42pki.core.settings_schema import RuntimeSettings, ServerSettings
from h42pki.db import with_pool_size
from h42pki.errors import NoActiveAuthority
from h42pki.heartbeat import heartbeat_age, heartbeat_path, read_heartbeat, write_heartbeat
from h42pki.keystore import KeyStore
from h42pki.main import create_app
from h42pki.models import Certificate
from h42pki.server.launcher import LauncherStatus, changed_listeners
from h42pki.server.ssl_context import build_context
from h42pki.services.tls_service import EnsureResult, TlsServiceManager
from h42pki.tasks.tls_service import TlsRenewalTask
from tests.integration.server.conftest import ALT_NAMES, HOSTNAME, Pki

NAMES = [HOSTNAME, *ALT_NAMES]
PROXIES = [ipaddress.ip_network("10.0.0.0/8")]


# --- client certificate ------------------------------------------------------------------


def _request(peer: str, *, header: str | None = None, tls: dict[str, Any] | None = None) -> Request:
    headers = [(b"client-cert", header.encode())] if header is not None else []
    scope: dict[str, Any] = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": headers,
        "client": (peer, 40000),
        "extensions": {"tls": tls} if tls is not None else {},
    }
    return Request(scope)


async def _client_pem(make_pki: Callable[[], Awaitable[Pki]]) -> tuple[str, x509.Certificate]:
    pki = await make_pki()
    pem = pki.client_cert.read_text()
    return pem, x509.load_pem_x509_certificate(pem.encode())


def _header(certificate: x509.Certificate) -> str:
    der = certificate.public_bytes(serialization.Encoding.DER)
    return f":{base64.b64encode(der).decode()}:"


async def test_client_certificate_from_the_tls_connection(
    make_pki: Callable[[], Awaitable[Pki]],
) -> None:
    pem, certificate = await _client_pem(make_pki)
    request = _request("192.0.2.1", tls={"client_cert_chain": [pem]})

    assert client_certificate(request, []) == certificate


async def test_client_cert_header_ignored_without_trusted_proxies(
    make_pki: Callable[[], Awaitable[Pki]],
) -> None:
    _, certificate = await _client_pem(make_pki)

    assert client_certificate(_request("10.1.2.3", header=_header(certificate)), []) is None


async def test_client_cert_header_ignored_from_an_unlisted_address(
    make_pki: Callable[[], Awaitable[Pki]],
) -> None:
    _, certificate = await _client_pem(make_pki)
    request = _request("192.0.2.1", header=_header(certificate))

    assert client_certificate(request, PROXIES) is None


async def test_client_cert_header_accepted_from_a_trusted_proxy(
    make_pki: Callable[[], Awaitable[Pki]],
) -> None:
    _, certificate = await _client_pem(make_pki)
    request = _request("10.1.2.3", header=_header(certificate))

    assert client_certificate(request, PROXIES) == certificate


async def test_tls_connection_wins_over_the_header(
    make_pki: Callable[[], Awaitable[Pki]],
) -> None:
    pem, certificate = await _client_pem(make_pki)
    request = _request("10.1.2.3", header=":AAAA:", tls={"client_cert_chain": [pem]})

    assert client_certificate(request, PROXIES) == certificate


@pytest.mark.parametrize("value", ["", "AAAA", ":not base64!:", ":AAAA:", "::"])
def test_invalid_client_cert_header(value: str) -> None:
    assert parse_client_cert_header(value) is None
    assert client_certificate(_request("10.1.2.3", header=value), PROXIES) is None


def test_no_header_no_tls() -> None:
    assert client_certificate(_request("10.1.2.3"), PROXIES) is None
    assert client_certificate(_request("not-an-ip"), PROXIES) is None


# --- renewal task ------------------------------------------------------------------------


class FlakyManager:
    """Fails ``failures`` times, then issues a certificate."""

    def __init__(self, real: TlsServiceManager, failures: int) -> None:
        self.real = real
        self.failures = failures

    async def ensure(self) -> EnsureResult:
        if self.failures:
            self.failures -= 1
            raise NoActiveAuthority("the certificate of the local CA has expired")
        return await self.real.ensure()


async def test_renewal_failure_is_retried(
    make_pki: Callable[[], Awaitable[Pki]],
    keystore: KeyStore,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await make_pki()
    renewed: list[Certificate] = []

    async def on_certificate(certificate: Certificate) -> None:
        renewed.append(certificate)

    manager = FlakyManager(TlsServiceManager(keystore, NAMES), failures=1)
    task = TlsRenewalTask(manager, on_certificate)  # type: ignore[arg-type]

    assert await task.check() is None
    assert task.state.failing
    assert task.state.last_error == "the certificate of the local CA has expired"
    assert "renewal of the HTTPS server certificate failed" in caplog.text
    assert "next attempt in 24 h" in caplog.text

    result = await task.check()  # the next day

    assert result is not None and result.issued
    assert not task.state.failing and task.state.last_error is None
    assert len(renewed) == 1


async def test_renewal_at_15_days(
    make_pki: Callable[[], Awaitable[Pki]], keystore: KeyStore
) -> None:
    await make_pki()
    renewed: list[Certificate] = []

    async def on_certificate(certificate: Certificate) -> None:
        renewed.append(certificate)

    manager = TlsServiceManager(keystore, NAMES)
    task = TlsRenewalTask(manager, on_certificate)
    first = await task.check()
    assert first is not None and first.certificate is not None
    not_after = first.certificate.not_after

    with time_machine.travel(not_after - timedelta(days=16), tick=False):
        assert (await task.check()) is not None
    assert len(renewed) == 1  # issued at the first check only
    with time_machine.travel(not_after - timedelta(days=15), tick=False):
        result = await task.check()

    assert result is not None and result.issued
    assert len(renewed) == 2
    assert renewed[1].serial_hex != renewed[0].serial_hex


async def test_renewal_task_wakes_up_on_demand(
    make_pki: Callable[[], Awaitable[Pki]], keystore: KeyStore
) -> None:
    import asyncio

    await make_pki()
    checks: list[object] = []

    async def on_certificate(certificate: Certificate) -> None:
        checks.append(certificate)

    task = TlsRenewalTask(TlsServiceManager(keystore, NAMES), on_certificate, interval=3600)
    stop = asyncio.Event()
    runner = asyncio.create_task(task.run(stop))
    task.check_soon()
    for _ in range(200):
        if checks:
            break
        await asyncio.sleep(0.01)
    stop.set()
    await runner

    assert len(checks) == 1
    assert task.interval == 3600


# --- health ------------------------------------------------------------------------------


@pytest.fixture
async def app_client(settings: Settings) -> AsyncIterator[tuple[FastAPI, AsyncClient]]:
    app = create_app(settings)
    async with (
        LifespanManager(app),
        AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as http,
    ):
        yield app, http


async def test_health_reports_a_failing_renewal(
    app_client: tuple[FastAPI, AsyncClient], tmp_path: Path
) -> None:
    app, client = app_client
    beat = tmp_path / "beat"
    write_heartbeat(beat)
    app.state.launcher = LauncherStatus(
        listeners={"http", "https"},
        https_certificate_serial="01",
        https_certificate_not_after=datetime(2027, 1, 8, tzinfo=UTC),
        renewal_failing=True,
        heartbeat_path=beat,
    )

    body = (await client.get("/health")).json()

    assert body["status"] == "degraded"
    assert body["https_certificate"] == {"not_after": "2027-01-08T00:00:00Z", "renewal": "failing"}
    assert body["warnings"] == ["the renewal of the HTTPS certificate is failing"]
    assert body["heartbeat_age_seconds"] is not None
    assert "serial" not in str(body)


async def test_health_without_heartbeat(
    app_client: tuple[FastAPI, AsyncClient], tmp_path: Path
) -> None:
    app, client = app_client
    app.state.launcher = LauncherStatus(heartbeat_path=tmp_path / "missing")

    body = (await client.get("/health")).json()

    assert body["https"] == "disabled"
    assert "no recent heartbeat of the launcher" in body["warnings"]


# --- heartbeat and healthcheck -----------------------------------------------------------


def test_heartbeat_file(tmp_path: Path) -> None:
    path = tmp_path / "beat"
    now = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)

    assert heartbeat_age(path) is None
    write_heartbeat(path, now)

    assert read_heartbeat(path) == now
    assert heartbeat_age(path, now + timedelta(seconds=12)) == 12
    assert list(tmp_path.iterdir()) == [path]  # no temporary file left
    path.write_text("garbage")
    assert read_heartbeat(path) is None


def test_heartbeat_path_depends_on_the_database(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tempfile, "tempdir", "/tmp-test")  # noqa: S108 - not created

    first = heartbeat_path("sqlite:///data/a.sqlite3")

    assert first == heartbeat_path("sqlite:///data/a.sqlite3")
    assert first != heartbeat_path("sqlite:///data/b.sqlite3")
    assert first.parent == Path("/tmp-test")  # noqa: S108


def _settings(tmp_path: Path) -> Settings:
    return Settings(database_url=f"sqlite://{(tmp_path / 'h.sqlite3').as_posix()}")


def test_healthcheck(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    settings = _settings(tmp_path)
    path = heartbeat_path(settings.database_url)

    assert check(settings) == (
        False,
        "unhealthy: no heartbeat, the launcher (h42pki serve) is not running",
    )
    write_heartbeat(path)
    healthy, message = check(settings)
    assert healthy and message.startswith("healthy: database answers")
    write_heartbeat(path, datetime.now(UTC) - timedelta(seconds=90))
    healthy, message = check(settings)
    assert not healthy and "heartbeat is 90 s old (limit 60 s)" in message


def test_healthcheck_database_unreachable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    settings = Settings(database_url=f"sqlite://{(tmp_path / 'missing' / 'db').as_posix()}")
    write_heartbeat(heartbeat_path(settings.database_url))

    assert check(settings) == (False, "unhealthy: the database does not answer")


# --- SSL context and settings ------------------------------------------------------------


async def test_ssl_context_leaves_no_file(
    make_pki: Callable[[], Awaitable[Pki]],
    keystore: KeyStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await make_pki()
    manager = TlsServiceManager(keystore, NAMES)
    record = (await manager.ensure()).certificate
    assert record is not None
    material = await manager.material(record)
    private_tmp = tmp_path / "tmp"
    private_tmp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(private_tmp))

    context = build_context(material, ServerSettings(tls_min_version="tls1.3"))

    assert list(private_tmp.iterdir()) == []  # temporary directory removed at once
    assert context.minimum_version is ssl.TLSVersion.TLSv1_3
    assert context.verify_mode is ssl.CERT_OPTIONAL
    assert len(context.get_ca_certs()) == 1  # the local CA chain


async def test_ssl_context_extra_trust_anchors_and_ciphers(
    make_pki: Callable[[], Awaitable[Pki]], keystore: KeyStore
) -> None:
    pki = await make_pki()
    manager = TlsServiceManager(keystore, NAMES)
    record = (await manager.ensure()).certificate
    assert record is not None
    material = await manager.material(record)
    server = ServerSettings(client_trust_anchors=[pki.root_pem], tls_ciphers="ECDHE+AESGCM")

    context = build_context(material, server)

    assert len(context.get_ca_certs()) == 1  # same anchor twice: one entry
    with pytest.raises(ssl.SSLError):
        build_context(material, ServerSettings(tls_ciphers="NOT-A-CIPHER"))


def test_changed_listeners() -> None:
    base = RuntimeSettings()

    def with_server(**values: Any) -> RuntimeSettings:
        return base.model_copy(update={"server": base.server.model_copy(update=values)})

    assert changed_listeners(base, base) == set()
    assert changed_listeners(base, with_server(tls_min_version="tls1.3")) == {"https"}
    assert changed_listeners(base, with_server(backlog=10)) == {"http", "https"}
    hot = base.model_copy(update={"logging": base.logging.model_copy(update={"level": "debug"})})
    assert changed_listeners(base, hot) == set()


@pytest.mark.parametrize(
    ("url", "size", "expected"),
    [
        ("sqlite://data/h.sqlite3", 5, "sqlite://data/h.sqlite3"),
        ("postgres://u@db:5432/pki", None, "postgres://u@db:5432/pki"),
        ("postgres://u@db:5432/pki", 5, "postgres://u@db:5432/pki?maxsize=5"),
        ("postgres://u@db/pki?ssl=true&maxsize=2", 8, "postgres://u@db/pki?ssl=true&maxsize=8"),
    ],
)
def test_pool_size(url: str, size: int | None, expected: str) -> None:
    assert with_pool_size(url, size) == expected
