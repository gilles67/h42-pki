"""Scenarios U1 to U13 of docs/spikes/2026-11-tls-launcher.md on the real launcher, and more.

U14 (SIGTERM) needs a separate process: test_process.py.
"""

import asyncio
import socket
import ssl
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from h42pki.config import Settings
from h42pki.services.settings import SettingsService
from tests.integration.server.conftest import Pki, wait_for

PkiFactory = Callable[[], Awaitable[Pki]]
SettingsFactory = Callable[..., Settings]


def _peer_serial(port: int, context: ssl.SSLContext) -> int:
    with (
        socket.create_connection(("127.0.0.1", port), timeout=5) as raw,
        context.wrap_socket(raw, server_hostname="127.0.0.1") as tls,
    ):
        der = tls.getpeercert(binary_form=True)
        assert der is not None
        return x509.load_der_x509_certificate(der).serial_number


async def peer_serial(port: int, context: ssl.SSLContext) -> int:
    return await asyncio.to_thread(_peer_serial, port, context)


def _connect_refused(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return False
    except OSError:
        return True


def _open_tls(port: int, context: ssl.SSLContext) -> ssl.SSLSocket:
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    return context.wrap_socket(raw, server_hostname="127.0.0.1")


def _keep_alive_get(tls: ssl.SSLSocket, path: str) -> int:
    """One HTTP/1.1 request on an open connection; returns the status code."""
    tls.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".encode("ascii"))
    data = b""
    while b"\r\n\r\n" not in data:
        data += tls.recv(4096)
    head, _, body = data.partition(b"\r\n\r\n")
    length = next(
        int(line.split(b":", 1)[1])
        for line in head.split(b"\r\n")
        if line.lower().startswith(b"content-length:")
    )
    while len(body) < length:
        body += tls.recv(4096)
    return int(head.split(b" ", 2)[1])


async def get(url: str, *, verify: ssl.SSLContext | bool = True) -> httpx.Response:
    async with httpx.AsyncClient(verify=verify, timeout=5) as http:
        return await http.get(url)


def _unknown_ca_client(tmp_dir: Any) -> tuple[str, str]:
    """A client certificate from a CA the server does not trust."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unknown CA")])
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "intruder")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(ca_key, hashes.SHA256())
    )
    cert_path, key_path = tmp_dir / "intruder.pem", tmp_dir / "intruder.key"
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


# --- U1 to U4: start-up and HTTP ------------------------------------------------------------


async def test_u1_u2_http_alone_before_any_certificate(
    run_launcher: Any, server_settings: SettingsFactory
) -> None:
    async with run_launcher(server_settings()) as running:
        response = await get(running.http("/"))

        assert response.status_code == 200  # U1
        assert running.launcher.status.listeners == {"http"}
        assert await asyncio.to_thread(_connect_refused, running.settings.https_port)  # U2
        assert running.launcher.status.https_waiting
        health = (await get(running.http("/health"))).json()
        assert (health["https"], health["authority"]) == ("waiting", "none")


async def test_u3_https_opens_once_the_ca_is_active(
    run_launcher: Any, server_settings: SettingsFactory, make_pki: PkiFactory
) -> None:
    async with run_launcher(server_settings()) as running:
        assert not running.launcher.https_started.is_set()

        pki = await make_pki()  # authority init, as `h42pki authority init` does
        await running.wait_https()

        response = await get(running.https("/health"), verify=pki.context())
        assert response.status_code == 200
        body = response.json()
        assert body["listeners"] == ["http", "https"]
        assert body["https"] == "serving"
        assert body["https_certificate"]["renewal"] == "ok"


async def test_u4_http_has_no_tls_extension(
    run_launcher: Any, server_settings: SettingsFactory
) -> None:
    async with run_launcher(server_settings()) as running:
        seen = (await get(running.http("/ca/whoami-test"))).json()

    assert seen == {"scheme": "http", "listener": "http", "tls": None}


# --- U5, U6 and the route split ----------------------------------------------------------


async def test_u5_u6_route_split(
    run_launcher: Any, server_settings: SettingsFactory, make_pki: PkiFactory
) -> None:
    pki = await make_pki()
    async with run_launcher(server_settings()) as running:
        await running.wait_https()
        context = pki.context()

        refused = await get(running.http("/api/v1/authority"))  # U5
        served = await get(running.https("/api/v1/authority"), verify=context)  # U6

        assert refused.status_code == 404
        assert refused.headers["content-type"] == "application/problem+json"
        assert "only served over HTTPS" in refused.json()["detail"]
        assert served.status_code == 200
        assert served.json()["name"] == "test-root"
        for path in ("/docs", "/openapi.json", "/api/v1/config", "/api/v1/profiles"):
            assert (await get(running.http(path))).status_code == 404, path
            assert (await get(running.https(path), verify=context)).status_code == 200, path
        public = ("/", "/health", "/favicon.ico", "/ca/test-root.crt", "/ca/test-root.pem")
        for path in (*public, "/ca/chain.pem"):
            assert (await get(running.http(path))).status_code == 200, path
            assert (await get(running.https(path), verify=context)).status_code == 200, path
        # No redirect to HTTPS: AIA must stay plain HTTP (CLAUDE.md section 6.9).
        assert "location" not in refused.headers


# --- U7 to U10: optional mTLS -------------------------------------------------------------


async def test_u7_https_without_client_certificate(
    run_launcher: Any, server_settings: SettingsFactory, make_pki: PkiFactory
) -> None:
    pki = await make_pki()
    async with run_launcher(server_settings()) as running:
        await running.wait_https()
        seen = (await get(running.https("/ca/whoami-test"), verify=pki.context())).json()

    assert (seen["scheme"], seen["listener"]) == ("https", "https")
    assert seen["tls"]["client_cert_chain"] == []
    assert seen["tls"]["client_cert_name"] is None
    assert seen["tls"]["tls_version"] in (0x0303, 0x0304)


async def test_u8_u9_client_certificate_and_verified_chain(
    run_launcher: Any, server_settings: SettingsFactory, make_pki: PkiFactory
) -> None:
    pki = await make_pki()
    async with run_launcher(server_settings()) as running:
        await running.wait_https()
        context = pki.context(with_client_cert=True)
        seen = (await get(running.https("/ca/whoami-test"), verify=context)).json()

    tls = seen["tls"]
    assert tls["client_cert_name"] == "CN=test-client"  # U8
    chain = [x509.load_pem_x509_certificate(pem.encode()) for pem in tls["client_cert_chain"]]
    assert len(chain) == 2  # U9: leaf then the CA (Python >= 3.13)
    assert chain[0].subject.rfc4514_string() == "CN=test-client"
    assert chain[1].subject == chain[0].issuer
    assert x509.load_pem_x509_certificate(pki.root_pem.encode()) == chain[1]


async def test_u10_client_certificate_of_an_unknown_ca_is_refused(
    run_launcher: Any, server_settings: SettingsFactory, make_pki: PkiFactory, tmp_path: Any
) -> None:
    pki = await make_pki()
    cert, key = _unknown_ca_client(tmp_path)
    async with run_launcher(server_settings()) as running:
        await running.wait_https()
        context = pki.context()
        context.load_cert_chain(cert, key)

        with pytest.raises((httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)):
            await get(running.https("/ca/whoami-test"), verify=context)


# --- U11, U12: hot reload of the certificate -----------------------------------------------


async def test_u11_u12_hot_renewal(
    run_launcher: Any, server_settings: SettingsFactory, make_pki: PkiFactory
) -> None:
    pki = await make_pki()
    async with run_launcher(server_settings()) as running:
        await running.wait_https()
        context = pki.context()
        port = running.settings.https_port
        first = await peer_serial(port, context)
        assert int(running.launcher.status.https_certificate_serial or "0", 16) == first
        # U12: a connection opened before the renewal.
        old = await asyncio.to_thread(_open_tls, port, context)
        try:
            assert await asyncio.to_thread(_keep_alive_get, old, "/health") == 200

            # Force a renewal through the hot settings (watcher): 47 days left <= 60.
            settings = SettingsService()
            await settings.set("tls_service.validity_days", 90, actor="cli")
            await settings.set("tls_service.renew_before_days", 60, actor="cli")
            await wait_for(
                lambda: (
                    running.launcher.status.https_certificate_serial is not None
                    and int(running.launcher.status.https_certificate_serial, 16) != first
                ),
                "the renewed certificate",
            )

            second = await peer_serial(port, context)  # U11: new connections, new certificate
            assert second != first
            assert await asyncio.to_thread(_keep_alive_get, old, "/health") == 200  # U12
            old_der = old.getpeercert(binary_form=True)
            assert old_der is not None
            assert x509.load_der_x509_certificate(old_der).serial_number == first
        finally:
            old.close()
        assert running.launcher.status.listeners == {"http", "https"}  # no restart


# --- U13: one process -------------------------------------------------------------------


async def test_u13_both_listeners_in_one_process(
    run_launcher: Any, server_settings: SettingsFactory, make_pki: PkiFactory
) -> None:
    pki = await make_pki()
    async with run_launcher(server_settings()) as running:
        await running.wait_https()
        http_health = (await get(running.http("/health"))).json()
        https_health = (await get(running.https("/health"), verify=pki.context())).json()

    # Both answered from this very process (the launcher runs in the test event loop).
    assert http_health["listeners"] == https_health["listeners"] == ["http", "https"]


# --- listener restart --------------------------------------------------------------------


async def test_listener_setting_restarts_only_https(
    run_launcher: Any, server_settings: SettingsFactory, make_pki: PkiFactory
) -> None:
    pki = await make_pki()
    async with run_launcher(server_settings()) as running:
        await running.wait_https()
        launcher = running.launcher
        http_server = launcher._servers["http"]
        https_server = launcher._servers["https"]
        tls12 = pki.context()
        tls12.maximum_version = ssl.TLSVersion.TLSv1_2
        assert (await get(running.https("/health"), verify=tls12)).status_code == 200

        await SettingsService().set("server.tls_min_version", "tls1.3", actor="cli")
        await wait_for(
            lambda: launcher._servers.get("https") not in (None, https_server), "restart"
        )

        assert launcher._servers["http"] is http_server  # HTTP untouched
        with pytest.raises((httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)):
            await get(running.https("/health"), verify=tls12)
        assert (await get(running.https("/health"), verify=pki.context())).status_code == 200
        assert (await get(running.http("/health"))).status_code == 200


async def test_uvicorn_limit_restarts_both_listeners(
    run_launcher: Any, server_settings: SettingsFactory, make_pki: PkiFactory
) -> None:
    await make_pki()
    async with run_launcher(server_settings()) as running:
        await running.wait_https()
        before = dict(running.launcher._servers)

        await SettingsService().set("server.keep_alive_timeout", 30, actor="cli")
        await wait_for(
            lambda: all(
                running.launcher._servers.get(name) not in (None, before[name])
                for name in ("http", "https")
            ),
            "both restarts",
        )

        assert running.launcher._servers["http"].config.timeout_keep_alive == 30


async def test_failed_restart_keeps_the_running_listener(
    run_launcher: Any,
    server_settings: SettingsFactory,
    make_pki: PkiFactory,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A new SSLContext that cannot be built never takes the listener down."""
    from h42pki.server import launcher as launcher_module

    pki = await make_pki()
    async with run_launcher(server_settings()) as running:
        await running.wait_https()
        https_server = running.launcher._servers["https"]

        def broken(*args: Any) -> ssl.SSLContext:
            raise ssl.SSLError("simulated failure")

        monkeypatch.setattr(launcher_module, "build_context", broken)
        await SettingsService().set("server.tls_min_version", "tls1.3", actor="cli")
        await wait_for(lambda: "not restarted" in caplog.text, "the error")

        assert running.launcher._servers["https"] is https_server
        assert (await get(running.https("/health"), verify=pki.context())).status_code == 200


async def test_log_level_is_applied_hot(
    run_launcher: Any, server_settings: SettingsFactory
) -> None:
    import logging

    async with run_launcher(server_settings()):
        await SettingsService().set("logging.level", "error", actor="cli")
        await wait_for(lambda: logging.getLogger("h42pki").level == logging.ERROR, "log level")
    logging.getLogger("h42pki").setLevel(logging.NOTSET)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).setLevel(logging.NOTSET)


# --- idle mode, disabled listeners, warnings ---------------------------------------------


async def test_idle_mode(
    run_launcher: Any, server_settings: SettingsFactory, caplog: pytest.LogCaptureFixture
) -> None:
    settings = server_settings(http_enabled=False, https_enabled=False)
    async with run_launcher(settings) as running:
        path = running.launcher.status.heartbeat_path
        assert path is not None
        await wait_for(path.exists, "the heartbeat")
        assert running.launcher.status.listeners == set()
        assert await asyncio.to_thread(_connect_refused, settings.http_port)
    assert "idle mode" in caplog.text
    assert not path.exists()  # removed at stop: the healthcheck turns red at once


async def test_https_disabled_never_issues_a_certificate(
    run_launcher: Any, server_settings: SettingsFactory, make_pki: PkiFactory
) -> None:
    from h42pki.models import Certificate

    await make_pki()
    before = await Certificate.all().count()
    async with run_launcher(server_settings(https_enabled=False)) as running:
        await asyncio.sleep(0.2)
        assert running.launcher.status.listeners == {"http"}
    assert await Certificate.all().count() == before


async def test_warning_https_without_http(
    run_launcher: Any,
    server_settings: SettingsFactory,
    make_root: Callable[..., Awaitable[Any]],
    caplog: pytest.LogCaptureFixture,
) -> None:
    await make_root(public_base_url="http://pki.home42.test")
    async with run_launcher(server_settings(http_enabled=False)) as running:
        await running.wait_https()
    assert "HTTP is disabled while HTTPS is enabled" in caplog.text
    assert "public base URL http://pki.home42.test is http://" in caplog.text


async def test_http_port_in_use_stops_the_launcher(
    run_launcher: Any, server_settings: SettingsFactory
) -> None:
    from h42pki.server.launcher import ListenerError

    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        settings = server_settings(http_port=busy.getsockname()[1])
        with pytest.raises(ListenerError, match="cannot listen"):
            async with run_launcher(settings):
                pass  # pragma: no cover
