"""`h42pki serve` in a separate process: U13, U14 (SIGTERM), healthcheck, HTTPS after init.

The CLI writes to the database of a running server: this needs a real Linux, WSL2, Windows or a
container (B42, closed: WSL1 is no longer a development environment).

Synchronous tests: each runs real processes of the CLI on its own database and temporary
directory (where the heartbeat lives).
"""

import ssl
import tempfile
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from h42pki.cli.health import check
from h42pki.config import ENV_PREFIX
from tests.cli_helpers import plain
from tests.integration.server.instance import POSIX, Instance, listening


@pytest.fixture
def instance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., Instance]]:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))  # in-process healthcheck: same file
    created: list[Instance] = []

    def make(**variables: str) -> Instance:
        created.append(Instance(tmp_path, **variables))
        return created[-1]

    yield make
    for item in created:
        item.kill()


def test_https_opens_after_authority_init_and_stops_cleanly(
    instance: Callable[..., Instance],
) -> None:
    """Acceptance scenario 1 to 4 outside Docker, then U13 and U14."""
    server = instance()
    server.serve()
    server.wait(lambda: listening(server.http_port), "HTTP")
    assert httpx.get(f"http://127.0.0.1:{server.http_port}/").status_code == 200
    assert not listening(server.https_port)  # HTTPS closed before the CA exists

    init = server.cli("authority", "init", "--name", "home42-root", "--common-name", "Root CA")
    assert init.returncode == 0, init.stderr
    server.wait(lambda: listening(server.https_port), "HTTPS after authority init")

    root = server.cli("authority", "export").stdout
    context = ssl.create_default_context(cadata=root)
    https = httpx.Client(verify=context)
    health = https.get(f"https://127.0.0.1:{server.https_port}/health").json()
    assert health["listeners"] == ["http", "https"]  # U13: one process serves both
    not_after = datetime.fromisoformat(health["https_certificate"]["not_after"])
    assert abs(not_after - (datetime.now(UTC) + timedelta(days=47))) < timedelta(minutes=10)
    http_admin = httpx.get(f"http://127.0.0.1:{server.http_port}/api/v1/authority")
    https_admin = https.get(f"https://127.0.0.1:{server.https_port}/api/v1/authority")
    assert (http_admin.status_code, https_admin.status_code) == (404, 200)
    https.close()
    healthy, message = check(server.settings())
    assert healthy, message

    code, output = server.stop()

    if POSIX:  # U14: clean stop of both servers on SIGTERM
        assert code == 0, output
        assert "launcher stopped" in output
        assert not server.heartbeat.exists()
        assert not listening(server.http_port) and not listening(server.https_port)


@pytest.mark.skipif(not POSIX, reason="SIGTERM cannot be delivered to a process on Windows")
def test_u14_sigterm_in_idle_mode(instance: Callable[..., Instance]) -> None:
    server = instance(HTTP_ENABLED="false", HTTPS_ENABLED="false")
    server.serve()
    server.wait(server.heartbeat.exists, "the heartbeat")

    code, output = server.stop()

    assert code == 0, output
    assert "idle mode" in output and "launcher stopped" in output


def test_healthcheck_in_idle_mode(instance: Callable[..., Instance]) -> None:
    """Green while the launcher runs without any listener, red once it is stopped."""
    server = instance(HTTP_ENABLED="false", HTTPS_ENABLED="false")
    assert server.cli("healthcheck").returncode == 1  # not running yet: no heartbeat
    server.serve()
    server.wait(server.heartbeat.exists, "the heartbeat")

    result = server.cli("healthcheck")

    assert result.returncode == 0, result.stderr
    assert "healthy" in plain(result, "stdout")
    assert not listening(server.http_port) and not listening(server.https_port)

    server.stop()
    time.sleep(1.5)
    # POSIX: the heartbeat was removed at stop. Windows (killed): it is older than 1 s.
    healthy, message = check(server.settings(), max_age=1.0)
    assert not healthy
    assert "unhealthy" in message
    if POSIX:
        assert server.cli("healthcheck").returncode == 1


def test_serve_requires_the_hostname(instance: Callable[..., Instance]) -> None:
    server = instance()
    del server.env[f"{ENV_PREFIX}SERVER_HOSTNAME"]

    result = server.cli("serve")

    assert result.returncode == 2
    assert "H42_PKI_SERVER_HOSTNAME" in plain(result, "stderr")


def test_serve_requires_the_passphrase(instance: Callable[..., Instance]) -> None:
    server = instance()
    del server.env[f"{ENV_PREFIX}CA_PASSPHRASE"]

    result = server.cli("serve")

    assert result.returncode == 2
    assert "H42_PKI_CA_PASSPHRASE" in plain(result, "stderr")


def test_serve_has_no_host_and_port_options(instance: Callable[..., Instance]) -> None:
    result = instance().cli("serve", "--port", "8000")

    assert result.returncode == 2
    assert "No such option" in plain(result, "stderr")


@pytest.mark.parametrize("option", ["--crl", "--ocsp"])
def test_idle_mode_refused_with_revocation(instance: Callable[..., Instance], option: str) -> None:
    """A CA with CRL or OCSP must serve them: idle mode is refused at start-up (ADR-0017)."""
    server = instance(HTTP_ENABLED="false", HTTPS_ENABLED="false")
    online = instance()  # same database, listeners on: authority init is allowed there
    online.database_url = server.database_url
    online.env[f"{ENV_PREFIX}DATABASE_URL"] = server.database_url
    init = online.cli("authority", "init", "--name", "root", "--common-name", "Root CA", option)
    assert init.returncode == 0, init.stderr

    result = server.cli("serve")

    assert result.returncode == 2
    assert "cannot run in idle mode" in plain(result, "stderr")
    assert "Traceback" not in result.stderr


def test_idle_mode_accepted_without_revocation(instance: Callable[..., Instance]) -> None:
    server = instance(HTTP_ENABLED="false", HTTPS_ENABLED="false")
    init = server.cli("authority", "init", "--name", "root", "--common-name", "Root CA")
    assert init.returncode == 0, init.stderr
    server.serve()

    server.wait(server.heartbeat.exists, "the heartbeat")

    assert server.cli("healthcheck").returncode == 0
