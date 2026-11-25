"""`h42pki serve` in a separate process: U13, U14 (SIGTERM), healthcheck, HTTPS after init.

Synchronous tests: each runs real processes of the CLI on its own database and temporary
directory (where the heartbeat lives).
"""

import os
import platform
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from h42pki.cli.health import check
from h42pki.config import ENV_PREFIX, Settings
from h42pki.heartbeat import heartbeat_path
from tests.cli_helpers import plain
from tests.conftest import TEST_PASSPHRASE
from tests.integration.server.conftest import free_port

CLI = [sys.executable, "-c", "from h42pki.cli import app; app()"]
START_TIMEOUT = 30.0
POSIX = os.name != "nt"
# WSL1 cannot share an SQLite database in WAL mode between processes ("locking protocol"); WSL2,
# Docker and Windows can. These tests run the CLI against the database of a running server.
WSL1 = "Microsoft" in platform.release()
shared_database = pytest.mark.skipif(
    WSL1, reason="WSL1: SQLite WAL cannot be shared between processes (use WSL2 or Docker)"
)


class Instance:
    def __init__(self, tmp_path: Path, **variables: str) -> None:
        self.tmp = tmp_path
        self.http_port = free_port()
        self.https_port = free_port()
        database = tmp_path / "data" / "h42pki.sqlite3"
        self.database_url = f"sqlite://{database.as_posix()}"
        self.env = {k: v for k, v in os.environ.items() if not k.upper().startswith(ENV_PREFIX)}
        self.env.update(
            {
                f"{ENV_PREFIX}ENVIRONMENT": "test",
                f"{ENV_PREFIX}SECRETS_DIR": str(tmp_path / "no-secrets"),
                f"{ENV_PREFIX}DATABASE_URL": self.database_url,
                f"{ENV_PREFIX}CA_PASSPHRASE": TEST_PASSPHRASE,
                f"{ENV_PREFIX}SERVER_HOSTNAME": "pki.home42.test",
                f"{ENV_PREFIX}SERVER_ALT_NAMES": "localhost,127.0.0.1",
                f"{ENV_PREFIX}HTTP_PORT": str(self.http_port),
                f"{ENV_PREFIX}HTTPS_PORT": str(self.https_port),
                # Heartbeat file of this instance (tempfile.gettempdir()).
                "TMPDIR": str(tmp_path),
                "TEMP": str(tmp_path),
                "TMP": str(tmp_path),
                **{f"{ENV_PREFIX}{k}": v for k, v in variables.items()},
            }
        )
        self.process: subprocess.Popen[str] | None = None

    def cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - our own CLI, fixed arguments
            [*CLI, *args], env=self.env, capture_output=True, text=True, timeout=60, check=False
        )

    def serve(self) -> None:
        self.process = subprocess.Popen(  # noqa: S603
            [*CLI, "serve"],
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

    def settings(self) -> Settings:
        return Settings(database_url=self.database_url, environment="test")

    @property
    def heartbeat(self) -> Path:
        return heartbeat_path(self.database_url)

    def wait(self, condition: Callable[[], bool], what: str) -> None:
        deadline = time.monotonic() + START_TIMEOUT
        while not condition():
            assert self.process is not None
            if self.process.poll() is not None:
                output = self.process.stdout.read() if self.process.stdout else ""
                raise AssertionError(f"the server exited while waiting for {what}:\n{output}")
            if time.monotonic() > deadline:
                raise AssertionError(f"timeout waiting for {what}")
            time.sleep(0.1)

    def stop(self) -> tuple[int, str]:
        assert self.process is not None
        if POSIX:
            self.process.send_signal(signal.SIGTERM)
        else:  # no SIGTERM delivery on Windows: TerminateProcess
            self.process.terminate()
        output, _ = self.process.communicate(timeout=30)
        return self.process.returncode, output


def listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.fixture
def instance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., Instance]]:
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))  # in-process healthcheck: same file
    created: list[Instance] = []

    def make(**variables: str) -> Instance:
        created.append(Instance(tmp_path, **variables))
        return created[-1]

    yield make
    for item in created:
        if item.process is not None and item.process.poll() is None:
            item.process.kill()
            item.process.communicate(timeout=30)


@shared_database
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


@shared_database
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
