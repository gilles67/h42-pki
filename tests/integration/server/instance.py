"""One `h42pki serve` in a separate process, on its own database and temporary directory."""

import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

from h42pki.config import ENV_PREFIX, Settings
from h42pki.heartbeat import heartbeat_path
from tests.conftest import TEST_PASSPHRASE
from tests.integration.server.conftest import free_port

CLI = [sys.executable, "-c", "from h42pki.cli import app; app()"]
START_TIMEOUT = 30.0
POSIX = os.name != "nt"


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
        self.log = tmp_path / "serve.log"
        self.process: subprocess.Popen[bytes] | None = None

    def cli(self, *args: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - our own CLI, fixed arguments
            [*CLI, *args],
            env=self.env,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def serve(self) -> None:
        # A file rather than a pipe: nobody reads a pipe, and a full one blocks the server.
        with self.log.open("wb") as log:
            self.process = subprocess.Popen(  # noqa: S603
                [*CLI, "serve"], env=self.env, stdout=log, stderr=subprocess.STDOUT
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
                output = self.log.read_text(encoding="utf-8")
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
        code = self.process.wait(timeout=30)
        return code, self.log.read_text(encoding="utf-8")

    def kill(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=30)


def listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False
