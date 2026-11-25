"""Three-level hierarchy with docker compose (needs docker, bash, curl and openssl)."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]


def _docker_available() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    return (
        subprocess.run(  # noqa: S603 - fixed arguments
            [docker, "compose", "version"], capture_output=True, check=False
        ).returncode
        == 0
    )


@pytest.mark.interop
@pytest.mark.slow
@pytest.mark.skipif(not _docker_available(), reason="docker compose is not available")
def test_bootstrap(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    docker = shutil.which("docker")
    assert bash is not None and docker is not None
    env = {**os.environ, "COMPOSE_PROJECT_NAME": f"h42pki-test-{os.getpid()}"}
    try:
        result = subprocess.run(  # noqa: S603
            [bash, str(ROOT / "deploy" / "bootstrap.sh"), str(tmp_path)],
            env=env,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "leaf.pem: OK" in result.stdout
    finally:
        subprocess.run(  # noqa: S603
            [docker, "compose", "-f", str(ROOT / "deploy" / "compose.yaml"), "down", "--volumes"],
            env=env,
            capture_output=True,
            check=False,
        )
