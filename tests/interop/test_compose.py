"""Three-level hierarchy with compose, then EST, SCEP and revocation (Podman, or Docker).

Needs bash, curl, openssl and a container engine. ``CONTAINER_ENGINE`` forces the engine, as for the
scripts of ``deploy/``; without it, the first one that is installed is used, Podman first.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
COMPOSE = {"podman": ["podman-compose"], "docker": ["docker", "compose"]}


def _available(engine: str) -> bool:
    if shutil.which(engine) is None:
        return False
    command = COMPOSE[engine]
    if shutil.which(command[0]) is None:
        return False
    version = subprocess.run(  # noqa: S603 - fixed arguments
        [*command, "version"], capture_output=True, check=False
    )
    return version.returncode == 0


def _engine() -> str | None:
    forced = os.environ.get("CONTAINER_ENGINE")
    engines = [forced] if forced else list(COMPOSE)
    return next((engine for engine in engines if engine in COMPOSE and _available(engine)), None)


ENGINE = _engine()


@pytest.mark.interop
@pytest.mark.slow
@pytest.mark.skipif(
    ENGINE is None,
    reason="no container engine: podman with podman-compose, or docker with compose v2, is needed",
)
def test_bootstrap(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    assert bash is not None and ENGINE is not None
    env = {
        **os.environ,
        "CONTAINER_ENGINE": ENGINE,
        "COMPOSE_PROJECT_NAME": f"h42pki-test-{os.getpid()}",
    }
    try:
        result = subprocess.run(  # noqa: S603
            [bash, str(ROOT / "deploy" / "bootstrap.sh"), str(tmp_path)],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=900,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "leaf.pem: OK" in result.stdout
        # EST then SCEP on the issuing CA, before the revocation scenario revokes that CA: EST
        # with a real client when ESTCLIENT is set, SCEP with sscep (deploy/sscep/Containerfile),
        # then CRL and OCSP with openssl.
        for scenario in ("est-test", "scep-test", "revocation-test"):
            run = subprocess.run(  # noqa: S603
                [bash, str(ROOT / "deploy" / f"{scenario}.sh"), str(tmp_path)],
                env=env,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=900,
                check=False,
            )
            assert run.returncode == 0, run.stdout + run.stderr
            assert f"{scenario}: all checks passed" in run.stdout
    finally:
        subprocess.run(  # noqa: S603
            [*COMPOSE[ENGINE], "-f", str(ROOT / "deploy" / "compose.yaml"), "down", "--volumes"],
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
        )
