"""Interoperability with the openssl command-line tool."""

import shutil
import subprocess
from pathlib import Path

import pytest
from httpx import AsyncClient

from tests.integration.test_smoke_ca import EXTENSIONS, SUBJECT

OPENSSL = shutil.which("openssl")

pytestmark = [
    pytest.mark.interop,
    pytest.mark.skipif(OPENSSL is None, reason="openssl is not installed"),
]


def _openssl(*args: str) -> str:
    assert OPENSSL is not None
    result = subprocess.run(  # noqa: S603 - openssl from PATH with fixed arguments
        [OPENSSL, *args], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    return result.stdout


@pytest.mark.parametrize("algorithm", ["rsa2048", "ec_p384", "ed25519"])
async def test_openssl_reads_and_verifies_root(
    client: AsyncClient, tmp_path: Path, algorithm: str
) -> None:
    response = await client.post("/api/v1/private-keys", json={"algorithm": algorithm})
    response = await client.post(
        "/api/v1/certificates",
        json={
            "private_key_id": response.json()["id"],
            "subject": SUBJECT,
            "extensions": EXTENSIONS,
        },
    )
    cert_id = response.json()["id"]
    response = await client.post(
        f"/api/v1/certificates/{cert_id}/self-sign", json={"validity_days": 365}
    )
    assert response.status_code == 200, response.text
    der = tmp_path / "root.crt"
    der.write_bytes((await client.get(f"/api/v1/certificates/{cert_id}.crt")).content)
    pem = tmp_path / "root.pem"
    pem.write_bytes((await client.get(f"/api/v1/certificates/{cert_id}.pem")).content)

    text = _openssl("x509", "-inform", "DER", "-in", str(der), "-noout", "-text")
    assert "CA:TRUE" in text
    assert "Certificate Sign, CRL Sign" in text
    assert "X509v3 Authority Key Identifier" in text

    assert ": OK" in _openssl("verify", "-CAfile", str(pem), str(pem))
