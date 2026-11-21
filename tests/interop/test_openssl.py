"""Interoperability with the openssl command-line tool."""

import shutil
import subprocess
from pathlib import Path

import pytest
from httpx import AsyncClient

from h42pki.core.keys import KeyAlgorithm
from h42pki.models import Certificate
from tests.conftest import RootFactory

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


@pytest.mark.parametrize(
    "algorithm", [KeyAlgorithm.RSA2048, KeyAlgorithm.EC_P384, KeyAlgorithm.ED25519]
)
async def test_openssl_reads_and_verifies_root(
    client: AsyncClient, make_root: RootFactory, tmp_path: Path, algorithm: KeyAlgorithm
) -> None:
    record = await Certificate.get(authority=await make_root(algorithm, validity_days=365))
    der = tmp_path / "root.crt"
    der.write_bytes((await client.get(f"/api/v1/certificates/{record.id}.crt")).content)
    pem = tmp_path / "root.pem"
    pem.write_bytes((await client.get(f"/api/v1/certificates/{record.id}.pem")).content)

    text = _openssl("x509", "-inform", "DER", "-in", str(der), "-noout", "-text")
    assert "CA:TRUE" in text
    assert "Digital Signature, Certificate Sign, CRL Sign" in text
    assert "X509v3 Authority Key Identifier" in text

    assert ": OK" in _openssl("verify", "-CAfile", str(pem), str(pem))
