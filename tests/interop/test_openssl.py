"""Interoperability with the openssl command-line tool."""

import shutil
import subprocess
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography import x509
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


@pytest.mark.parametrize(
    ("newkey", "key_encipherment"),
    [
        (["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"], False),
        (["-newkey", "rsa:2048"], True),
    ],
    ids=["ec_p256", "rsa2048"],
)
async def test_openssl_csr_is_issued_and_verified(
    client: AsyncClient,
    make_root: RootFactory,
    tmp_path: Path,
    newkey: list[str],
    key_encipherment: bool,
) -> None:
    record = await Certificate.get(authority=await make_root(KeyAlgorithm.EC_P384))
    root_pem = tmp_path / "root.pem"
    root_pem.write_bytes((await client.get(f"/api/v1/certificates/{record.id}.pem")).content)
    csr = tmp_path / "req.pem"
    _openssl(
        "req", "-new", *newkey, "-nodes",
        "-keyout", str(tmp_path / "key.pem"), "-out", str(csr),
        "-subj", "/CN=www.example.test",
        "-addext", "subjectAltName=DNS:www.example.test,IP:192.0.2.10",
        "-addext", "basicConstraints=critical,CA:TRUE",  # must not be copied
    )  # fmt: skip

    response = await client.post(
        "/api/v1/requests",
        json={"csr_pem": csr.read_text(encoding="ascii"), "profile": "tls_server"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "issued"
    assert body["ignored_extensions"] == ["BasicConstraints (2.5.29.19)"]
    leaf_pem = tmp_path / "leaf.pem"
    leaf_pem.write_bytes(
        (await client.get(f"/api/v1/certificates/{body['certificate_id']}.pem")).content
    )

    assert ": OK" in _openssl("verify", "-CAfile", str(root_pem), str(leaf_pem))
    text = _openssl("x509", "-in", str(leaf_pem), "-noout", "-text")
    assert "CA:FALSE" in text and "CA:TRUE" not in text
    expected_usage = (
        "Digital Signature, Key Encipherment" if key_encipherment else "Digital Signature"
    )
    assert f"X509v3 Key Usage: critical\n                {expected_usage}\n" in text
    assert "TLS Web Server Authentication" in text
    assert "DNS:www.example.test, IP Address:192.0.2.10" in text
    assert "CRL Distribution Points" not in text
    assert "Authority Information Access" not in text
    leaf = x509.load_pem_x509_certificate(leaf_pem.read_bytes())
    assert leaf.not_valid_after_utc - leaf.not_valid_before_utc == timedelta(days=90)
