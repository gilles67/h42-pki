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


def _run_openssl(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    assert OPENSSL is not None
    return subprocess.run(  # noqa: S603 - openssl from PATH with fixed arguments
        [OPENSSL, *args], input=stdin, capture_output=True, text=True, check=False
    )


def _openssl(*args: str, stdin: str | None = None) -> str:
    result = _run_openssl(*args, stdin=stdin)
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
    assert leaf.not_valid_after_utc - leaf.not_valid_before_utc == timedelta(days=47)


async def test_aia_and_published_chain(
    client: AsyncClient, make_root: RootFactory, tmp_path: Path
) -> None:
    """Interactive `openssl req` (with ST and L, B33), AIA caIssuers, /ca/chain.pem."""
    await make_root(KeyAlgorithm.EC_P384, name="home42-root", public_base_url="http://testserver")
    csr = tmp_path / "req.pem"
    answers = "FR\nIle-de-France\nParis\nHome42\nPKI\nwww.example.test\n\n\n\n"
    _openssl(
        "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-nodes", "-keyout", str(tmp_path / "key.pem"), "-out", str(csr),
        "-addext", "subjectAltName=DNS:www.example.test",
        stdin=answers,  # interactive prompts, no -subj
    )  # fmt: skip

    response = await client.post(
        "/api/v1/requests",
        json={"csr_pem": csr.read_text(encoding="ascii"), "profile": "tls_server"},
    )
    assert response.status_code == 201, response.text
    leaf_pem = tmp_path / "leaf.pem"
    leaf_pem.write_bytes(
        (await client.get(f"/api/v1/certificates/{response.json()['certificate_id']}.pem")).content
    )
    root_der = tmp_path / "root.crt"
    root_der.write_bytes((await client.get("/ca/home42-root.crt")).content)
    root_pem = tmp_path / "root.pem"
    root_pem.write_bytes((await client.get("/ca/home42-root.pem")).content)
    chain_pem = tmp_path / "chain.pem"
    chain_pem.write_bytes((await client.get("/ca/chain.pem")).content)

    text = _openssl("x509", "-in", str(leaf_pem), "-noout", "-text")
    assert "CA Issuers - URI:http://testserver/ca/home42-root.crt" in text
    assert "ST=Ile-de-France" in text.replace(" = ", "=") and "L=Paris" in text.replace(" = ", "=")
    assert "OCSP - URI" not in text and "CRL Distribution Points" not in text
    subject = _openssl("x509", "-inform", "DER", "-in", str(root_der), "-noout", "-subject")
    assert "Home42" in subject
    assert ": OK" in _openssl("verify", "-CAfile", str(root_pem), str(leaf_pem))
    assert ": OK" in _openssl("verify", "-CAfile", str(chain_pem), str(leaf_pem))


# --- revocation (ADR-0017) --------------------------------------------------------------------


async def _revocation_setup(
    client: AsyncClient, make_root: RootFactory, tmp_path: Path
) -> tuple[Path, Path, str]:
    """Root with CRL and OCSP, a leaf from an openssl CSR: (root.pem, leaf.pem, leaf id)."""
    authority = await make_root(crl=True, ocsp=True, public_base_url="http://pki.example.test")
    root = tmp_path / "root.pem"
    root.write_bytes(
        (
            await client.get(
                f"/api/v1/certificates/{(await Certificate.get(authority=authority)).id}.pem"
            )
        ).content
    )
    _openssl(
        "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-keyout", str(tmp_path / "leaf.key"), "-out", str(tmp_path / "leaf.csr"),
        "-subj", "/CN=www.example.test", "-addext", "subjectAltName=DNS:www.example.test",
    )  # fmt: skip
    body = {"csr_pem": (tmp_path / "leaf.csr").read_text(), "profile": "tls_server"}
    certificate_id = (await client.post("/api/v1/requests", json=body)).json()["certificate_id"]
    leaf = tmp_path / "leaf.pem"
    leaf.write_bytes((await client.get(f"/api/v1/certificates/{certificate_id}.pem")).content)
    return root, leaf, certificate_id


async def test_crl_with_openssl(
    client: AsyncClient, make_root: RootFactory, tmp_path: Path
) -> None:
    root, leaf, certificate_id = await _revocation_setup(client, make_root, tmp_path)
    text = _openssl("x509", "-in", str(leaf), "-noout", "-text")
    assert "URI:http://pki.example.test/crl/test-root.crl" in text
    assert "OCSP - URI:http://pki.example.test/ocsp" in text

    response = await client.post(
        f"/api/v1/certificates/{certificate_id}/revoke", json={"reason": "key_compromise"}
    )
    assert response.status_code == 200
    der = tmp_path / "root.crl"
    der.write_bytes((await client.get("/crl/test-root.crl")).content)
    crl_pem = tmp_path / "root.crl.pem"
    crl_pem.write_text(_openssl("crl", "-inform", "DER", "-in", str(der)))

    text = _openssl("crl", "-inform", "DER", "-in", str(der), "-noout", "-text")
    assert "X509v3 CRL Number" in text and "Key Compromise" in text
    serial = _openssl("x509", "-in", str(leaf), "-noout", "-serial").strip().split("=")[1]
    assert f"Serial Number: {serial}" in text
    refused = _run_openssl(
        "verify", "-crl_check", "-CAfile", str(root), "-CRLfile", str(crl_pem), str(leaf)
    )
    assert refused.returncode != 0 and "certificate revoked" in refused.stdout + refused.stderr


@pytest.mark.parametrize("nonce", [True, False], ids=["nonce", "no_nonce"])
async def test_ocsp_with_openssl(
    client: AsyncClient, make_root: RootFactory, tmp_path: Path, nonce: bool
) -> None:
    root, leaf, certificate_id = await _revocation_setup(client, make_root, tmp_path)
    request = tmp_path / "request.der"
    options = [] if nonce else ["-no_nonce"]
    _openssl("ocsp", "-issuer", str(root), "-cert", str(leaf), "-reqout", str(request), *options)

    async def status() -> str:
        answer = await client.post(
            "/ocsp",
            content=request.read_bytes(),
            headers={"content-type": "application/ocsp-request"},
        )
        response = tmp_path / "response.der"
        response.write_bytes(answer.content)
        # -reqin without -cert: openssl checks the answer against this very request (nonce
        # included); with -cert it would build another request with another nonce.
        result = _run_openssl(
            "ocsp", "-reqin", str(request), "-respin", str(response), "-CAfile", str(root),
            "-resp_text",
        )  # fmt: skip
        assert result.returncode == 0, result.stderr
        assert "Response verify OK" in result.stderr
        assert "WARNING" not in result.stderr and "Nonce Verify error" not in result.stderr
        return result.stdout

    good = await status()
    await client.post(
        f"/api/v1/certificates/{certificate_id}/revoke", json={"reason": "superseded"}
    )
    revoked = await status()

    assert "Cert Status: good" in good
    assert "Cert Status: revoked" in revoked and "Revocation Reason: superseded" in revoked
    assert ("OCSP Nonce" in good) is nonce
