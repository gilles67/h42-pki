"""CRL and OCSP options of a CA: chosen at creation, fixed, and incompatible with idle mode."""

from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest
from click.testing import Result
from cryptography import x509
from httpx import AsyncClient
from typer.testing import CliRunner

from h42pki.cli import app
from h42pki.config import ENV_PREFIX, get_settings
from h42pki.core.inspection import crl_distribution_url, ocsp_url
from h42pki.core.keys import KeyAlgorithm
from h42pki.errors import NoActiveAuthority, RevocationNeedsListener
from h42pki.keystore import KeyStore
from h42pki.models import Authority, AuthorityStatus, Certificate, CertificateRequest
from h42pki.services import IssuanceService
from h42pki.services.authority import AuthorityService
from h42pki.services.tls_service import TlsServiceManager
from tests.cli_helpers import plain
from tests.conftest import TEST_PASSPHRASE, IssueFactory, RootFactory
from tests.x509_helpers import csr_pem, make_csr, name

runner = CliRunner()
KeyFor = Callable[[KeyAlgorithm], Any]


def server_csr(key_for: KeyFor, host: str = "www.example.test") -> str:
    return csr_pem(make_csr(key_for(KeyAlgorithm.EC_P256), name(CN=host), sans=[f"dns:{host}"]))


INIT = ["authority", "init", "--name", "home42-root", "--common-name", "Home42 Root CA"]


# --- service and API --------------------------------------------------------------------------


async def test_options_are_disabled_by_default(make_root: RootFactory) -> None:
    authority = await make_root()

    assert (authority.crl_enabled, authority.ocsp_enabled) == (False, False)


async def test_options_are_stored_and_shown(client: AsyncClient, make_root: RootFactory) -> None:
    await make_root(crl=True, ocsp=True)

    body = (await client.get("/api/v1/authority")).json()

    assert (body["crl_enabled"], body["ocsp_enabled"]) == (True, True)


async def test_idle_mode_refused_with_crl_or_ocsp(make_root: RootFactory) -> None:
    await make_root(crl=True)

    with pytest.raises(RevocationNeedsListener, match="cannot run in idle mode"):
        await AuthorityService.check_serving(idle=True)
    await AuthorityService.check_serving(idle=False)


async def test_idle_mode_accepted_without_revocation(make_root: RootFactory) -> None:
    await make_root()

    await AuthorityService.check_serving(idle=True)


async def test_revoked_local_ca_is_current_but_does_not_issue(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    authority = await make_root()
    await Authority.filter(id=authority.id).update(status=AuthorityStatus.REVOKED)

    current = await AuthorityService().find_local()
    assert current is not None and current.status is AuthorityStatus.REVOKED
    with pytest.raises(NoActiveAuthority, match="revoked by its parent"):
        await AuthorityService().get_issuing()
    with pytest.raises(NoActiveAuthority):
        await issue("tls_server", server_csr(key_for))


# --- CLI --------------------------------------------------------------------------------------


@pytest.fixture
def cli_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    database = tmp_path / "data" / "h42pki.sqlite3"
    monkeypatch.setenv(f"{ENV_PREFIX}DATABASE_URL", f"sqlite://{database.as_posix()}")
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE", TEST_PASSPHRASE)
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "test")
    get_settings.cache_clear()
    return database


def invoke(*args: str) -> Result:
    result = runner.invoke(app, list(args))
    assert "Traceback" not in plain(result)
    return result


def test_cli_init_with_crl_and_ocsp(cli_environment: Path) -> None:
    created = invoke(*INIT, "--crl", "--ocsp")
    status = invoke("authority", "status")

    assert created.exit_code == 0, created.output
    assert status.exit_code == 0, status.output
    lines = plain(status).splitlines()
    assert any(line.split() == ["CRL", "enabled"] for line in lines)
    assert any(line.split() == ["OCSP", "enabled"] for line in lines)


def test_cli_status_shows_disabled_options(cli_environment: Path) -> None:
    invoke(*INIT)

    lines = plain(invoke("authority", "status")).splitlines()

    assert any(line.split() == ["CRL", "disabled"] for line in lines)
    assert any(line.split() == ["OCSP", "disabled"] for line in lines)


@pytest.mark.parametrize("option", ["--crl", "--ocsp"])
def test_cli_init_refused_in_idle_mode(
    cli_environment: Path, monkeypatch: pytest.MonkeyPatch, option: str
) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}HTTP_ENABLED", "false")
    monkeypatch.setenv(f"{ENV_PREFIX}HTTPS_ENABLED", "false")
    get_settings.cache_clear()

    result = invoke(*INIT, option)

    assert result.exit_code != 0
    assert "cannot run in idle mode" in plain(result)
    assert invoke("authority", "status").exit_code != 0  # nothing was created


def test_cli_init_without_options_accepted_in_idle_mode(
    cli_environment: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(f"{ENV_PREFIX}HTTP_ENABLED", "false")
    monkeypatch.setenv(f"{ENV_PREFIX}HTTPS_ENABLED", "false")
    get_settings.cache_clear()

    assert invoke(*INIT).exit_code == 0


def test_cli_resume_refuses_options(cli_environment: Path) -> None:
    result = invoke("authority", "init", "--resume", "--token", "x", "--crl")

    assert result.exit_code == 2
    assert "--resume only takes" in plain(result)


# --- URLs written in issued certificates (B41) -------------------------------------------------

BASE = "http://pki.example.test:8080"


def revocation_urls(cert: x509.Certificate) -> tuple[str | None, str | None]:
    return crl_distribution_url(cert), ocsp_url(cert)


async def issued(request_id: UUID) -> x509.Certificate:
    request = await CertificateRequest.get(id=request_id)
    record = await Certificate.get(id=request.certificate_id)
    return x509.load_der_x509_certificate(record.der)


@pytest.mark.parametrize(
    ("crl", "ocsp", "base", "expected"),
    [
        (True, True, BASE, (f"{BASE}/crl/test-root.crl", f"{BASE}/ocsp")),
        (True, False, BASE, (f"{BASE}/crl/test-root.crl", None)),
        (False, True, BASE, (None, f"{BASE}/ocsp")),
        (False, False, BASE, (None, None)),
        (True, True, None, (None, None)),  # nowhere to point to without a public base URL
    ],
)
async def test_urls_follow_the_options(
    make_root: RootFactory,
    issue: IssueFactory,
    key_for: KeyFor,
    crl: bool,
    ocsp: bool,
    base: str | None,
    expected: tuple[str | None, str | None],
) -> None:
    authority = await make_root(crl=crl, ocsp=ocsp, public_base_url=base)

    leaf = await issued((await issue("tls_server", server_csr(key_for))).id)
    root = x509.load_der_x509_certificate((await Certificate.get(authority=authority)).der)

    assert revocation_urls(leaf) == expected
    assert revocation_urls(root) == (None, None)  # never on the root certificate itself


async def test_urls_in_sub_ca_and_service_tls_certificates(
    make_root: RootFactory, keystore: KeyStore, key_for: KeyFor
) -> None:
    await make_root(crl=True, ocsp=True, public_base_url=BASE)
    expected = (f"{BASE}/crl/test-root.crl", f"{BASE}/ocsp")
    service = IssuanceService(keystore)
    csr = csr_pem(make_csr(key_for(KeyAlgorithm.EC_P384), name(CN="Issuing CA")))
    pending = await service.submit(
        csr=csr, profile_name="sub_ca", validity_days=None, actor="anonymous"
    )
    sub_ca = await issued((await service.approve(pending.id, actor="anonymous")).id)
    https = (await TlsServiceManager(keystore, ["pki.home42.test"]).ensure()).certificate

    assert https is not None
    assert revocation_urls(sub_ca) == expected
    assert revocation_urls(x509.load_der_x509_certificate(https.der)) == expected


async def test_regression_B41_cdp_and_ocsp_in_issued(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    await make_root(crl=True, ocsp=True, public_base_url=BASE)
    request = await issue("tls_server", server_csr(key_for))

    body = (await client.get(f"/api/v1/certificates/{request.certificate_id}")).json()

    assert body["crl_url"] == f"{BASE}/crl/test-root.crl"
    assert body["ocsp_url"] == f"{BASE}/ocsp"
