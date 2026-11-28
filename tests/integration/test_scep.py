"""SCEP routes (RFC 8894): availability, labels, GetCACaps, GetCACert (ADR-0019)."""

import pytest
from asn1crypto import cms
from cryptography import x509
from httpx import AsyncClient

from h42pki.api.listener import served_over_http
from h42pki.keystore import KeyStore
from h42pki.services.scep_ra import ScepRaManager
from h42pki.services.settings import SettingsService
from tests.conftest import RootFactory

CA_RA_CERT = "application/x-x509-ca-ra-cert"
PATHS = ["/scep", "/scep/pkiclient.exe", "/scep/tls_client", "/scep/tls_client/pkiclient.exe"]


@pytest.fixture
async def scep(make_root: RootFactory, keystore: KeyStore) -> None:
    """An active root, SCEP enabled, its RA issued, tls_client as default profile."""
    await make_root()
    await SettingsService().set("scep.enabled", True, actor="cli")
    await SettingsService().set("scep.default_profile", "tls_client", actor="cli")
    await ScepRaManager(keystore).ensure()


def certificates(der: bytes) -> list[x509.Certificate]:
    signed = cms.ContentInfo.load(der)["content"]
    return [x509.load_der_x509_certificate(c.chosen.dump()) for c in signed["certificates"]]


@pytest.mark.parametrize("path", PATHS)
@pytest.mark.parametrize("operation", ["GetCACaps", "GetCACert", "PKIOperation", "Nope"])
async def test_disabled_by_default(
    client: AsyncClient, make_root: RootFactory, path: str, operation: str
) -> None:
    await make_root()

    response = await client.get(path, params={"operation": operation})
    posted = await client.post(path, params={"operation": operation}, content=b"x")

    assert (response.status_code, posted.status_code) == (404, 404)
    assert response.text == "SCEP is not enabled on this CA\n"
    assert response.headers["content-type"].startswith("text/plain")


@pytest.mark.usefixtures("scep")
async def test_get_ca_caps(client: AsyncClient) -> None:
    modern = await client.get("/scep/tls_client", params={"operation": "GetCACaps"})
    await SettingsService().set("scep.allow_legacy_crypto", True, actor="cli")
    legacy = await client.get("/scep/tls_client", params={"operation": "GetCACaps"})

    assert modern.status_code == 200 and modern.headers["content-type"].startswith("text/plain")
    assert modern.text.splitlines() == [
        "POSTPKIOperation", "SHA-256", "SHA-512", "AES", "SCEPStandard", "Renewal",
    ]  # fmt: skip
    assert legacy.text.splitlines()[-2:] == ["DES3", "SHA-1"]
    assert "GetNextCACert" not in legacy.text


@pytest.mark.usefixtures("scep")
@pytest.mark.parametrize("path", PATHS)
async def test_get_ca_cert(client: AsyncClient, path: str) -> None:
    published = x509.load_pem_x509_certificates((await client.get("/ca/chain.pem")).content)
    ra = await ScepRaManager().current()
    assert ra is not None

    response = await client.get(path, params={"operation": "GetCACert"})

    assert response.status_code == 200 and response.headers["content-type"] == CA_RA_CERT
    received = certificates(response.content)
    assert received[0] == published[0]  # the CA
    assert received[1] == x509.load_der_x509_certificate(ra.der)  # the RA
    assert received[2:] == published[1:]  # ancestors of the CA (none for a root)


async def test_get_ca_cert_waits_for_the_ra(client: AsyncClient, make_root: RootFactory) -> None:
    await make_root()
    await SettingsService().set("scep.enabled", True, actor="cli")

    response = await client.get("/scep/tls_client", params={"operation": "GetCACert"})

    assert response.status_code == 503 and "RA certificate" in response.text


@pytest.mark.usefixtures("scep")
@pytest.mark.parametrize("label", ["nope", "service_tls", "scep_ra", "X" * 80])
async def test_unknown_label(client: AsyncClient, label: str) -> None:
    response = await client.get(f"/scep/{label}", params={"operation": "GetCACaps"})

    assert response.status_code == 404


@pytest.mark.usefixtures("scep")
async def test_without_label_needs_a_default_profile(client: AsyncClient) -> None:
    assert (await client.get("/scep", params={"operation": "GetCACaps"})).status_code == 200

    await SettingsService().unset("scep.default_profile", actor="cli")
    response = await client.get("/scep", params={"operation": "GetCACaps"})

    assert response.status_code == 404 and "no default SCEP profile" in response.text


@pytest.mark.usefixtures("scep")
@pytest.mark.parametrize("params", [{}, {"operation": "GetNextCACert"}, {"operation": "nope"}])
async def test_unsupported_operations(client: AsyncClient, params: dict[str, str]) -> None:
    response = await client.get("/scep/tls_client", params=params)

    assert response.status_code == 400 and "unsupported SCEP operation" in response.text


def test_scep_is_served_over_http() -> None:
    assert served_over_http("/scep") and served_over_http("/scep/tls_client/pkiclient.exe")
