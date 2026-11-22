"""Public publication endpoints: /ca/{name}.crt|.pem and /ca/chain.pem."""

from collections.abc import Callable
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import pytest
from cryptography import x509
from httpx import AsyncClient

from h42pki.core.extensions import BasicConstraints, Extensions, KeyUsage
from h42pki.core.issuance import build_self_signed
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.core.names import Subject
from h42pki.core.serial import new_serial_hex
from h42pki.keystore import SoftwareKeyStore
from h42pki.models import Authority, AuthorityKind, AuthorityStatus, Certificate
from h42pki.services.x509_fields import signed_fields
from tests.conftest import IssueFactory, RootFactory
from tests.integration.test_aia import ca_issuers, certificate_of
from tests.x509_helpers import csr_pem, make_csr

KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]


async def test_ca_certificate_der_and_pem(client: AsyncClient, make_root: RootFactory) -> None:
    authority = await make_root(name="home42-root")
    record = await Certificate.get(authority=authority)

    der = await client.get("/ca/home42-root.crt")
    pem = await client.get("/ca/home42-root.pem")

    assert der.status_code == pem.status_code == 200
    assert der.headers["content-type"] == "application/pkix-cert"
    assert pem.headers["content-type"] == "application/x-pem-file"
    assert der.content == record.der
    assert x509.load_der_x509_certificate(der.content) == x509.load_pem_x509_certificate(
        pem.content
    )
    for response in (der, pem):
        assert response.headers["etag"] == f'"{record.sha256_fingerprint}"'
        assert response.headers["cache-control"] == "public, max-age=3600"
        assert parsedate_to_datetime(response.headers["last-modified"]) == record.not_before


async def test_chain_includes_the_root(client: AsyncClient, make_root: RootFactory) -> None:
    authority = await make_root()
    record = await Certificate.get(authority=authority)

    response = await client.get("/ca/chain.pem")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/x-pem-file"
    assert x509.load_pem_x509_certificates(response.content) == [
        x509.load_der_x509_certificate(record.der)
    ]
    assert response.headers["etag"].startswith('"') and "cache-control" in response.headers


async def test_chain_walks_up_the_ancestors(
    client: AsyncClient, make_root: RootFactory, key_for: KeyFor
) -> None:
    """A parent CA (phase 2) is appended after the local one."""
    local = await make_root()
    parent_key = key_for(KeyAlgorithm.EC_P384)
    parent_cert = build_self_signed(
        Subject(common_name="Parent Root"),
        Extensions(
            basic_constraints=BasicConstraints(ca=True),
            key_usage=KeyUsage(key_cert_sign=True, crl_sign=True),
        ),
        parent_key,
        serial_hex=new_serial_hex(),
        validity_days=3650,
        now=datetime.now(UTC),
    )
    parent = await Authority.create(name="parent", kind=AuthorityKind.PARENT)
    await Certificate.create(authority=parent, **signed_fields(parent_cert))
    await Authority.filter(id=local.id).update(parent_id=parent.id)

    chain = x509.load_pem_x509_certificates((await client.get("/ca/chain.pem")).content)

    assert [cert.subject.rfc4514_string() for cert in chain] == [
        "CN=h42 Test Root CA,O=Home42",
        "CN=Parent Root",
    ]


@pytest.mark.parametrize("path", ["/ca/{name}.crt", "/ca/{name}.pem"])
async def test_if_none_match(client: AsyncClient, make_root: RootFactory, path: str) -> None:
    await make_root(name="home42-root")
    url = path.format(name="home42-root")
    etag = (await client.get(url)).headers["etag"]

    for header in (etag, f"W/{etag}", f'"other", {etag}', "*"):
        response = await client.get(url, headers={"If-None-Match": header})
        assert response.status_code == 304, header
        assert response.content == b""
        assert response.headers["etag"] == etag
    assert (await client.get(url, headers={"If-None-Match": '"other"'})).status_code == 200


async def test_chain_if_none_match(client: AsyncClient, make_root: RootFactory) -> None:
    await make_root()
    etag = (await client.get("/ca/chain.pem")).headers["etag"]

    response = await client.get("/ca/chain.pem", headers={"If-None-Match": etag})

    assert response.status_code == 304


@pytest.mark.parametrize("path", ["/ca/unknown.crt", "/ca/unknown.pem"])
async def test_unknown_ca_is_404(client: AsyncClient, make_root: RootFactory, path: str) -> None:
    await make_root()

    response = await client.get(path)

    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"


async def test_chain_without_ca_is_503(client: AsyncClient) -> None:
    response = await client.get("/ca/chain.pem")

    assert response.status_code == 503
    assert response.headers["content-type"] == "application/problem+json"


async def test_retired_ca_is_still_published(client: AsyncClient, make_root: RootFactory) -> None:
    old = await make_root(name="old-root")
    old_der = (await Certificate.get(authority=old)).der
    await Authority.filter(id=old.id).update(status=AuthorityStatus.RETIRED)
    new = await make_root(name="new-root")

    assert (await client.get("/ca/old-root.crt")).content == old_der
    chain = x509.load_pem_x509_certificates((await client.get("/ca/chain.pem")).content)
    assert chain == [x509.load_der_x509_certificate((await Certificate.get(authority=new)).der)]


async def test_non_local_ca_is_not_published(client: AsyncClient, make_root: RootFactory) -> None:
    await make_root()
    await Authority.create(name="someone-else", kind=AuthorityKind.CHILD)

    assert (await client.get("/ca/someone-else.crt")).status_code == 404


async def test_following_the_aia_url_gives_the_issuer(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    await make_root(name="home42-root", public_base_url="http://testserver")
    csr = make_csr(key_for(KeyAlgorithm.EC_P256), sans=["dns:www.example.test"])
    leaf = await certificate_of(await issue("tls_server", csr_pem(csr)))

    (url,) = ca_issuers(leaf)
    assert url == "http://testserver/ca/home42-root.crt"
    response = await client.get(url)

    issuer = x509.load_der_x509_certificate(response.content)
    leaf.verify_directly_issued_by(issuer)


async def test_publication_never_touches_a_private_key(
    client: AsyncClient, make_root: RootFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_root(name="home42-root")

    async def forbidden(self: SoftwareKeyStore, stored: bytes) -> None:
        raise AssertionError("a public endpoint loaded a private key")

    monkeypatch.setattr(SoftwareKeyStore, "load", forbidden)
    monkeypatch.setattr(SoftwareKeyStore, "generate", forbidden)

    for path in ("/ca/home42-root.crt", "/ca/home42-root.pem", "/ca/chain.pem"):
        assert (await client.get(path)).status_code == 200
