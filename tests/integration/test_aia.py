"""AIA caIssuers in issued certificates and the public base URL of the local CA."""

from collections.abc import Callable

import pytest
from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID
from httpx import AsyncClient

from h42pki.core.errors import InvalidAuthorityName, InvalidPublicBaseUrl
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.models import AuditLog, Certificate, CertificateRequest
from h42pki.services import AuthorityService
from tests.conftest import IssueFactory, RootFactory
from tests.x509_helpers import csr_pem, make_csr, name

KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]


def ca_issuers(cert: x509.Certificate) -> list[str]:
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
    except x509.ExtensionNotFound:
        return []
    assert not aia.critical
    return [
        description.access_location.value
        for description in aia.value
        if description.access_method == AuthorityInformationAccessOID.CA_ISSUERS
    ]


async def certificate_of(request: CertificateRequest) -> x509.Certificate:
    return x509.load_der_x509_certificate((await Certificate.get(id=request.certificate_id)).der)


async def _issue_server(issue: IssueFactory, key_for: KeyFor) -> x509.Certificate:
    csr = make_csr(key_for(KeyAlgorithm.EC_P256), sans=["dns:www.example.test"])
    return await certificate_of(await issue("tls_server", csr_pem(csr)))


async def test_aia_with_public_base_url(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    authority = await make_root(public_base_url="http://pki.example.test:8000/")

    leaf = await _issue_server(issue, key_for)

    assert authority.public_base_url == "http://pki.example.test:8000"  # normalized
    assert ca_issuers(leaf) == ["http://pki.example.test:8000/ca/test-root.crt"]
    root = x509.load_der_x509_certificate((await Certificate.get(authority=authority)).der)
    assert ca_issuers(root) == []  # a root has no issuer to point to


async def test_no_aia_without_public_base_url(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    await make_root()

    assert ca_issuers(await _issue_server(issue, key_for)) == []


async def test_update_only_affects_new_certificates(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    await make_root()
    service = AuthorityService()  # no key store needed to change the URL
    before = await _issue_server(issue, key_for)

    authority, normalized = await service.update_public_base_url(
        "http://pki.example.test/", actor="anonymous"
    )
    first = await _issue_server(issue, key_for)
    await service.update_public_base_url("http://ca.example.test", actor="anonymous")
    second = await _issue_server(issue, key_for)
    await service.update_public_base_url(None, actor="anonymous")
    after_removal = await _issue_server(issue, key_for)

    assert normalized is not None and normalized.url == "http://pki.example.test"
    assert ca_issuers(before) == []
    assert ca_issuers(first) == ["http://pki.example.test/ca/test-root.crt"]
    assert ca_issuers(second) == ["http://ca.example.test/ca/test-root.crt"]
    assert ca_issuers(after_removal) == []
    entries = await AuditLog.filter(action="authority.update").order_by("timestamp")
    assert [(e.details["previous"], e.details["new"]) for e in entries] == [
        (None, "http://pki.example.test"),
        ("http://pki.example.test", "http://ca.example.test"),
        ("http://ca.example.test", None),
    ]
    assert {e.object_id for e in entries} == {str(authority.id)}


async def test_https_public_base_url_is_accepted(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    await make_root(public_base_url="https://pki.example.test")

    assert ca_issuers(await _issue_server(issue, key_for)) == [
        "https://pki.example.test/ca/test-root.crt"
    ]


@pytest.mark.parametrize("url", ["ftp://pki.example.test", "http://pki.example.test/?a=1"])
async def test_invalid_public_base_url_is_refused(make_root: RootFactory, url: str) -> None:
    with pytest.raises(InvalidPublicBaseUrl):
        await make_root(public_base_url=url)


@pytest.mark.parametrize("authority_name", ["chain", "Home42 Root", "home/42"])
async def test_invalid_authority_name_is_refused(
    make_root: RootFactory, authority_name: str
) -> None:
    with pytest.raises(InvalidAuthorityName):
        await make_root(name=authority_name)


async def test_update_requires_a_local_ca(client: AsyncClient) -> None:
    from h42pki.errors import NoActiveAuthority

    with pytest.raises(NoActiveAuthority):
        await AuthorityService().update_public_base_url("http://x.test", actor="anonymous")


@pytest.mark.parametrize("profile", ["tls_client", "device"])
async def test_aia_on_other_profiles(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor, profile: str
) -> None:
    await make_root(public_base_url="http://pki.example.test")
    csr = make_csr(key_for(KeyAlgorithm.EC_P256), name(CN="client-1"))

    cert = await certificate_of(await issue(profile, csr_pem(csr)))

    assert ca_issuers(cert) == ["http://pki.example.test/ca/test-root.crt"]
