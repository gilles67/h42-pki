"""EST (RFC 7030): availability, cacerts, simpleenroll, approval and retries (ADR-0018)."""

import base64
import ipaddress
from collections.abc import Callable
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from fastapi import FastAPI
from httpx import AsyncClient, Response

from h42pki.core.keys import KeyAlgorithm
from h42pki.keystore import KeyStore
from h42pki.models import AuditLog, Certificate, CertificateRequest, Channel
from h42pki.services.est_accounts import EstAccountService
from h42pki.services.revocation import RevocationService
from h42pki.services.settings import SettingsService
from tests.conftest import IssueFactory, RootFactory
from tests.unit.core.test_issued import _root
from tests.x509_helpers import csr_pem, make_csr, name

KeyFor = Callable[[KeyAlgorithm], Any]
EST = "/.well-known/est"
PASSWORD = "est password 1"  # noqa: S105 - test value
CERTS_ONLY = "application/pkcs7-mime; smime-type=certs-only"


def basic(username: str = "alice", password: str = PASSWORD) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def csr_body(key_for: KeyFor, host: str = "www.example.test", *, sans: bool = True) -> bytes:
    csr = make_csr(
        key_for(KeyAlgorithm.EC_P256), name(CN=host), sans=[f"dns:{host}"] if sans else []
    )
    der = csr.public_bytes(serialization.Encoding.DER)
    text = base64.b64encode(der)
    return b"\r\n".join(text[i : i + 64] for i in range(0, len(text), 64))  # CRLF lines


def certificates(response: Response) -> list[x509.Certificate]:
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == CERTS_ONLY
    assert response.headers["content-transfer-encoding"] == "base64"
    return pkcs7.load_der_pkcs7_certificates(base64.b64decode(response.content))


async def enroll(
    client: AsyncClient, body: bytes, *, label: str | None = "tls_server", **headers: str
) -> Response:
    path = f"{EST}/{label}/simpleenroll" if label else f"{EST}/simpleenroll"
    return await client.post(
        path, content=body, headers={"Content-Type": "application/pkcs10", **headers}
    )


@pytest.fixture
async def est(make_root: RootFactory) -> None:
    """An active root, EST enabled, an account alice."""
    await make_root()
    await SettingsService().set("est.enabled", True, actor="cli")
    await EstAccountService().create("alice", password=PASSWORD, actor="cli")


# --- availability -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method, path",
    [
        ("GET", "/cacerts"),
        ("GET", "/tls_server/cacerts"),
        ("POST", "/simpleenroll"),
        ("POST", "/tls_server/simpleenroll"),
        ("POST", "/fullcmc"),
        ("GET", "/nothing/here"),
    ],
)
async def test_disabled_by_default(
    client: AsyncClient, make_root: RootFactory, method: str, path: str
) -> None:
    await make_root()

    response = await client.request(method, EST + path, headers=basic())

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("text/plain")
    assert response.text == "EST is not enabled on this CA\n"


@pytest.mark.usefixtures("est")
async def test_enabled_and_disabled_hot(client: AsyncClient) -> None:
    assert (await client.get(f"{EST}/tls_server/cacerts")).status_code == 200

    await SettingsService().set("est.enabled", False, actor="cli")

    assert (await client.get(f"{EST}/tls_server/cacerts")).status_code == 404


@pytest.mark.usefixtures("est")
async def test_cacerts(client: AsyncClient) -> None:
    published = x509.load_pem_x509_certificates((await client.get("/ca/chain.pem")).content)

    received = certificates(await client.get(f"{EST}/tls_server/cacerts"))

    assert received == published


# --- labels and profiles ----------------------------------------------------------------------


@pytest.mark.usefixtures("est")
async def test_without_label_needs_a_default_profile(client: AsyncClient, key_for: KeyFor) -> None:
    refused = await enroll(client, csr_body(key_for), label=None, **basic())
    await SettingsService().set("est.default_profile", "tls_server", actor="cli")
    accepted = await enroll(client, csr_body(key_for), label=None, **basic())

    assert refused.status_code == 404 and "no default EST profile" in refused.text
    assert certificates(accepted)


@pytest.mark.usefixtures("est")
@pytest.mark.parametrize("label", ["nope", "service_tls", "A" * 80, "../ca"])
async def test_unknown_label(client: AsyncClient, key_for: KeyFor, label: str) -> None:
    response = await enroll(client, csr_body(key_for), label=label, **basic())

    assert response.status_code == 404


@pytest.mark.usefixtures("est")
async def test_disabled_profile_is_forbidden(client: AsyncClient, key_for: KeyFor) -> None:
    await SettingsService().set("issuance.disabled_profiles", ["tls_server"], actor="cli")

    response = await enroll(client, csr_body(key_for), **basic())

    assert response.status_code == 403 and "disabled" in response.text


@pytest.mark.usefixtures("est")
async def test_wrong_methods_and_operations(client: AsyncClient) -> None:
    wrong_method = await client.get(f"{EST}/tls_server/simpleenroll")
    unknown = await client.post(f"{EST}/tls_server/enrollme", content=b"")
    full = await client.post(f"{EST}/tls_server/fullcmc", content=b"")

    assert wrong_method.status_code == 405 and wrong_method.headers["allow"] == "POST"
    assert unknown.status_code == 404 and unknown.text == "unknown EST operation\n"
    assert full.status_code == 501


# --- simpleenroll with HTTP Basic -------------------------------------------------------------


@pytest.mark.usefixtures("est")
async def test_simpleenroll_with_basic(client: AsyncClient, key_for: KeyFor) -> None:
    response = await enroll(client, csr_body(key_for), **basic())

    [issued] = certificates(response)
    assert issued.subject.rfc4514_string() == "CN=www.example.test"
    record = await Certificate.get(sha256_fingerprint=issued.fingerprint(hashes.SHA256()).hex())
    assert record.channel is Channel.EST
    request = await CertificateRequest.get(certificate_id=record.id)
    assert (request.requester, request.channel) == ("est:alice", Channel.EST)
    assert (await AuditLog.get(action="est.enroll")).actor == "est:alice"


@pytest.mark.usefixtures("est")
@pytest.mark.parametrize(
    "headers",
    [
        {},
        basic(password="wrong password"),  # noqa: S106 - test value
        basic(username="bob"),
        {"Authorization": "Basic !!!"},
        {"Authorization": "Bearer abc"},
    ],
)
async def test_unauthenticated(
    client: AsyncClient, key_for: KeyFor, headers: dict[str, str]
) -> None:
    response = await enroll(client, csr_body(key_for), **headers)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == 'Basic realm="h42pki-est"'
    assert response.text == "authentication required\n"
    assert PASSWORD not in response.text


@pytest.mark.usefixtures("est")
async def test_disabled_account(client: AsyncClient, key_for: KeyFor) -> None:
    from h42pki.models import CredentialStatus

    await EstAccountService().set_status("alice", CredentialStatus.DISABLED, actor="cli")

    assert (await enroll(client, csr_body(key_for), **basic())).status_code == 401


@pytest.mark.usefixtures("est")
@pytest.mark.parametrize(
    ("body", "message"),
    [
        (b"!!! not base64 !!!", "not base64"),
        (b"", "empty"),
        (base64.b64encode(b"not a CSR"), "cannot be parsed"),
    ],
)
async def test_unreadable_requests(client: AsyncClient, body: bytes, message: str) -> None:
    response = await enroll(client, body, **basic())

    assert response.status_code == 400 and message in response.text
    assert response.headers["content-type"].startswith("text/plain")


@pytest.mark.usefixtures("est")
async def test_refused_by_the_profile(client: AsyncClient, key_for: KeyFor) -> None:
    response = await enroll(client, csr_body(key_for, sans=False), **basic())

    assert response.status_code == 400 and "subject alternative name" in response.text


@pytest.mark.usefixtures("est")
async def test_same_request_gives_the_same_certificate(
    client: AsyncClient, key_for: KeyFor
) -> None:
    body = csr_body(key_for)

    first = certificates(await enroll(client, body, **basic()))
    second = certificates(await enroll(client, body, **basic()))

    assert first == second
    assert await CertificateRequest.filter(channel=Channel.EST).count() == 1


@pytest.mark.usefixtures("est")
async def test_a_revoked_certificate_is_not_given_again(
    client: AsyncClient, key_for: KeyFor, keystore: KeyStore
) -> None:
    body = csr_body(key_for)
    [first] = certificates(await enroll(client, body, **basic()))
    record = await Certificate.get(sha256_fingerprint=first.fingerprint(hashes.SHA256()).hex())
    await RevocationService(keystore).revoke(record.id, reason="superseded", actor="cli")

    [second] = certificates(await enroll(client, body, **basic()))

    assert second.serial_number != first.serial_number


# --- manual approval --------------------------------------------------------------------------


@pytest.mark.usefixtures("est")
async def test_manual_approval_with_retries(client: AsyncClient, key_for: KeyFor) -> None:
    body = base64.b64encode(
        make_csr(key_for(KeyAlgorithm.EC_P384), name(CN="Lab CA")).public_bytes(
            serialization.Encoding.DER
        )
    )

    first = await enroll(client, body, label="sub_ca", **basic())
    again = await enroll(client, body, label="sub_ca", **basic())
    [request] = await CertificateRequest.filter(channel=Channel.EST)
    approved = await client.post(f"/api/v1/requests/{request.id}/approve")
    issued = await enroll(client, body, label="sub_ca", **basic())
    replay = await enroll(client, body, label="sub_ca", **basic())

    assert first.status_code == 202 and first.headers["retry-after"] == "60"
    assert again.status_code == 202
    assert approved.status_code == 200, approved.text
    [certificate] = certificates(issued)
    assert certificates(replay) == [certificate]
    assert certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert await CertificateRequest.filter(channel=Channel.EST).count() == 1


@pytest.mark.usefixtures("est")
async def test_retry_after_follows_the_setting(client: AsyncClient, key_for: KeyFor) -> None:
    await SettingsService().set("est.retry_after_seconds", 5, actor="cli")
    body = base64.b64encode(
        make_csr(key_for(KeyAlgorithm.EC_P384), name(CN="Lab CA")).public_bytes(
            serialization.Encoding.DER
        )
    )

    response = await enroll(client, body, label="sub_ca", **basic())

    assert response.headers["retry-after"] == "5"


@pytest.mark.usefixtures("est")
async def test_rejected_request(client: AsyncClient, key_for: KeyFor) -> None:
    body = base64.b64encode(
        make_csr(key_for(KeyAlgorithm.EC_P384), name(CN="Lab CA")).public_bytes(
            serialization.Encoding.DER
        )
    )
    await enroll(client, body, label="sub_ca", **basic())
    [request] = await CertificateRequest.filter(channel=Channel.EST)
    await client.post(f"/api/v1/requests/{request.id}/reject", json={"reason": "not this one"})

    response = await enroll(client, body, label="sub_ca", **basic())

    assert response.status_code == 403
    assert response.text == "the request was rejected: not this one\n"


@pytest.mark.usefixtures("est")
async def test_another_account_does_not_get_the_request(
    client: AsyncClient, key_for: KeyFor
) -> None:
    body = csr_body(key_for)
    await EstAccountService().create("bob", password=PASSWORD, actor="cli")

    first = certificates(await enroll(client, body, **basic()))
    other = certificates(await enroll(client, body, **basic("bob")))

    assert first != other
    assert await CertificateRequest.filter(channel=Channel.EST).count() == 2


# --- client certificate from a trusted proxy (B45) --------------------------------------------


def client_cert_header(certificate: x509.Certificate) -> dict[str, str]:
    der = certificate.public_bytes(serialization.Encoding.DER)
    return {"Client-Cert": f":{base64.b64encode(der).decode()}:"}


@pytest.fixture
def trusted_proxy(app: FastAPI) -> None:
    """The test client (127.0.0.1) is a trusted proxy."""
    settings = app.state.settings
    app.state.settings = settings.model_copy(
        update={"trusted_proxies": [ipaddress.ip_network("127.0.0.0/8")]}
    )


async def client_certificate(issue: IssueFactory, key_for: KeyFor) -> x509.Certificate:
    key = key_for(KeyAlgorithm.EC_P256)
    request = await issue(
        "tls_client", csr_pem(make_csr(key, name(CN="device-1"), sans=["dns:device-1.test"]))
    )
    return x509.load_der_x509_certificate((await Certificate.get(id=request.certificate_id)).der)


@pytest.mark.usefixtures("est", "trusted_proxy")
async def test_regression_B45_client_cert_from_a_trusted_proxy_is_verified(
    client: AsyncClient, issue: IssueFactory, key_for: KeyFor, keystore: KeyStore
) -> None:
    mine = await client_certificate(issue, key_for)
    stranger_key = key_for(KeyAlgorithm.RSA2048)
    stranger_ca = _root(stranger_key)
    forged = (
        x509.CertificateBuilder()
        .subject_name(mine.subject)
        .issuer_name(stranger_ca.subject)
        .public_key(mine.public_key())
        .serial_number(mine.serial_number)
        .not_valid_before(mine.not_valid_before_utc)
        .not_valid_after(mine.not_valid_after_utc)
        .sign(stranger_key, hashes.SHA256())
    )

    accepted = await enroll(client, csr_body(key_for), **client_cert_header(mine))
    refused = await enroll(client, csr_body(key_for, "b.test"), **client_cert_header(forged))
    record = await Certificate.get(sha256_fingerprint=mine.fingerprint(hashes.SHA256()).hex())
    await RevocationService(keystore).revoke(record.id, reason="superseded", actor="cli")
    revoked = await enroll(client, csr_body(key_for, "c.test"), **client_cert_header(mine))

    assert certificates(accepted)
    fingerprint = mine.fingerprint(hashes.SHA256()).hex()
    assert await CertificateRequest.exists(requester=f"est-cert:{fingerprint}")
    assert refused.status_code == 401
    assert revoked.status_code == 401


@pytest.mark.usefixtures("est")
async def test_client_cert_header_ignored_without_trusted_proxy(
    client: AsyncClient, issue: IssueFactory, key_for: KeyFor
) -> None:
    mine = await client_certificate(issue, key_for)

    response = await enroll(client, csr_body(key_for), **client_cert_header(mine))

    assert response.status_code == 401


@pytest.mark.usefixtures("est", "trusted_proxy")
async def test_client_cert_of_an_external_anchor(client: AsyncClient, key_for: KeyFor) -> None:
    anchor_key = key_for(KeyAlgorithm.RSA2048)
    anchor = _root(anchor_key)
    leaf_key = key_for(KeyAlgorithm.EC_P256)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(name(CN="external device"))
        .issuer_name(anchor.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(anchor.not_valid_before_utc)
        .not_valid_after(anchor.not_valid_after_utc)
        .sign(anchor_key, hashes.SHA256())
    )
    refused = await enroll(client, csr_body(key_for), **client_cert_header(leaf))
    pem = anchor.public_bytes(serialization.Encoding.PEM).decode()
    await SettingsService().set("server.client_trust_anchors", [pem], actor="cli")

    accepted = await enroll(client, csr_body(key_for), **client_cert_header(leaf))

    assert refused.status_code == 401
    assert certificates(accepted)
