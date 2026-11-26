"""OCSP responder: POST and GET, cache, revocation, errors (ADR-0017)."""

import base64
import os
from collections.abc import Callable
from datetime import timedelta
from typing import Any
from urllib.parse import quote

import pytest
import time_machine
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from fastapi import FastAPI
from httpx import AsyncClient, Response

from h42pki.api.listener import served_over_http
from h42pki.core.keys import KeyAlgorithm
from h42pki.keystore import KeyStore
from h42pki.models import Authority, Certificate
from h42pki.services.crl import CrlService
from h42pki.services.revocation import RevocationService
from h42pki.services.settings import SettingsService
from tests.conftest import IssueFactory, RootFactory
from tests.unit.core.test_issued import _root
from tests.x509_helpers import csr_pem, make_csr, name

KeyFor = Callable[[KeyAlgorithm], Any]
SHA1 = hashes.SHA1()  # noqa: S303 - CertID of RFC 5019 clients
OCSP_REQUEST = {"content-type": "application/ocsp-request"}


async def setup(
    make_root: RootFactory, issue: IssueFactory, key_for: KeyFor, **options: Any
) -> tuple[Authority, x509.Certificate, x509.Certificate, Certificate]:
    authority = await make_root(ocsp=True, **options)
    root = x509.load_der_x509_certificate((await Certificate.get(authority_id=authority.id)).der)
    host = "www.example.test"
    csr = csr_pem(make_csr(key_for(KeyAlgorithm.EC_P256), name(CN=host), sans=[f"dns:{host}"]))
    record = await Certificate.get(id=(await issue("tls_server", csr)).certificate_id)
    return authority, root, x509.load_der_x509_certificate(record.der), record


def request_der(
    leaf: x509.Certificate,
    issuer: x509.Certificate,
    *,
    nonce: bytes | None = None,
    algorithm: hashes.HashAlgorithm = SHA1,
) -> bytes:
    builder = ocsp.OCSPRequestBuilder().add_certificate(leaf, issuer, algorithm)
    if nonce is not None:
        builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
    return builder.build().public_bytes(serialization.Encoding.DER)


def parsed(response: Response) -> ocsp.OCSPResponse:
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/ocsp-response"
    return ocsp.load_der_ocsp_response(response.content)


def verified(response: Response, issuer: x509.Certificate) -> ocsp.OCSPResponse:
    answer = parsed(response)
    assert answer.response_status is ocsp.OCSPResponseStatus.SUCCESSFUL
    public_key = issuer.public_key()  # test roots are EC P-256
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    assert answer.signature_hash_algorithm is not None
    public_key.verify(
        answer.signature, answer.tbs_response_bytes, ec.ECDSA(answer.signature_hash_algorithm)
    )
    assert answer.certificates == [issuer]
    return answer


async def post(client: AsyncClient, der: bytes) -> Response:
    return await client.post("/ocsp", content=der, headers=OCSP_REQUEST)


# --- statuses ---------------------------------------------------------------------------------


@pytest.mark.parametrize("algorithm", [SHA1, hashes.SHA256()])
async def test_good_by_post(
    client: AsyncClient,
    make_root: RootFactory,
    issue: IssueFactory,
    key_for: KeyFor,
    algorithm: hashes.HashAlgorithm,
) -> None:
    _, root, leaf, _ = await setup(make_root, issue, key_for)

    response = await post(client, request_der(leaf, root, algorithm=algorithm))

    answer = verified(response, root)
    assert answer.certificate_status is ocsp.OCSPCertStatus.GOOD
    assert answer.serial_number == leaf.serial_number
    assert answer.hash_algorithm.name == algorithm.name
    assert answer.next_update_utc is not None
    assert answer.next_update_utc - answer.this_update_utc == timedelta(hours=24)
    assert response.headers["cache-control"] == "no-store"  # POST: not cacheable


async def test_revoked_with_reason(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    _, root, leaf, record = await setup(make_root, issue, key_for)
    await client.post(f"/api/v1/certificates/{record.id}/revoke", json={"reason": "key_compromise"})

    answer = verified(await post(client, request_der(leaf, root)), root)

    assert answer.certificate_status is ocsp.OCSPCertStatus.REVOKED
    assert answer.revocation_reason is x509.ReasonFlags.key_compromise
    assert answer.revocation_time_utc is not None


async def test_never_issued_serial_is_unknown(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    _, root, leaf, record = await setup(make_root, issue, key_for)
    await Certificate.filter(id=record.id).update(serial_hex="1")  # the serial was never issued

    answer = verified(await post(client, request_der(leaf, root)), root)

    assert answer.certificate_status is ocsp.OCSPCertStatus.UNKNOWN


async def test_unknown_issuer_is_unauthorized(
    client: AsyncClient,
    make_root: RootFactory,
    issue: IssueFactory,
    key_for: KeyFor,
) -> None:
    _, _, leaf, _ = await setup(make_root, issue, key_for)
    stranger = _root(key_for(KeyAlgorithm.RSA2048))

    answer = parsed(await post(client, request_der(leaf, stranger)))

    assert answer.response_status is ocsp.OCSPResponseStatus.UNAUTHORIZED


@pytest.mark.parametrize("body", [b"", b"not an OCSP request", os.urandom(70 * 1024)])
async def test_malformed_post(
    client: AsyncClient,
    make_root: RootFactory,
    issue: IssueFactory,
    key_for: KeyFor,
    body: bytes,
) -> None:
    await setup(make_root, issue, key_for)

    answer = parsed(await post(client, body))

    assert answer.response_status is ocsp.OCSPResponseStatus.MALFORMED_REQUEST


async def test_nonce_is_echoed_and_never_cached(
    app: FastAPI, client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    _, root, leaf, _ = await setup(make_root, issue, key_for)
    der = request_der(leaf, root, nonce=b"0123456789abcdef")
    path = "/ocsp/" + quote(base64.b64encode(der).decode(), safe="")

    first = await client.get(path)
    second = await client.get(path)

    answer = verified(first, root)
    assert answer.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce == (
        b"0123456789abcdef"
    )
    assert first.headers["cache-control"] == "no-store"
    assert first.content != second.content  # signed again: thisUpdate or signature differ
    assert len(app.state.ocsp_cache) == 0


async def test_oversized_nonce_is_malformed(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    _, root, leaf, _ = await setup(make_root, issue, key_for)

    answer = parsed(await post(client, request_der(leaf, root, nonce=bytes(33))))

    assert answer.response_status is ocsp.OCSPResponseStatus.MALFORMED_REQUEST


# --- GET (RFC 6960 appendix A.1) --------------------------------------------------------------


def encoded_with_slash_and_plus(leaf: x509.Certificate, root: x509.Certificate) -> str:
    """A request whose base64 holds both "/" and "+" (the nonce is varied until it does)."""
    for counter in range(10_000):
        der = request_der(leaf, root, nonce=counter.to_bytes(4, "big") + b"h42pki")
        text = base64.b64encode(der).decode()
        if "/" in text and "+" in text:
            return text
    raise AssertionError("no such request")  # pragma: no cover


@pytest.mark.parametrize("encode", [True, False])
async def test_get_with_slash_and_plus(
    client: AsyncClient,
    make_root: RootFactory,
    issue: IssueFactory,
    key_for: KeyFor,
    encode: bool,
) -> None:
    _, root, leaf, _ = await setup(make_root, issue, key_for)
    text = encoded_with_slash_and_plus(leaf, root)

    response = await client.get("/ocsp/" + (quote(text, safe="") if encode else text))

    assert verified(response, root).certificate_status is ocsp.OCSPCertStatus.GOOD


async def test_get_cache_headers_and_reuse(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    _, root, leaf, _ = await setup(make_root, issue, key_for)
    path = "/ocsp/" + quote(base64.b64encode(request_der(leaf, root)).decode(), safe="")

    first = await client.get(path)
    second = await client.get(path)

    answer = verified(first, root)
    assert first.content == second.content  # from the cache: signed once
    cache_control = first.headers["cache-control"]
    assert cache_control.endswith(", public, no-transform, must-revalidate")
    max_age = int(cache_control.split(",")[0].removeprefix("max-age="))
    assert 24 * 3600 - 60 < max_age <= 24 * 3600
    assert first.headers["etag"].startswith('"') and first.headers["last-modified"]
    assert answer.next_update_utc is not None
    assert first.headers["expires"].endswith("GMT")


async def test_cached_answer_regenerated_after_half_its_validity(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    _, root, leaf, _ = await setup(make_root, issue, key_for)
    der = request_der(leaf, root)
    first = parsed(await post(client, der))

    with time_machine.travel(first.this_update_utc + timedelta(hours=11, minutes=59)):
        kept = parsed(await post(client, der))
    with time_machine.travel(first.this_update_utc + timedelta(hours=12, seconds=1)):
        renewed = parsed(await post(client, der))

    assert kept.this_update_utc == first.this_update_utc
    assert renewed.this_update_utc > first.this_update_utc


@pytest.mark.parametrize("path", ["/ocsp/***", "/ocsp/QUJD", "/ocsp/%25"])
async def test_malformed_get(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor, path: str
) -> None:
    await setup(make_root, issue, key_for)

    answer = parsed(await client.get(path))

    assert answer.response_status is ocsp.OCSPResponseStatus.MALFORMED_REQUEST


# --- cache invalidation -----------------------------------------------------------------------


async def test_cache_invalidated_by_a_revocation_through_the_api(
    app: FastAPI, client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    _, root, leaf, record = await setup(make_root, issue, key_for)
    der = request_der(leaf, root)
    assert parsed(await post(client, der)).certificate_status is ocsp.OCSPCertStatus.GOOD
    cache = app.state.ocsp_cache
    assert len(cache) == 1

    await client.post(f"/api/v1/certificates/{record.id}/revoke", json={"reason": "superseded"})

    assert len(cache) == 0
    assert parsed(await post(client, der)).certificate_status is ocsp.OCSPCertStatus.REVOKED


async def test_cache_follows_a_revocation_made_by_another_process(
    client: AsyncClient,
    make_root: RootFactory,
    issue: IssueFactory,
    key_for: KeyFor,
    keystore: KeyStore,
) -> None:
    """The CLI revokes without access to the cache of the server: the stored status decides."""
    _, root, leaf, record = await setup(make_root, issue, key_for)
    der = request_der(leaf, root)
    assert parsed(await post(client, der)).certificate_status is ocsp.OCSPCertStatus.GOOD

    await RevocationService(keystore).revoke(record.id, reason="superseded", actor="cli")

    assert parsed(await post(client, der)).certificate_status is ocsp.OCSPCertStatus.REVOKED


# --- validity, availability -------------------------------------------------------------------


async def test_next_update_bounded_by_the_crl(
    client: AsyncClient,
    make_root: RootFactory,
    issue: IssueFactory,
    key_for: KeyFor,
    keystore: KeyStore,
) -> None:
    await SettingsService().set("crl.regenerate_before_hours", 2, actor="cli")
    await SettingsService().set("crl.validity_hours", 10, actor="cli")
    authority, root, leaf, _ = await setup(make_root, issue, key_for, crl=True)
    crl = await CrlService(keystore).ensure_fresh(authority)
    assert crl is not None

    answer = verified(await post(client, request_der(leaf, root)), root)

    assert answer.next_update_utc == crl.next_update


async def test_validity_follows_the_setting(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    await SettingsService().set("ocsp.response_validity_hours", 6, actor="cli")
    _, root, leaf, _ = await setup(make_root, issue, key_for)

    answer = verified(await post(client, request_der(leaf, root)), root)

    assert answer.next_update_utc is not None
    assert answer.next_update_utc - answer.this_update_utc == timedelta(hours=6)


@pytest.mark.parametrize("method", ["get", "post"])
async def test_404_without_ocsp(client: AsyncClient, make_root: RootFactory, method: str) -> None:
    await make_root()  # created without --ocsp

    response = await (client.get("/ocsp/MAA=") if method == "get" else post(client, b"\x30\x00"))

    assert response.status_code == 404
    assert response.headers["content-type"] == "application/problem+json"


async def test_revoked_ca_still_answers(
    client: AsyncClient, make_root: RootFactory, issue: IssueFactory, key_for: KeyFor
) -> None:
    from h42pki.models import AuthorityStatus

    authority, root, leaf, _ = await setup(make_root, issue, key_for)
    await Authority.filter(id=authority.id).update(status=AuthorityStatus.REVOKED)

    answer = verified(await post(client, request_der(leaf, root)), root)

    assert answer.certificate_status is ocsp.OCSPCertStatus.GOOD


def test_ocsp_is_public_over_http() -> None:
    assert served_over_http("/ocsp")
    assert served_over_http("/ocsp/MEIwQDA%2BMDwwOjAJBgUrDgMCGgUABBQ")
