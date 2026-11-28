"""SCEP PKIOperation (RFC 8894): PKCSReq, CertPoll, RenewalReq, GetCert, GetCRL (ADR-0019)."""

import base64
import logging
import os
from collections.abc import Awaitable, Callable
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
import time_machine
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import AsyncClient

from h42pki.core.cms import FailInfo, MessageType, PkiStatus
from h42pki.keystore import KeyStore
from h42pki.models import (
    Authority,
    Certificate,
    CertificateRequest,
    Channel,
    EnrollmentCredential,
    ScepTransaction,
)
from h42pki.services.crl import CrlService
from h42pki.services.revocation import RevocationService
from h42pki.services.scep_challenges import ScepChallengeService
from h42pki.services.scep_ra import ScepRaManager
from h42pki.services.settings import SettingsService
from tests.conftest import RootFactory
from tests.scep_client import (
    Reply,
    ScepClient,
    csr,
    issuer_and_serial,
    issuer_and_subject,
    read_reply,
    self_signed,
)

PKI_MESSAGE = "application/x-pki-message"
Send = Callable[..., Awaitable[Reply]]


@pytest.fixture(scope="module")
def device_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
async def ra(make_root: RootFactory, keystore: KeyStore) -> x509.Certificate:
    """An active root, SCEP enabled, its RA certificate."""
    await make_root()
    await SettingsService().set("scep.enabled", True, actor="cli")
    record = (await ScepRaManager(keystore).ensure()).certificate
    assert record is not None
    return x509.load_der_x509_certificate(record.der)


async def challenge(max_uses: int | None = 1) -> str:
    return (await ScepChallengeService().create(max_uses=max_uses, actor="cli")).challenge.text


def new_client(key: rsa.RSAPrivateKey, ra: x509.Certificate, **options: Any) -> ScepClient:
    return ScepClient(key, self_signed(key, "device-1"), ra, **options)


@pytest.fixture
def send(client: AsyncClient) -> Send:
    async def post(
        scep: ScepClient,
        message_type: MessageType,
        content: bytes,
        *,
        label: str = "tls_client",
        **options: Any,
    ) -> Reply:
        response = await client.post(
            f"/scep/{label}",
            params={"operation": "PKIOperation"},
            content=scep.message(message_type, content, **options),
            headers={"Content-Type": PKI_MESSAGE},
        )
        assert response.status_code == 200, response.text
        assert response.headers["content-type"] == PKI_MESSAGE
        return read_reply(response.content, scep)

    return post


def enrolment(key: rsa.RSAPrivateKey, secret: str | None, cn: str = "device-1") -> bytes:
    return csr(key, cn, challenge=secret, dns=(f"{cn}.test",))


# --- PKCSReq ----------------------------------------------------------------------------------


async def test_pkcsreq_auto_approved(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    text = await challenge()
    scep = new_client(device_key, ra)

    reply = await send(scep, MessageType.PKCS_REQ, enrolment(device_key, text))

    assert reply.status is PkiStatus.SUCCESS and reply.transaction_id == scep.transaction_id
    [issued] = reply.certificates
    assert issued.subject.rfc4514_string() == "CN=device-1"
    assert issued.public_key() == device_key.public_key()
    record = await Certificate.get(sha256_fingerprint=issued.fingerprint(hashes.SHA256()).hex())
    request = await CertificateRequest.get(certificate_id=record.id)
    identifier = text.split("-")[0]
    assert (request.channel, request.requester) == (Channel.SCEP, f"scep:{identifier}")
    assert request.metadata["csr_sealed"] is True
    assert text.encode() not in request.csr_der  # the CSR is sealed: no challenge in the base
    credential = await EnrollmentCredential.get(identifier=identifier)
    assert credential.use_count == 1


async def test_retransmission_gets_the_same_answer(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    text = await challenge()
    scep = new_client(device_key, ra)
    request = enrolment(device_key, text)

    first = await send(scep, MessageType.PKCS_REQ, request)
    again = await send(scep, MessageType.PKCS_REQ, request)  # same transactionID, new nonce

    assert again.status is PkiStatus.SUCCESS and again.certificates == first.certificates
    assert await CertificateRequest.filter(channel=Channel.SCEP).count() == 1
    assert (await EnrollmentCredential.get(identifier=text[:8])).use_count == 1


async def test_retransmission_with_a_new_self_signed_certificate(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    """sscep signs each run with a new self-signed certificate of the same key (regression)."""
    text = await challenge()
    scep = new_client(device_key, ra)
    request = enrolment(device_key, text)
    first = await send(scep, MessageType.PKCS_REQ, request)
    resent = replace(scep, certificate=self_signed(device_key, "device-1"))
    assert resent.certificate != scep.certificate
    poll = issuer_and_subject(
        resent.certificate.subject, x509.Name.from_rfc4514_string("CN=device-1")
    )

    again = await send(resent, MessageType.PKCS_REQ, request)
    polled = await send(resent, MessageType.CERT_POLL, poll)

    assert again.status is PkiStatus.SUCCESS and again.certificates == first.certificates
    assert polled.status is PkiStatus.SUCCESS and polled.certificates == first.certificates
    assert await CertificateRequest.filter(channel=Channel.SCEP).count() == 1


async def test_transaction_of_another_key_is_refused(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    text = await challenge(max_uses=None)
    scep = new_client(device_key, ra)
    await send(scep, MessageType.PKCS_REQ, enrolment(device_key, text))
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intruder = replace(new_client(other_key, ra), transaction_id=scep.transaction_id)

    reply = await send(intruder, MessageType.PKCS_REQ, enrolment(other_key, text))

    assert (reply.status, reply.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_REQUEST)


async def test_single_use_challenge(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    text = await challenge()
    await send(new_client(device_key, ra), MessageType.PKCS_REQ, enrolment(device_key, text))

    again = await send(
        new_client(device_key, ra), MessageType.PKCS_REQ, enrolment(device_key, text)
    )

    assert (again.status, again.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_REQUEST)


async def test_reusable_challenge(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    text = await challenge(max_uses=None)

    replies = [
        await send(
            new_client(device_key, ra), MessageType.PKCS_REQ, enrolment(device_key, text, cn)
        )
        for cn in ("device-a", "device-b", "device-c")
    ]

    assert [reply.status for reply in replies] == [PkiStatus.SUCCESS] * 3


@pytest.mark.parametrize("problem", ["none", "unknown", "disabled"])
async def test_refused_challenges(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey, problem: str
) -> None:
    from h42pki.models import CredentialStatus

    text = await challenge()
    if problem == "disabled":
        await ScepChallengeService().set_status(text[:8], CredentialStatus.DISABLED, actor="cli")
    secret = {"none": None, "unknown": "ABCDEFGH-" + "A" * 32}.get(problem, text)

    reply = await send(
        new_client(device_key, ra), MessageType.PKCS_REQ, enrolment(device_key, secret)
    )

    assert (reply.status, reply.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_REQUEST)


async def test_expired_challenge(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    text = (await ScepChallengeService().create(expires_in_hours=1, actor="cli")).challenge.text

    with time_machine.travel(timedelta(hours=1, seconds=1)):
        reply = await send(
            new_client(device_key, ra), MessageType.PKCS_REQ, enrolment(device_key, text)
        )

    assert (reply.status, reply.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_REQUEST)


async def test_disabled_profile(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    await SettingsService().set("issuance.disabled_profiles", ["tls_client"], actor="cli")
    text = await challenge()

    reply = await send(
        new_client(device_key, ra), MessageType.PKCS_REQ, enrolment(device_key, text)
    )

    assert (reply.status, reply.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_REQUEST)
    assert (await EnrollmentCredential.get(identifier=text[:8])).use_count == 0


# --- manual approval and CertPoll -------------------------------------------------------------


async def test_pending_then_approved(
    client: AsyncClient, send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    text = await challenge()
    scep = new_client(device_key, ra)
    poll = issuer_and_subject(
        scep.certificate.subject, x509.Name.from_rfc4514_string("CN=responder")
    )

    pending = await send(
        scep,
        MessageType.PKCS_REQ,
        csr(device_key, "responder", challenge=text),
        label="ocsp_signer",
    )
    still = await send(scep, MessageType.CERT_POLL, poll, label="ocsp_signer")
    [request] = await CertificateRequest.filter(channel=Channel.SCEP)
    approved = await client.post(f"/api/v1/requests/{request.id}/approve")
    issued = await send(scep, MessageType.CERT_POLL, poll, label="ocsp_signer")

    assert pending.status is PkiStatus.PENDING and still.status is PkiStatus.PENDING
    assert approved.status_code == 200, approved.text  # the sealed CSR is opened for the issuance
    assert issued.status is PkiStatus.SUCCESS
    assert issued.certificates[0].subject.rfc4514_string() == "CN=responder"
    assert (await EnrollmentCredential.get(identifier=text[:8])).use_count == 1


async def test_pending_then_rejected(
    client: AsyncClient, send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    text = await challenge()
    scep = new_client(device_key, ra)
    await send(
        scep,
        MessageType.PKCS_REQ,
        csr(device_key, "responder", challenge=text),
        label="ocsp_signer",
    )
    [request] = await CertificateRequest.filter(channel=Channel.SCEP)
    await client.post(f"/api/v1/requests/{request.id}/reject", json={"reason": "no"})

    reply = await send(scep, MessageType.CERT_POLL, b"", label="ocsp_signer")

    assert (reply.status, reply.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_REQUEST)
    # Consumed at acceptance, even though rejected afterwards.
    assert (await EnrollmentCredential.get(identifier=text[:8])).use_count == 1


async def test_poll_of_an_unknown_transaction(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    reply = await send(new_client(device_key, ra), MessageType.CERT_POLL, b"")

    assert (reply.status, reply.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_CERT_ID)


# --- protocol errors --------------------------------------------------------------------------


async def test_nonce_replayed_on_another_transaction(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    nonce = os.urandom(16)
    await send(
        new_client(device_key, ra),
        MessageType.PKCS_REQ,
        enrolment(device_key, await challenge()),
        nonce=nonce,
    )

    replay = await send(
        new_client(device_key, ra),
        MessageType.PKCS_REQ,
        enrolment(device_key, await challenge()),
        nonce=nonce,
    )

    assert (replay.status, replay.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_REQUEST)


async def test_bad_signature(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    reply = await send(
        new_client(device_key, ra),
        MessageType.PKCS_REQ,
        enrolment(device_key, await challenge()),
        tamper=True,
    )

    assert (reply.status, reply.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK)


async def test_legacy_crypto_follows_the_setting(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    refused = await send(
        new_client(device_key, ra, cipher="tripledes_3key", digest="sha1"),
        MessageType.PKCS_REQ,
        enrolment(device_key, await challenge()),
    )
    await SettingsService().set("scep.allow_legacy_crypto", True, actor="cli")
    accepted = await send(
        new_client(device_key, ra, cipher="tripledes_3key", digest="sha1"),
        MessageType.PKCS_REQ,
        enrolment(device_key, await challenge()),
    )

    assert (refused.status, refused.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_ALG)
    assert accepted.status is PkiStatus.SUCCESS  # answered with 3DES and SHA-1 as asked


async def test_encrypted_for_another_recipient(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    stranger = self_signed(device_key, "not the RA")
    scep = new_client(device_key, ra)
    enveloped = ScepClient(device_key, scep.certificate, stranger).envelope(
        enrolment(device_key, await challenge())
    )

    reply = await send(scep, MessageType.PKCS_REQ, b"", enveloped=enveloped)

    assert (reply.status, reply.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK)


@pytest.mark.parametrize("body", [b"", b"not CMS", bytes(100)])
async def test_unreadable_message_is_400(
    client: AsyncClient, ra: x509.Certificate, body: bytes
) -> None:
    response = await client.post(
        "/scep/tls_client", params={"operation": "PKIOperation"}, content=body
    )

    assert response.status_code == 400 and "unreadable SCEP message" in response.text


async def test_pki_operation_by_get(
    client: AsyncClient, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    scep = new_client(device_key, ra)
    message = base64.b64encode(
        scep.message(MessageType.PKCS_REQ, enrolment(device_key, await challenge()))
    )

    response = await client.get(
        "/scep/tls_client/pkiclient.exe",
        params={"operation": "PKIOperation", "message": message.decode()},
    )

    assert response.status_code == 200
    assert read_reply(response.content, scep).status is PkiStatus.SUCCESS


# --- RenewalReq -------------------------------------------------------------------------------


async def enrolled(send: Send, ra: x509.Certificate, key: rsa.RSAPrivateKey) -> x509.Certificate:
    reply = await send(new_client(key, ra), MessageType.PKCS_REQ, enrolment(key, await challenge()))
    [certificate] = reply.certificates
    return certificate


@pytest.mark.parametrize(
    "message_type",
    # PKCSReq signed by the current certificate, without challenge: how sscep 0.10 renews.
    [MessageType.RENEWAL_REQ, MessageType.PKCS_REQ],
)
async def test_renewal(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey, message_type: MessageType
) -> None:
    current = await enrolled(send, ra, device_key)
    scep = ScepClient(device_key, current, ra)

    reply = await send(scep, message_type, enrolment(device_key, None))  # no challenge

    assert reply.status is PkiStatus.SUCCESS
    [renewed] = reply.certificates
    assert renewed.subject == current.subject and renewed.serial_number != current.serial_number
    request = await CertificateRequest.get(
        certificate_id=(
            await Certificate.get(sha256_fingerprint=renewed.fingerprint(hashes.SHA256()).hex())
        ).id
    )
    assert request.requester.startswith("scep-cert:")


async def test_pkcsreq_without_challenge_signed_by_itself(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    reply = await send(
        new_client(device_key, ra), MessageType.PKCS_REQ, enrolment(device_key, None)
    )

    assert (reply.status, reply.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_REQUEST)
    assert await CertificateRequest.filter(channel=Channel.SCEP).count() == 0


async def test_renewal_needs_the_same_subject(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    current = await enrolled(send, ra, device_key)

    reply = await send(
        ScepClient(device_key, current, ra),
        MessageType.RENEWAL_REQ,
        enrolment(device_key, None, "other"),
    )

    assert (reply.status, reply.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_REQUEST)


async def test_renewal_with_a_revoked_or_expired_certificate(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey, keystore: KeyStore
) -> None:
    current = await enrolled(send, ra, device_key)
    with time_machine.travel(current.not_valid_after_utc + timedelta(seconds=1)):
        fresh = (await ScepRaManager(keystore).ensure()).certificate  # the first RA expired too
        assert fresh is not None
        new_ra = x509.load_der_x509_certificate(fresh.der)
        expired = await send(
            ScepClient(device_key, current, new_ra),
            MessageType.RENEWAL_REQ,
            enrolment(device_key, None),
        )
    record = await Certificate.get(sha256_fingerprint=current.fingerprint(hashes.SHA256()).hex())
    await RevocationService(keystore).revoke(record.id, reason="superseded", actor="cli")
    revoked = await send(
        ScepClient(device_key, current, ra), MessageType.RENEWAL_REQ, enrolment(device_key, None)
    )
    self_signed_only = await send(
        new_client(device_key, ra), MessageType.RENEWAL_REQ, enrolment(device_key, None)
    )

    assert (expired.status, expired.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_TIME)
    assert (revoked.status, revoked.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_REQUEST)
    assert (self_signed_only.status, self_signed_only.fail_info) == (
        PkiStatus.FAILURE,
        FailInfo.BAD_REQUEST,
    )


# --- GetCert, GetCRL --------------------------------------------------------------------------


async def test_get_cert(send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey) -> None:
    current = await enrolled(send, ra, device_key)
    scep = ScepClient(device_key, current, ra)

    found = await send(scep, MessageType.GET_CERT, issuer_and_serial(current))
    missing = await send(scep, MessageType.GET_CERT, issuer_and_serial_of(current.issuer, 12345))
    anonymous = await send(
        new_client(device_key, ra), MessageType.GET_CERT, issuer_and_serial(current)
    )

    assert found.status is PkiStatus.SUCCESS and found.certificates == [current]
    assert (missing.status, missing.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_CERT_ID)
    assert (anonymous.status, anonymous.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_REQUEST)


def issuer_and_serial_of(issuer: x509.Name, serial: int) -> bytes:
    from asn1crypto import cms
    from asn1crypto import x509 as asn1_x509

    return bytes(
        cms.IssuerAndSerialNumber(
            {"issuer": asn1_x509.Name.load(issuer.public_bytes()), "serial_number": serial}
        ).dump()
    )


async def test_get_crl(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey, keystore: KeyStore
) -> None:
    current = await enrolled(send, ra, device_key)
    scep = ScepClient(device_key, current, ra)
    without = await send(scep, MessageType.GET_CRL, issuer_and_serial(current))
    authority = await Authority.get(kind="local")
    await Authority.filter(id=authority.id).update(crl_enabled=True)
    await CrlService(keystore).ensure_fresh(await Authority.get(id=authority.id))

    with_crl = await send(scep, MessageType.GET_CRL, issuer_and_serial(current))
    # sscep names its -c certificate, the RA (whose signature it verifies).
    named_by_ra = await send(
        scep, MessageType.GET_CRL, issuer_and_serial_of(ra.subject, ra.serial_number)
    )
    other_serial = await send(scep, MessageType.GET_CRL, issuer_and_serial_of(ra.subject, 1))

    assert (without.status, without.fail_info) == (PkiStatus.FAILURE, FailInfo.BAD_REQUEST)
    assert with_crl.status is PkiStatus.SUCCESS and len(with_crl.crls) == 1
    assert x509.load_der_x509_crl(with_crl.crls[0]).issuer == current.issuer
    assert named_by_ra.status is PkiStatus.SUCCESS and named_by_ra.crls == with_crl.crls
    assert (other_serial.status, other_serial.fail_info) == (
        PkiStatus.FAILURE,
        FailInfo.BAD_CERT_ID,
    )


# --- RA renewal, CA key, secrets --------------------------------------------------------------


async def test_old_ra_still_decrypts_after_a_renewal(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey, keystore: KeyStore
) -> None:
    text = await challenge()
    scep = new_client(device_key, ra)  # encrypts for the current (soon old) RA
    await send(
        scep,
        MessageType.PKCS_REQ,
        csr(device_key, "responder", challenge=text),
        label="ocsp_signer",
    )
    with time_machine.travel(ra.not_valid_after_utc - timedelta(days=30)):
        renewed = await ScepRaManager(keystore).ensure()
        assert renewed.issued
        reply = await send(scep, MessageType.CERT_POLL, b"", label="ocsp_signer")

    assert reply.status is PkiStatus.PENDING  # decrypted by the old RA key, signed by the new RA


async def test_the_ca_key_is_never_used_by_scep(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey, keystore: KeyStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    authority = await Authority.get(kind="local").prefetch_related("private_key")
    ca_key = authority.private_key.encrypted_key
    calls: list[tuple[str, bytes]] = []
    store = type(keystore)
    for name in ("decrypt", "sign", "load"):
        original = getattr(store, name)

        async def spy(
            self: Any, stored: bytes, *args: Any, _name: str = name, _original: Any = original
        ) -> Any:
            calls.append((_name, stored))
            return await _original(self, stored, *args)

        monkeypatch.setattr(store, name, spy)
    text = await challenge()

    pending = await send(
        new_client(device_key, ra),
        MessageType.PKCS_REQ,
        csr(device_key, "responder", challenge=text),
        label="ocsp_signer",
    )

    assert pending.status is PkiStatus.PENDING
    assert {name for name, _ in calls} >= {"decrypt", "sign"}
    assert all(stored != ca_key for _, stored in calls)  # RA only: never the CA key


async def test_no_challenge_in_logs_nor_audit(
    send: Send,
    ra: x509.Certificate,
    device_key: rsa.RSAPrivateKey,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from h42pki.models import AuditLog

    caplog.set_level(logging.DEBUG)
    text = await challenge()
    await send(new_client(device_key, ra), MessageType.PKCS_REQ, enrolment(device_key, text))
    await send(
        new_client(device_key, ra), MessageType.PKCS_REQ, enrolment(device_key, text)
    )  # refused

    secret = text.split("-")[1]
    assert secret not in caplog.text
    assert secret not in " ".join(str(entry.details) for entry in await AuditLog.all())
    assert await ScepTransaction.filter().count() == 1


async def test_old_nonces_are_purged(
    send: Send, ra: x509.Certificate, device_key: rsa.RSAPrivateKey
) -> None:
    from h42pki.models import ScepNonce
    from h42pki.services.maintenance import MaintenanceService

    await send(
        new_client(device_key, ra), MessageType.PKCS_REQ, enrolment(device_key, await challenge())
    )
    assert await ScepNonce.all().count() == 1

    with time_machine.travel(timedelta(days=31)):
        await MaintenanceService.purge_service_tls()

    assert await ScepNonce.all().count() == 0
