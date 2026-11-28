"""core.cms: SCEP messages, round trip with the test client (RFC 8894)."""

import os
from collections.abc import Callable

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from h42pki.core.cms import (
    FailInfo,
    Malformed,
    MessageType,
    PkiStatus,
    ScepError,
    capabilities,
    cert_rep,
    certs_only,
    decrypt_content,
    envelope,
    parse_envelope,
    parse_pki_message,
    verify,
)
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from tests.scep_client import ScepClient, csr, read_reply, self_signed
from tests.unit.core.test_issued import _root

KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]


@pytest.fixture(scope="module")
def client_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def ra(key_for: KeyFor) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = key_for(KeyAlgorithm.RSA2048)
    assert isinstance(key, rsa.RSAPrivateKey)
    return key, self_signed(key, "Test RA")


def client_of(
    client_key: rsa.RSAPrivateKey, ra: tuple[rsa.RSAPrivateKey, x509.Certificate], **options: str
) -> ScepClient:
    return ScepClient(client_key, self_signed(client_key, "device"), ra[1], **options)


def serve(
    der: bytes, ra: tuple[rsa.RSAPrivateKey, x509.Certificate], *, legacy: bool = False
) -> tuple[bytes, bytes]:
    """What the server does, with the RA key at hand: the inner content and a SUCCESS CertRep."""
    ra_key, ra_cert = ra
    message = parse_pki_message(der)
    verify(message, legacy=legacy)
    sealed = parse_envelope(message.content, legacy=legacy)
    content = decrypt_content(sealed, ra_key.decrypt(sealed.encrypted_key, padding.PKCS1v15()))
    issued = self_signed(ra_key, "issued")  # stands for the certificate of the CA
    answer = cert_rep(
        ra=ra_cert,
        digest_algorithm=message.digest_algorithm,
        transaction_id=message.transaction_id,
        recipient_nonce=message.sender_nonce,
        status=PkiStatus.SUCCESS,
        content=envelope(certs_only([issued]), message.signer, sealed.algorithm),
    )
    signature = ra_key.sign(answer.to_sign, padding.PKCS1v15(), answer.hash_algorithm)
    return content, answer.assemble(signature)


@pytest.mark.parametrize(
    ("cipher", "digest", "legacy"),
    [
        ("aes128_cbc", "sha256", False),
        ("aes256_cbc", "sha512", False),
        ("tripledes_3key", "sha1", True),
    ],
)
def test_round_trip(
    client_key: rsa.RSAPrivateKey,
    ra: tuple[rsa.RSAPrivateKey, x509.Certificate],
    cipher: str,
    digest: str,
    legacy: bool,
) -> None:
    client = client_of(client_key, ra, cipher=cipher, digest=digest)
    request = csr(client_key, "device", challenge="ABCD1234-SECRET")
    nonce = os.urandom(16)

    content, answer = serve(
        client.message(MessageType.PKCS_REQ, request, nonce=nonce), ra, legacy=legacy
    )
    reply = read_reply(answer, client)

    assert content == request
    assert reply.status is PkiStatus.SUCCESS and reply.fail_info is None
    assert reply.transaction_id == client.transaction_id and reply.recipient_nonce == nonce
    assert [c.subject.rfc4514_string() for c in reply.certificates] == ["CN=issued"]


def test_attributes(
    client_key: rsa.RSAPrivateKey, ra: tuple[rsa.RSAPrivateKey, x509.Certificate]
) -> None:
    client = client_of(client_key, ra)
    nonce = os.urandom(16)

    message = parse_pki_message(client.message(MessageType.RENEWAL_REQ, b"csr", nonce=nonce))

    assert message.message_type is MessageType.RENEWAL_REQ
    assert message.transaction_id == client.transaction_id and message.sender_nonce == nonce
    assert message.signer == client.certificate and message.digest_algorithm == "sha256"


def test_failure_reply(
    client_key: rsa.RSAPrivateKey, ra: tuple[rsa.RSAPrivateKey, x509.Certificate]
) -> None:
    client = client_of(client_key, ra)
    answer = cert_rep(
        ra=ra[1],
        digest_algorithm="sha256",
        transaction_id=client.transaction_id,
        recipient_nonce=b"n" * 16,
        status=PkiStatus.FAILURE,
        fail_info=FailInfo.BAD_REQUEST,
    )
    der = answer.assemble(ra[0].sign(answer.to_sign, padding.PKCS1v15(), answer.hash_algorithm))

    reply = read_reply(der, client)

    assert (reply.status, reply.fail_info, reply.certificates) == (
        PkiStatus.FAILURE,
        FailInfo.BAD_REQUEST,
        [],
    )


def test_tampered_signature(
    client_key: rsa.RSAPrivateKey, ra: tuple[rsa.RSAPrivateKey, x509.Certificate]
) -> None:
    message = parse_pki_message(
        client_of(client_key, ra).message(MessageType.PKCS_REQ, b"x", tamper=True)
    )

    with pytest.raises(ScepError) as error:
        verify(message, legacy=False)
    assert error.value.fail_info is FailInfo.BAD_MESSAGE_CHECK


def test_legacy_algorithms_refused_by_default(
    client_key: rsa.RSAPrivateKey, ra: tuple[rsa.RSAPrivateKey, x509.Certificate]
) -> None:
    sha1 = parse_pki_message(
        client_of(client_key, ra, digest="sha1").message(MessageType.PKCS_REQ, b"x")
    )
    des = parse_pki_message(
        client_of(client_key, ra, cipher="tripledes_3key").message(MessageType.PKCS_REQ, b"x")
    )

    with pytest.raises(ScepError) as digest_error:
        verify(sha1, legacy=False)
    with pytest.raises(ScepError) as cipher_error:
        parse_envelope(des.content, legacy=False)
    assert digest_error.value.fail_info is FailInfo.BAD_ALG
    assert cipher_error.value.fail_info is FailInfo.BAD_ALG
    verify(sha1, legacy=True)
    parse_envelope(des.content, legacy=True)


def test_every_decryption_failure_looks_the_same(
    client_key: rsa.RSAPrivateKey, ra: tuple[rsa.RSAPrivateKey, x509.Certificate]
) -> None:
    """Wrong key (implicit rejection), wrong length, altered content: one badMessageCheck."""
    ra_key = ra[0]
    message = parse_pki_message(
        client_of(client_key, ra).message(MessageType.PKCS_REQ, b"secret csr")
    )
    sealed = parse_envelope(message.content, legacy=False)
    good = ra_key.decrypt(sealed.encrypted_key, padding.PKCS1v15())
    wrong_key = client_key.decrypt(sealed.encrypted_key, padding.PKCS1v15())  # implicit rejection
    altered = type(sealed)(
        **{**sealed.__dict__, "encrypted_content": bytes(16) + sealed.encrypted_content[16:]}
    )

    reasons = set()
    for envelope_, key in (
        (sealed, wrong_key),
        (sealed, good[:-1]),
        (sealed, os.urandom(16)),
        (altered, good),
    ):
        with pytest.raises(ScepError) as error:
            decrypt_content(envelope_, key)
        assert error.value.fail_info is FailInfo.BAD_MESSAGE_CHECK
        reasons.add(error.value.reason)
    assert reasons == {"the content cannot be decrypted"}
    assert decrypt_content(sealed, good) == b"secret csr"


@pytest.mark.parametrize("der", [b"", b"garbage", bytes(64)])
def test_unreadable_message(der: bytes) -> None:
    with pytest.raises(Malformed):
        parse_pki_message(der)


def test_answer_needs_an_rsa_recipient(key_for: KeyFor) -> None:
    ec_key = key_for(KeyAlgorithm.EC_P256)

    with pytest.raises(ScepError) as error:
        envelope(b"x", _root(ec_key), "aes128_cbc")
    assert error.value.fail_info is FailInfo.BAD_ALG


def test_capabilities() -> None:
    assert capabilities(False) == [
        "POSTPKIOperation", "SHA-256", "SHA-512", "AES", "SCEPStandard", "Renewal",
    ]  # fmt: skip
    assert capabilities(True)[-2:] == ["DES3", "SHA-1"]
    assert "GetNextCACert" not in capabilities(True)


# --- malformed and refused messages -------------------------------------------------------------


def _signed(info_content: dict[str, object]) -> bytes:
    from asn1crypto import cms as asn1_cms

    return bytes(
        asn1_cms.ContentInfo({"content_type": "signed_data", "content": info_content}).dump()
    )


def test_not_a_signed_data() -> None:
    from asn1crypto import cms as asn1_cms

    data = bytes(asn1_cms.ContentInfo({"content_type": "data", "content": b"x"}).dump())

    with pytest.raises(Malformed, match="not a SignedData"):
        parse_pki_message(data)


def test_scep_attributes_required(
    client_key: rsa.RSAPrivateKey, ra: tuple[rsa.RSAPrivateKey, x509.Certificate]
) -> None:
    from asn1crypto import cms as asn1_cms

    der = client_of(client_key, ra).message(MessageType.PKCS_REQ, b"x")
    info = asn1_cms.ContentInfo.load(der)
    signed = info["content"]
    signer = signed["signer_infos"][0]
    signer["signed_attrs"] = asn1_cms.CMSAttributes(
        [a for a in signer["signed_attrs"] if a["type"].native != "transaction_id"]
    )

    with pytest.raises(Malformed, match="transactionID"):
        parse_pki_message(bytes(info.dump(force=True)))


def test_signer_certificate_required(
    client_key: rsa.RSAPrivateKey, ra: tuple[rsa.RSAPrivateKey, x509.Certificate]
) -> None:
    from asn1crypto import cms as asn1_cms

    der = client_of(client_key, ra).message(MessageType.PKCS_REQ, b"x")
    info = asn1_cms.ContentInfo.load(der)
    info["content"]["certificates"] = None

    with pytest.raises(Malformed, match="signer certificate"):
        parse_pki_message(bytes(info.dump(force=True)))


def test_message_digest_must_match(
    client_key: rsa.RSAPrivateKey, ra: tuple[rsa.RSAPrivateKey, x509.Certificate]
) -> None:
    from dataclasses import replace

    message = parse_pki_message(client_of(client_key, ra).message(MessageType.PKCS_REQ, b"x"))

    with pytest.raises(ScepError, match="messageDigest") as error:
        verify(replace(message, content=message.content + b"!"), legacy=False)
    assert error.value.fail_info is FailInfo.BAD_MESSAGE_CHECK


@pytest.mark.parametrize("der", [b"", b"junk", bytes(certs_only([]))])
def test_unreadable_envelope(der: bytes) -> None:
    with pytest.raises(ScepError) as error:
        parse_envelope(der, legacy=False)
    assert error.value.fail_info is FailInfo.BAD_MESSAGE_CHECK
