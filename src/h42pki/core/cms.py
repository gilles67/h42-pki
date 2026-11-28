"""CMS for SCEP (RFC 8894): SignedData and EnvelopedData with the SCEP authenticated attributes.

``asn1crypto`` reads and writes the structures (``cryptography`` neither reads nor writes arbitrary
authenticated attributes); ``cryptography`` does the cryptography. Pure: no private key here. The RA
key decrypts the content-encryption key and signs the answers through the key store (ADR-0019):
this module only hands over the bytes to decrypt or to sign.

Checked by the spike of phase 5: with OpenSSL 4 (``cryptography`` 48), RSA PKCS#1 v1.5 decryption
uses implicit rejection (a wrong padding gives pseudo-random bytes, no error): every failure then
ends in the same ``badMessageCheck``, whatever its cause.
"""

import hashlib
import hmac
import os
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum

from asn1crypto import cms, core
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- SCEP attributes (RFC 8894 section 3.2.1) ---------------------------------------------------


class _SetOfPrintableString(core.SetOf):  # type: ignore[misc]
    _child_spec = core.PrintableString


class _SetOfOctetString(core.SetOf):  # type: ignore[misc]
    _child_spec = core.OctetString


SCEP_ATTRIBUTES: dict[str, tuple[str, type[core.SetOf]]] = {
    "2.16.840.1.113733.1.9.2": ("message_type", _SetOfPrintableString),
    "2.16.840.1.113733.1.9.3": ("pki_status", _SetOfPrintableString),
    "2.16.840.1.113733.1.9.4": ("fail_info", _SetOfPrintableString),
    "2.16.840.1.113733.1.9.5": ("sender_nonce", _SetOfOctetString),
    "2.16.840.1.113733.1.9.6": ("recipient_nonce", _SetOfOctetString),
    "2.16.840.1.113733.1.9.7": ("transaction_id", _SetOfPrintableString),
}
# Documented extension point of asn1crypto: teach it the SCEP attribute types.
for _oid, (_name, _spec) in SCEP_ATTRIBUTES.items():
    cms.CMSAttributeType._map[_oid] = _name  # noqa: SLF001
    cms.CMSAttribute._oid_specs[_name] = _spec  # noqa: SLF001


class MessageType(IntEnum):
    CERT_REP = 3
    RENEWAL_REQ = 17
    PKCS_REQ = 19
    CERT_POLL = 20
    GET_CERT = 21
    GET_CRL = 22


class PkiStatus(IntEnum):
    SUCCESS = 0
    FAILURE = 2
    PENDING = 3


class FailInfo(IntEnum):
    BAD_ALG = 0
    BAD_MESSAGE_CHECK = 1
    BAD_REQUEST = 2
    BAD_TIME = 3
    BAD_CERT_ID = 4


class Malformed(ValueError):
    """The outer message cannot be read at all: HTTP 400, no CertRep possible."""


class ScepError(Exception):
    """A protocol error, answered by a CertRep FAILURE with this failInfo."""

    def __init__(self, fail_info: FailInfo, reason: str) -> None:
        super().__init__(reason)
        self.fail_info = fail_info
        self.reason = reason


# --- algorithms ----------------------------------------------------------------------------------

DIGESTS: dict[str, type[hashes.HashAlgorithm]] = {
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}
LEGACY_DIGESTS: dict[str, type[hashes.HashAlgorithm]] = {"sha1": hashes.SHA1}
# Content encryption: asn1crypto name -> key length in bytes.
CIPHERS = {"aes128_cbc": 16, "aes256_cbc": 32}
LEGACY_CIPHERS = {"tripledes_3key": 24}


def digest_algorithms(legacy: bool) -> dict[str, type[hashes.HashAlgorithm]]:
    return {**DIGESTS, **LEGACY_DIGESTS} if legacy else dict(DIGESTS)


def content_ciphers(legacy: bool) -> dict[str, int]:
    return {**CIPHERS, **LEGACY_CIPHERS} if legacy else dict(CIPHERS)


def capabilities(legacy: bool) -> list[str]:
    """GetCACaps (RFC 8894 section 3.5.2); no GetNextCACert before the CA rollover (phase 7)."""
    caps = ["POSTPKIOperation", "SHA-256", "SHA-512", "AES", "SCEPStandard", "Renewal"]
    return [*caps, "DES3", "SHA-1"] if legacy else caps


# --- reading a pkiMessage ------------------------------------------------------------------------


@dataclass(frozen=True)
class PkiMessage:
    message_type: MessageType
    transaction_id: str
    sender_nonce: bytes
    signer: x509.Certificate
    digest_algorithm: str  # asn1crypto name, e.g. "sha256"
    content: bytes  # DER of the EnvelopedData ContentInfo (empty for none)
    _signed_attrs: bytes  # DER of the signed attributes, as signed (SET OF)
    _signature: bytes
    _content_digest: bytes  # messageDigest attribute


def _attribute(attributes: cms.CMSAttributes, name: str) -> object | None:
    for attribute in attributes:
        if attribute["type"].native == name:
            values = attribute["values"]
            return values[0].native if len(values) else None
    return None


def parse_pki_message(der: bytes) -> PkiMessage:
    """Read a pkiMessage; Malformed when it is not a SignedData with SCEP attributes.

    Nothing is verified yet: ``verify`` checks the signature, so that a failure can still be
    answered by a CertRep carrying the transactionID and the nonce.
    """
    try:
        info = cms.ContentInfo.load(der)
        if info["content_type"].native != "signed_data":
            raise Malformed("not a SignedData")
        signed = info["content"]
        [signer_info] = list(signed["signer_infos"])
        attributes = signer_info["signed_attrs"]
        message_type = _attribute(attributes, "message_type")
        transaction_id = _attribute(attributes, "transaction_id")
        sender_nonce = _attribute(attributes, "sender_nonce")
        content_digest = _attribute(attributes, "message_digest")
        if not isinstance(transaction_id, str) or not isinstance(sender_nonce, bytes):
            raise Malformed("transactionID or senderNonce missing")
        if not isinstance(message_type, str) or not isinstance(content_digest, bytes):
            raise Malformed("messageType or messageDigest missing")
        sid = signer_info["sid"]
        signer = _signer_certificate(signed, sid)
        encapsulated = signed["encap_content_info"]["content"]
        content = encapsulated.native if encapsulated.native is not None else b""
        if not isinstance(content, bytes):
            content = encapsulated.parsed.dump()
        signed_attrs = attributes.dump()
        return PkiMessage(
            message_type=MessageType(int(message_type)),
            transaction_id=transaction_id,
            sender_nonce=sender_nonce,
            signer=signer,
            digest_algorithm=signer_info["digest_algorithm"]["algorithm"].native,
            content=content,
            _signed_attrs=b"\x31" + signed_attrs[1:],  # [0] IMPLICIT -> SET OF for the signature
            _signature=signer_info["signature"].native,
            _content_digest=content_digest,
        )
    except Malformed:
        raise
    except (ValueError, TypeError, KeyError, IndexError):
        raise Malformed("unreadable pkiMessage") from None


def _signer_certificate(signed: cms.SignedData, sid: cms.SignerIdentifier) -> x509.Certificate:
    if sid.name != "issuer_and_serial_number":
        raise Malformed("the signer must be identified by issuer and serial number")
    issuer = sid.chosen["issuer"].dump()
    serial = sid.chosen["serial_number"].native
    for choice in signed["certificates"] or []:
        if choice.name != "certificate":
            continue
        certificate = choice.chosen
        if certificate.serial_number == serial and certificate.issuer.dump() == issuer:
            return x509.load_der_x509_certificate(certificate.dump())
    raise Malformed("the signer certificate is not in the message")


def verify(message: PkiMessage, *, legacy: bool) -> None:
    """Digest algorithm allowed, messageDigest of the content, signature of the signer."""
    allowed = digest_algorithms(legacy)
    if message.digest_algorithm not in allowed:
        raise ScepError(FailInfo.BAD_ALG, f"digest {message.digest_algorithm} not allowed")
    hash_algorithm = allowed[message.digest_algorithm]()
    digest = hashes.Hash(hash_algorithm)
    digest.update(message.content)
    if not hmac.compare_digest(digest.finalize(), message._content_digest):  # noqa: SLF001
        raise ScepError(FailInfo.BAD_MESSAGE_CHECK, "the messageDigest does not match")
    key = message.signer.public_key()
    if not isinstance(key, rsa.RSAPublicKey):
        # The answer is encrypted for this key (RSA key transport): an RSA key is required.
        raise ScepError(FailInfo.BAD_ALG, "the signer key must be RSA")
    data, signature = message._signed_attrs, message._signature  # noqa: SLF001
    try:
        key.verify(signature, data, asym_padding.PKCS1v15(), hash_algorithm)
    except InvalidSignature:
        raise ScepError(FailInfo.BAD_MESSAGE_CHECK, "the signature does not verify") from None


# --- EnvelopedData -------------------------------------------------------------------------------


@dataclass(frozen=True)
class Envelope:
    recipient_issuer: bytes  # DER of the Name
    recipient_serial: int
    encrypted_key: bytes
    algorithm: str
    iv: bytes
    encrypted_content: bytes


def parse_envelope(der: bytes, *, legacy: bool) -> Envelope:
    """The EnvelopedData of a request; badAlg for a refused cipher, badMessageCheck otherwise."""
    try:
        info = cms.ContentInfo.load(der)
        if info["content_type"].native != "enveloped_data":
            raise ValueError("not an EnvelopedData")
        enveloped = info["content"]
        [recipient] = list(enveloped["recipient_infos"])
        if recipient.name != "ktri":
            raise ValueError("key transport recipient expected")
        ktri = recipient.chosen
        rid = ktri["rid"]
        if rid.name != "issuer_and_serial_number":
            raise ValueError("recipient identified by issuer and serial number expected")
        content_info = enveloped["encrypted_content_info"]
        algorithm = content_info["content_encryption_algorithm"]
        name = algorithm["algorithm"].native
        envelope = Envelope(
            recipient_issuer=rid.chosen["issuer"].dump(),
            recipient_serial=rid.chosen["serial_number"].native,
            encrypted_key=ktri["encrypted_key"].native,
            algorithm=name,
            iv=algorithm["parameters"].native if name in {**CIPHERS, **LEGACY_CIPHERS} else b"",
            encrypted_content=content_info["encrypted_content"].native or b"",
        )
    except (ValueError, TypeError, KeyError, IndexError):
        raise ScepError(FailInfo.BAD_MESSAGE_CHECK, "unreadable EnvelopedData") from None
    if envelope.algorithm not in content_ciphers(legacy):
        raise ScepError(FailInfo.BAD_ALG, f"content encryption {envelope.algorithm} not allowed")
    return envelope


def _cipher(name: str, key: bytes) -> algorithms.AES | TripleDES:
    return TripleDES(key) if name == "tripledes_3key" else algorithms.AES(key)


def decrypt_content(envelope: Envelope, content_key: bytes) -> bytes:
    """The content, with the content-encryption key; any failure is the same badMessageCheck."""
    try:
        if len(content_key) != content_ciphers(True)[envelope.algorithm]:
            raise ValueError("bad key")
        cipher = _cipher(envelope.algorithm, content_key)
        decryptor = Cipher(cipher, modes.CBC(envelope.iv)).decryptor()
        padded = decryptor.update(envelope.encrypted_content) + decryptor.finalize()
        unpadder = padding.PKCS7(cipher.block_size).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except (ValueError, KeyError):
        raise ScepError(FailInfo.BAD_MESSAGE_CHECK, "the content cannot be decrypted") from None


def envelope(content: bytes, recipient: x509.Certificate, algorithm: str) -> bytes:
    """EnvelopedData ContentInfo of ``content`` for ``recipient`` (RSA key transport)."""
    key = recipient.public_key()
    if not isinstance(key, rsa.RSAPublicKey):
        raise ScepError(FailInfo.BAD_ALG, "the answer can only be encrypted for an RSA key")
    length = content_ciphers(True)[algorithm]
    content_key, iv = os.urandom(length), os.urandom(16 if algorithm in CIPHERS else 8)
    cipher = _cipher(algorithm, content_key)
    padder = padding.PKCS7(cipher.block_size).padder()
    padded = padder.update(content) + padder.finalize()
    encryptor = Cipher(cipher, modes.CBC(iv)).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    certificate = asn1_x509.Certificate.load(recipient.public_bytes(serialization.Encoding.DER))
    recipient_info = cms.RecipientInfo(
        name="ktri",
        value=cms.KeyTransRecipientInfo(
            {
                "version": "v0",
                "rid": cms.RecipientIdentifier(
                    name="issuer_and_serial_number",
                    value=cms.IssuerAndSerialNumber(
                        {"issuer": certificate.issuer, "serial_number": certificate.serial_number}
                    ),
                ),
                "key_encryption_algorithm": {"algorithm": "rsaes_pkcs1v15"},
                "encrypted_key": key.encrypt(content_key, asym_padding.PKCS1v15()),
            }
        ),
    )
    enveloped = cms.EnvelopedData(
        {
            "version": "v0",
            "recipient_infos": [recipient_info],
            "encrypted_content_info": {
                "content_type": "data",
                "content_encryption_algorithm": {"algorithm": algorithm, "parameters": iv},
                "encrypted_content": encrypted,
            },
        }
    )
    return bytes(cms.ContentInfo({"content_type": "enveloped_data", "content": enveloped}).dump())


# --- degenerate SignedData (certs-only, CRL) -----------------------------------------------------


def certs_only(
    certificates: Sequence[x509.Certificate], crls: Sequence[x509.CertificateRevocationList] = ()
) -> bytes:
    """PKCS#7 degenerate SignedData with certificates and/or CRLs (GetCACert, CertRep)."""
    from asn1crypto import crl as asn1_crl

    signed = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": [],
            "encap_content_info": {"content_type": "data"},
            "certificates": [
                asn1_x509.Certificate.load(c.public_bytes(serialization.Encoding.DER))
                for c in certificates
            ]
            or None,
            "crls": [
                asn1_crl.CertificateList.load(c.public_bytes(serialization.Encoding.DER))
                for c in crls
            ]
            or None,
            "signer_infos": [],
        }
    )
    return bytes(cms.ContentInfo({"content_type": "signed_data", "content": signed}).dump())


# --- CertRep -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class UnsignedCertRep:
    """A CertRep waiting for the signature of the RA: sign ``to_sign``, then ``assemble``."""

    to_sign: bytes
    hash_algorithm: hashes.HashAlgorithm
    _signed: cms.SignedData

    def assemble(self, signature: bytes) -> bytes:
        signed = self._signed.copy()
        signed["signer_infos"][0]["signature"] = signature
        return bytes(cms.ContentInfo({"content_type": "signed_data", "content": signed}).dump())


def cert_rep(
    *,
    ra: x509.Certificate,
    digest_algorithm: str,
    transaction_id: str,
    recipient_nonce: bytes,
    status: PkiStatus,
    fail_info: FailInfo | None = None,
    content: bytes = b"",
) -> UnsignedCertRep:
    """CertRep (messageType 3) signed by the RA; ``content`` is an EnvelopedData for SUCCESS."""
    hash_type = digest_algorithms(True).get(digest_algorithm, hashes.SHA256)
    digest_name = digest_algorithm if digest_algorithm in digest_algorithms(True) else "sha256"
    hash_algorithm = hash_type()
    message_digest = hashlib.new(digest_name, content).digest()
    attributes = [
        {"type": "content_type", "values": ["data"]},
        {"type": "message_digest", "values": [message_digest]},
        {"type": "message_type", "values": [str(int(MessageType.CERT_REP))]},
        {"type": "pki_status", "values": [str(int(status))]},
        {"type": "transaction_id", "values": [transaction_id]},
        {"type": "recipient_nonce", "values": [recipient_nonce]},
        {"type": "sender_nonce", "values": [os.urandom(16)]},
    ]
    if fail_info is not None:
        attributes.append({"type": "fail_info", "values": [str(int(fail_info))]})
    signed_attrs = cms.CMSAttributes(attributes)
    certificate = asn1_x509.Certificate.load(ra.public_bytes(serialization.Encoding.DER))
    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                name="issuer_and_serial_number",
                value=cms.IssuerAndSerialNumber(
                    {"issuer": certificate.issuer, "serial_number": certificate.serial_number}
                ),
            ),
            "digest_algorithm": {"algorithm": digest_name},
            "signed_attrs": signed_attrs,
            "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
            "signature": b"",
        }
    )
    encapsulated: dict[str, object] = {"content_type": "data"}
    if content:
        encapsulated["content"] = content
    signed = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": [{"algorithm": digest_name}],
            "encap_content_info": encapsulated,
            "certificates": [certificate],
            "signer_infos": [signer_info],
        }
    )
    to_sign = signed_attrs.dump()
    to_sign = b"\x31" + to_sign[1:]
    return UnsignedCertRep(to_sign, hash_algorithm, signed)


__all__ = [
    "Envelope",
    "FailInfo",
    "Malformed",
    "MessageType",
    "PkiMessage",
    "PkiStatus",
    "ScepError",
    "UnsignedCertRep",
    "capabilities",
    "cert_rep",
    "certs_only",
    "content_ciphers",
    "decrypt_content",
    "digest_algorithms",
    "envelope",
    "parse_envelope",
    "parse_pki_message",
    "verify",
]
