"""A SCEP client written for the tests (RFC 8894), independent of the server where it can be.

The EnvelopedData of a request is built by ``cryptography`` (``PKCS7EnvelopeBuilder``) for AES, and
the answers are decrypted by ``cryptography`` (``pkcs7_decrypt_der``): only the SignedData with its
SCEP attributes is written with ``asn1crypto``, as no other library writes them. 3DES requests reuse
``core.cms.envelope`` (``cryptography`` cannot encrypt with it).
"""

import datetime as dt
import hashlib
import os
from dataclasses import dataclass, field

from asn1crypto import cms
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from h42pki.core import cms as scep  # also registers the SCEP attribute types in asn1crypto
from h42pki.core.cms import FailInfo, MessageType, PkiStatus

HASHES = {"sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha512": hashes.SHA512}
CHALLENGE_PASSWORD = x509.ObjectIdentifier("1.2.840.113549.1.9.7")


def self_signed(key: rsa.RSAPrivateKey, common_name: str) -> x509.Certificate:
    """The temporary certificate a SCEP client signs its first request with."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


def csr(
    key: rsa.RSAPrivateKey,
    common_name: str,
    *,
    challenge: str | None = None,
    dns: tuple[str, ...] = (),
) -> bytes:
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    )
    if dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in dns]), critical=False
        )
    if challenge is not None:
        builder = builder.add_attribute(CHALLENGE_PASSWORD, challenge.encode())
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def issuer_and_serial(certificate: x509.Certificate) -> bytes:
    parsed = asn1_x509.Certificate.load(certificate.public_bytes(serialization.Encoding.DER))
    return bytes(
        cms.IssuerAndSerialNumber(
            {"issuer": parsed.issuer, "serial_number": parsed.serial_number}
        ).dump()
    )


def issuer_and_subject(issuer: x509.Name, subject: x509.Name) -> bytes:
    """IssuerAndSubject of CertPoll (RFC 8894 section 3.3.3)."""
    issuer_der, subject_der = issuer.public_bytes(), subject.public_bytes()
    body = issuer_der + subject_der
    return b"\x30" + _length(len(body)) + body


def _length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


@dataclass
class ScepClient:
    """One client identity: a key and the certificate its messages are signed with."""

    key: rsa.RSAPrivateKey
    certificate: x509.Certificate
    ra: x509.Certificate
    cipher: str = "aes128_cbc"
    digest: str = "sha256"
    transaction_id: str = field(default_factory=lambda: os.urandom(16).hex())

    def envelope(self, content: bytes) -> bytes:
        if self.cipher == "tripledes_3key":
            return scep.envelope(content, self.ra, "tripledes_3key")
        algorithm = {"aes128_cbc": algorithms.AES128, "aes256_cbc": algorithms.AES256}[self.cipher]
        return (
            pkcs7.PKCS7EnvelopeBuilder()
            .set_data(content)
            .add_recipient(self.ra)
            .set_content_encryption_algorithm(algorithm)
            .encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
        )

    def message(
        self,
        message_type: MessageType,
        content: bytes,
        *,
        nonce: bytes | None = None,
        tamper: bool = False,
        enveloped: bytes | None = None,
    ) -> bytes:
        """A signed pkiMessage; ``tamper`` breaks the signature, ``enveloped`` replaces it."""
        inner = enveloped if enveloped is not None else self.envelope(content)
        digest = HASHES[self.digest]()
        attributes = cms.CMSAttributes(
            [
                {"type": "content_type", "values": ["data"]},
                {"type": "message_digest", "values": [hashlib.new(self.digest, inner).digest()]},
                {"type": "message_type", "values": [str(int(message_type))]},
                {"type": "transaction_id", "values": [self.transaction_id]},
                {"type": "sender_nonce", "values": [nonce or os.urandom(16)]},
            ]
        )
        to_sign = b"\x31" + attributes.dump()[1:]
        signature = self.key.sign(to_sign, padding.PKCS1v15(), digest)
        if tamper:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        certificate = asn1_x509.Certificate.load(
            self.certificate.public_bytes(serialization.Encoding.DER)
        )
        signer = cms.SignerInfo(
            {
                "version": "v1",
                "sid": cms.SignerIdentifier(
                    name="issuer_and_serial_number",
                    value=cms.IssuerAndSerialNumber(
                        {"issuer": certificate.issuer, "serial_number": certificate.serial_number}
                    ),
                ),
                "digest_algorithm": {"algorithm": self.digest},
                "signed_attrs": attributes,
                "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
                "signature": signature,
            }
        )
        signed = cms.SignedData(
            {
                "version": "v1",
                "digest_algorithms": [{"algorithm": self.digest}],
                "encap_content_info": {"content_type": "data", "content": inner},
                "certificates": [certificate],
                "signer_infos": [signer],
            }
        )
        return bytes(cms.ContentInfo({"content_type": "signed_data", "content": signed}).dump())


@dataclass(frozen=True)
class Reply:
    status: PkiStatus
    fail_info: FailInfo | None
    transaction_id: str
    recipient_nonce: bytes
    certificates: list[x509.Certificate]
    crls: list[bytes]


def read_reply(der: bytes, client: ScepClient) -> Reply:
    """Check and read a CertRep: RA signature, attributes, content decrypted by cryptography.

    ``cryptography`` only decrypts AES: a 3DES answer is decrypted with ``core.cms`` instead.
    """
    info = cms.ContentInfo.load(der)
    signed = info["content"]
    [signer] = list(signed["signer_infos"])
    attributes = {a["type"].native: a["values"][0].native for a in signer["signed_attrs"]}
    assert attributes["message_type"] == str(int(MessageType.CERT_REP))
    to_sign = b"\x31" + signer["signed_attrs"].dump()[1:]
    digest = HASHES[signer["digest_algorithm"]["algorithm"].native]()
    ra_key = client.ra.public_key()
    assert isinstance(ra_key, rsa.RSAPublicKey)
    ra_key.verify(signer["signature"].native, to_sign, padding.PKCS1v15(), digest)  # raises if bad
    status = PkiStatus(int(attributes["pki_status"]))
    fail_info = FailInfo(int(attributes["fail_info"])) if "fail_info" in attributes else None
    certificates: list[x509.Certificate] = []
    crls: list[bytes] = []
    content = signed["encap_content_info"]["content"]
    if status is PkiStatus.SUCCESS and content.native:
        sealed = scep.parse_envelope(content.native, legacy=True)
        if sealed.algorithm == "tripledes_3key":
            key = client.key.decrypt(sealed.encrypted_key, padding.PKCS1v15())
            inner = scep.decrypt_content(sealed, key)
        else:
            inner = pkcs7.pkcs7_decrypt_der(content.native, client.certificate, client.key, [])
        degenerate = cms.ContentInfo.load(inner)["content"]
        certificates = [
            x509.load_der_x509_certificate(choice.chosen.dump())
            for choice in degenerate["certificates"] or []
        ]
        crls = [crl.dump() for crl in degenerate["crls"] or []]
    return Reply(
        status=status,
        fail_info=fail_info,
        transaction_id=attributes["transaction_id"],
        recipient_nonce=attributes["recipient_nonce"],
        certificates=certificates,
        crls=crls,
    )
