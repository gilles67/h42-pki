"""core.est: tolerant base64, certs-only, CSR attributes, multipart (RFC 7030, RFC 8951)."""

import base64
from collections.abc import Callable
from email import message_from_bytes

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtensionOID, NameOID

from h42pki.core.est import (
    InvalidBase64,
    Part,
    certs_only,
    csr_attrs,
    decode_base64,
    encode_base64,
    multipart_mixed,
)
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from tests.unit.core.test_issued import _root

KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]
DATA = bytes(range(256)) * 3


@pytest.mark.parametrize(
    "transform",
    [
        lambda text: text,
        lambda text: b"\n".join(text[i : i + 64] for i in range(0, len(text), 64)),
        lambda text: b"\r\n".join(text[i : i + 76] for i in range(0, len(text), 76)) + b"\r\n",
        lambda text: b"  " + text.rstrip(b"=") + b"\t\n",  # padding dropped, spaces
    ],
    ids=["one line", "LF", "CRLF", "no padding"],
)
def test_tolerant_base64(transform: Callable[[bytes], bytes]) -> None:
    assert decode_base64(transform(base64.b64encode(DATA))) == DATA


@pytest.mark.parametrize("body", [b"", b"   \r\n", b"not*base64", b"A" * (65 * 1024)])
def test_invalid_base64(body: bytes) -> None:
    with pytest.raises(InvalidBase64):
        decode_base64(body)


def test_encoded_lines() -> None:
    encoded = encode_base64(DATA)

    lines = encoded.split(b"\n")
    assert b"\r" not in encoded  # GNU base64 -d refuses CR
    assert all(len(line) <= 76 for line in lines) and lines[-1] == b""
    assert decode_base64(encoded) == DATA


def test_certs_only(key_for: KeyFor) -> None:
    first, second = _root(key_for(KeyAlgorithm.EC_P256)), _root(key_for(KeyAlgorithm.RSA2048))

    assert pkcs7.load_der_pkcs7_certificates(certs_only([first, second])) == [first, second]


def _read_oids(der: bytes) -> list[str]:
    """Tiny DER reader of a SEQUENCE OF OBJECT IDENTIFIER (independent of the encoder)."""
    assert der[0] == 0x30
    length, offset = der[1], 2
    if length & 0x80:
        size = length & 0x7F
        length, offset = int.from_bytes(der[2 : 2 + size], "big"), 2 + size
    assert len(der) == offset + length
    oids = []
    while offset < len(der):
        assert der[offset] == 0x06
        size = der[offset + 1]
        body = der[offset + 2 : offset + 2 + size]
        offset += 2 + size
        values, current = [], 0
        for byte in body:
            current = (current << 7) | (byte & 0x7F)
            if not byte & 0x80:
                values.append(current)
                current = 0
        first = values[0]
        head = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
        oids.append(".".join(str(value) for value in [*head, *values[1:]]))
    return oids


def test_csr_attrs() -> None:
    oids = [NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME, ExtensionOID.SUBJECT_ALTERNATIVE_NAME]

    der = csr_attrs(oids)

    assert _read_oids(der) == ["2.5.4.3", "2.5.4.10", "2.5.29.17"]
    assert csr_attrs([]) == b"\x30\x00"


def test_csr_attrs_long_and_large_oids() -> None:
    oids = [x509.ObjectIdentifier("1.2.840.113549.1.9.14")] * 20  # long content: 2-byte length

    assert _read_oids(csr_attrs(oids)) == ["1.2.840.113549.1.9.14"] * 20


def test_multipart_mixed() -> None:
    header, body = multipart_mixed(
        [Part("application/pkcs8", b"key bytes"), Part("application/pkcs7-mime", b"certs")],
        boundary="frontier",
    )

    message = message_from_bytes(f"Content-Type: {header}\r\n\r\n".encode() + body)
    parts = message.get_payload()
    assert header == "multipart/mixed; boundary=frontier"
    assert isinstance(parts, list) and len(parts) == 2
    assert [part.get_content_type() for part in parts] == [
        "application/pkcs8",
        "application/pkcs7-mime",
    ]
    assert [part.get_payload(decode=True) for part in parts] == [b"key bytes", b"certs"]
    assert all(part["Content-Transfer-Encoding"] == "base64" for part in parts)


def test_multipart_boundary_is_random() -> None:
    first, _ = multipart_mixed([Part("text/plain", b"a")])
    second, _ = multipart_mixed([Part("text/plain", b"a")])

    assert first != second
