"""EST encodings (RFC 7030, RFC 8951): base64 bodies, PKCS#7 certs-only, CSR attributes, multipart.

Pure: no I/O. The routes of ``api/est`` use these to read requests and build answers.
"""

import base64
import binascii
import secrets
from collections.abc import Sequence
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

MAX_BODY_BYTES = 64 * 1024
LINE_LENGTH = 76  # base64 lines of the answers (RFC 2045)
CERTS_ONLY = "application/pkcs7-mime; smime-type=certs-only"
CSRATTRS = "application/csrattrs"
PKCS8 = "application/pkcs8"


class InvalidBase64(ValueError):
    pass


def decode_base64(body: bytes) -> bytes:
    """Base64 body of an EST request: line breaks, CRLF and spaces tolerated (RFC 8951)."""
    if len(body) > MAX_BODY_BYTES:
        raise InvalidBase64("the request body is too large")
    compact = b"".join(body.split())  # spaces, tabs, LF, CR
    if not compact:
        raise InvalidBase64("the request body is empty")
    try:
        return base64.b64decode(compact + b"=" * (-len(compact) % 4), validate=True)
    except (binascii.Error, ValueError):
        raise InvalidBase64("the request body is not base64 (RFC 7030 section 4)") from None


def encode_base64(data: bytes) -> bytes:
    """Base64 in lines of 76 characters, CRLF-separated, as EST clients expect."""
    text = base64.b64encode(data)
    lines = [text[i : i + LINE_LENGTH] for i in range(0, len(text), LINE_LENGTH)]
    return b"\r\n".join(lines) + b"\r\n"


def certs_only(certificates: Sequence[x509.Certificate]) -> bytes:
    """PKCS#7 certs-only (degenerate SignedData), DER."""
    return pkcs7.serialize_certificates(list(certificates), serialization.Encoding.DER)


# --- CSR attributes (RFC 7030 section 4.5.2) ----------------------------------------------------


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _oid(dotted: str) -> bytes:
    parts = [int(part) for part in dotted.split(".")]
    if len(parts) < 2 or parts[0] > 2 or (parts[0] < 2 and parts[1] > 39):
        raise ValueError(f"invalid object identifier {dotted!r}")
    body = bytearray()
    for value in [40 * parts[0] + parts[1], *parts[2:]]:
        chunk = [value & 0x7F]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7F))
            value >>= 7
        body += bytes(reversed(chunk))
    return b"\x06" + _der_length(len(body)) + bytes(body)


def csr_attrs(oids: Sequence[x509.ObjectIdentifier]) -> bytes:
    """``CsrAttrs ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID``, here only bare OIDs, DER."""
    content = b"".join(_oid(oid.dotted_string) for oid in oids)
    return b"\x30" + _der_length(len(content)) + content


# --- multipart/mixed (serverkeygen, RFC 7030 section 4.4.2) -------------------------------------


@dataclass(frozen=True)
class Part:
    content_type: str
    body: bytes  # raw bytes, base64-encoded in the part


def multipart_mixed(parts: Sequence[Part], boundary: str | None = None) -> tuple[str, bytes]:
    """Content-Type header value and body of a ``multipart/mixed`` answer, parts in base64."""
    boundary = boundary or f"h42pki-{secrets.token_hex(16)}"
    body = bytearray()
    for part in parts:
        body += f"--{boundary}\r\n".encode("ascii")
        body += f"Content-Type: {part.content_type}\r\n".encode("ascii")
        body += b"Content-Transfer-Encoding: base64\r\n\r\n"
        body += encode_base64(part.body)
    body += f"--{boundary}--\r\n".encode("ascii")
    return f"multipart/mixed; boundary={boundary}", bytes(body)
