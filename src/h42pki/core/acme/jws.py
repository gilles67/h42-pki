"""JWS of ACME requests (RFC 8555 section 6.2, RFC 7515), JWK and thumbprints (RFC 7638).

A minimal implementation on ``cryptography`` (ADR-0020): ACME only needs the flattened JSON
serialization, four algorithms and the RFC 7638 thumbprint. ``josepy`` has no EdDSA and
``joserfc`` refuses ``EdDSA`` unless told otherwise: neither was worth a dependency.

Rules (RFC 8555 section 6.2): ``alg`` among RS256, ES256, ES384, EdDSA (never ``none`` nor a MAC);
exactly one of ``jwk`` and ``kid``; ``url`` and ``nonce`` present; no unprotected header.
"""

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from h42pki.core.acme.errors import AcmeError

PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey

MIN_RSA_BITS = 2048
MAX_JWS_BYTES = 64 * 1024
_CURVES: dict[str, tuple[type[ec.EllipticCurve], int]] = {
    "P-256": (ec.SECP256R1, 32),
    "P-384": (ec.SECP384R1, 48),
}
_EC_ALGORITHMS = {"ES256": ("P-256", hashes.SHA256), "ES384": ("P-384", hashes.SHA384)}
_B64URL = re.compile(r"[A-Za-z0-9_-]*")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: object, what: str = "value") -> bytes:
    """Strict base64url without padding (RFC 7515 section 2): anything else is malformed."""
    if not isinstance(text, str) or not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise AcmeError("malformed", f"the {what} is not base64url without padding")
    try:
        data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        raise AcmeError("malformed", f"the {what} is not base64url without padding") from None
    if b64url(data) != text:  # non-canonical trailing bits
        raise AcmeError("malformed", f"the {what} is not canonical base64url")
    return data


@dataclass(frozen=True)
class Jws:
    """A parsed flattened JWS; the signature is not verified yet."""

    protected: dict[str, Any]
    signing_input: bytes
    payload: bytes
    signature: bytes

    @property
    def alg(self) -> str:
        return str(self.protected["alg"])

    @property
    def jwk(self) -> dict[str, Any] | None:
        value = self.protected.get("jwk")
        return value if isinstance(value, dict) else None

    @property
    def kid(self) -> str | None:
        value = self.protected.get("kid")
        return value if isinstance(value, str) else None

    @property
    def url(self) -> str:
        return str(self.protected["url"])

    @property
    def nonce(self) -> str:
        return str(self.protected["nonce"])

    def json_payload(self) -> Any:
        """The payload as JSON; ``None`` for POST-as-GET (empty payload)."""
        if self.payload == b"":
            return None
        try:
            return json.loads(self.payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AcmeError("malformed", "the payload is not JSON") from None


def parse(body: bytes) -> Jws:
    """A flattened JWS (``application/jose+json``) with the header rules of ACME."""
    if len(body) > MAX_JWS_BYTES:
        raise AcmeError("malformed", "the request is too large")
    try:
        outer = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AcmeError("malformed", "the request is not a JSON object") from None
    if not isinstance(outer, dict) or set(outer) != {"protected", "payload", "signature"}:
        raise AcmeError(
            "malformed",
            "the request must be a flattened JWS with protected, payload and signature only",
        )
    protected_b64, payload_b64 = outer["protected"], outer["payload"]
    try:
        protected = json.loads(b64url_decode(protected_b64, "protected header"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AcmeError("malformed", "the protected header is not JSON") from None
    if not isinstance(protected, dict):
        raise AcmeError("malformed", "the protected header is not a JSON object")
    payload = b64url_decode(payload_b64, "payload")
    signature = b64url_decode(outer["signature"], "signature")
    _check_header(protected)
    return Jws(
        protected=protected,
        signing_input=f"{protected_b64}.{payload_b64}".encode("ascii"),
        payload=payload,
        signature=signature,
    )


def _check_header(protected: dict[str, Any]) -> None:
    alg = protected.get("alg")
    if not isinstance(alg, str) or alg not in ("RS256", "ES256", "ES384", "EdDSA"):
        raise AcmeError("badSignatureAlgorithm", f"the algorithm {alg!r} is not accepted")
    has_jwk, has_kid = "jwk" in protected, "kid" in protected
    if has_jwk == has_kid:
        raise AcmeError("malformed", "the protected header needs exactly one of jwk and kid")
    if has_jwk and not isinstance(protected["jwk"], dict):
        raise AcmeError("malformed", "jwk is not a JSON object")
    if has_kid and not isinstance(protected["kid"], str):
        raise AcmeError("malformed", "kid is not a string")
    for name in ("url", "nonce"):
        if not isinstance(protected.get(name), str) or not protected[name]:
            raise AcmeError(
                "badNonce" if name == "nonce" else "malformed",
                f"the protected header has no {name}",
            )
    if "crit" in protected:
        raise AcmeError("malformed", "no critical header parameter is supported")


# --- JWK ----------------------------------------------------------------------------------------


def _uint(jwk: dict[str, Any], name: str) -> int:
    return int.from_bytes(b64url_decode(jwk.get(name), f"JWK member {name}"), "big")


def public_key(jwk: dict[str, Any]) -> PublicKey:
    """The public key of a JWK: RSA (2048 bits or more), EC P-256 / P-384, Ed25519."""
    kty = jwk.get("kty")
    if "d" in jwk or "p" in jwk:
        raise AcmeError("badPublicKey", "the JWK holds a private key")
    try:
        if kty == "RSA":
            key = rsa.RSAPublicNumbers(_uint(jwk, "e"), _uint(jwk, "n")).public_key()
            if key.key_size < MIN_RSA_BITS:
                raise AcmeError("badPublicKey", f"RSA keys need {MIN_RSA_BITS} bits or more")
            return key
        if kty == "EC":
            crv = jwk.get("crv")
            if crv not in _CURVES:
                raise AcmeError("badPublicKey", f"the curve {crv!r} is not accepted")
            curve, size = _CURVES[str(crv)]
            x, y = (b64url_decode(jwk.get(n), f"JWK member {n}") for n in ("x", "y"))
            if len(x) != size or len(y) != size:
                raise AcmeError("badPublicKey", "the EC coordinates have the wrong length")
            return ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), curve()
            ).public_key()
        if kty == "OKP" and jwk.get("crv") == "Ed25519":
            return ed25519.Ed25519PublicKey.from_public_bytes(
                b64url_decode(jwk.get("x"), "JWK member x")
            )
    except AcmeError:
        raise
    except ValueError:
        raise AcmeError("badPublicKey", "the JWK is not a valid public key") from None
    raise AcmeError("badPublicKey", f"the key type {kty!r} is not accepted")


def jwk_of(key: PublicKey) -> dict[str, str]:
    """The public JWK of a key (members of RFC 7638 only)."""
    if isinstance(key, rsa.RSAPublicKey):
        numbers = key.public_numbers()
        return {
            "e": b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
            "kty": "RSA",
            "n": b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        }
    if isinstance(key, ec.EllipticCurvePublicKey):
        crv = {"secp256r1": "P-256", "secp384r1": "P-384"}.get(key.curve.name)
        if crv is None:
            raise AcmeError("badPublicKey", f"the curve {key.curve.name} is not accepted")
        size = _CURVES[crv][1]
        point = key.public_numbers()
        return {
            "crv": crv,
            "kty": "EC",
            "x": b64url(point.x.to_bytes(size, "big")),
            "y": b64url(point.y.to_bytes(size, "big")),
        }
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"crv": "Ed25519", "kty": "OKP", "x": b64url(raw)}


def thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 thumbprint (SHA-256, base64url) of the canonical form of ``jwk``."""
    canonical = jwk_of(public_key(jwk))
    data = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return b64url(hashlib.sha256(data).digest())


def key_authorization(token: str, jwk: dict[str, Any]) -> str:
    """RFC 8555 section 8.1: ``token || '.' || base64url(thumbprint(accountKey))``."""
    return f"{token}.{thumbprint(jwk)}"


def public_key_der(key: PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


# --- Signatures ---------------------------------------------------------------------------------


def verify(jws: Jws, key: PublicKey) -> None:
    """``AcmeError('malformed')`` unless the signature of ``jws`` verifies with ``key``."""
    alg = jws.alg
    try:
        if alg == "RS256" and isinstance(key, rsa.RSAPublicKey):
            key.verify(jws.signature, jws.signing_input, padding.PKCS1v15(), hashes.SHA256())
            return
        if alg in _EC_ALGORITHMS and isinstance(key, ec.EllipticCurvePublicKey):
            crv, digest = _EC_ALGORITHMS[alg]
            size = _CURVES[crv][1]
            if jwk_of(key)["crv"] != crv or len(jws.signature) != 2 * size:
                raise InvalidSignature
            r = int.from_bytes(jws.signature[:size], "big")
            s = int.from_bytes(jws.signature[size:], "big")
            key.verify(encode_dss_signature(r, s), jws.signing_input, ec.ECDSA(digest()))
            return
        if alg == "EdDSA" and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(jws.signature, jws.signing_input)
            return
    except InvalidSignature:
        raise AcmeError("malformed", "the JWS signature does not verify") from None
    raise AcmeError("badSignatureAlgorithm", f"the algorithm {alg} does not match the key")


def sign_raw_ecdsa(der_signature: bytes, size: int) -> bytes:
    """DER ECDSA signature → JWS form (r ‖ s, fixed length): for clients and tests."""
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(size, "big") + s.to_bytes(size, "big")
