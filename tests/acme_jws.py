"""JWS signing for the ACME client of the tests (RFC 7515 flattened JSON, RFC 8555 section 6.2)."""

import json
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from h42pki.core.acme.jws import b64url, jwk_of, sign_raw_ecdsa

PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey


def alg_of(key: PrivateKey) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return "RS256"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return {"secp256r1": "ES256", "secp384r1": "ES384"}[key.curve.name]
    return "EdDSA"


def sign_input(key: PrivateKey, data: bytes) -> bytes:
    if isinstance(key, rsa.RSAPrivateKey):
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    if isinstance(key, ec.EllipticCurvePrivateKey):
        size = (key.curve.key_size + 7) // 8
        digest = hashes.SHA256() if size == 32 else hashes.SHA384()
        return sign_raw_ecdsa(key.sign(data, ec.ECDSA(digest)), size)
    return key.sign(data)


def jws(
    key: PrivateKey,
    payload: Any,
    *,
    url: str,
    nonce: str | None,
    kid: str | None = None,
    extra: dict[str, Any] | None = None,
) -> bytes:
    """A flattened JWS; ``payload`` None → POST-as-GET (empty payload); ``kid`` None → jwk."""
    protected: dict[str, Any] = {"alg": alg_of(key), "url": url}
    if nonce is not None:
        protected["nonce"] = nonce
    if kid is None:
        protected["jwk"] = jwk_of(key.public_key())
    else:
        protected["kid"] = kid
    protected.update(extra or {})
    protected_b64 = b64url(json.dumps(protected).encode())
    payload_b64 = "" if payload is None else b64url(json.dumps(payload).encode())
    signature = sign_input(key, f"{protected_b64}.{payload_b64}".encode())
    return json.dumps(
        {"protected": protected_b64, "payload": payload_b64, "signature": b64url(signature)}
    ).encode()
