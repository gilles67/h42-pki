"""Key algorithms, generation and PKCS#8 serialization (B8, B18).

Only ``h42pki.keystore`` calls the generation and (de)serialization functions: it is the
component that holds the passphrase (ADR-0004).
"""

import hashlib
import os
from enum import StrEnum
from typing import assert_never

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from h42pki.core.errors import InvalidPassphrase, UnsupportedAlgorithm

RSA_PUBLIC_EXPONENT = 65537

# Private key types this project generates and accepts.
SupportedPrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey


class KeyAlgorithm(StrEnum):
    RSA2048 = "rsa2048"
    RSA3072 = "rsa3072"
    RSA4096 = "rsa4096"
    EC_P256 = "ec_p256"
    EC_P384 = "ec_p384"
    ED25519 = "ed25519"


def generate_private_key(algorithm: KeyAlgorithm) -> SupportedPrivateKey:
    """Generate a new private key (slow for RSA: call it from a worker thread)."""
    match algorithm:
        case KeyAlgorithm.RSA2048:
            return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=2048)
        case KeyAlgorithm.RSA3072:
            return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=3072)
        case KeyAlgorithm.RSA4096:
            return rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=4096)
        case KeyAlgorithm.EC_P256:
            return ec.generate_private_key(ec.SECP256R1())
        case KeyAlgorithm.EC_P384:
            return ec.generate_private_key(ec.SECP384R1())
        case KeyAlgorithm.ED25519:
            return ed25519.Ed25519PrivateKey.generate()
        case _:  # pragma: no cover - exhaustive
            assert_never(algorithm)


def _supported(key: PrivateKeyTypes) -> SupportedPrivateKey:
    if isinstance(key, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey):
        return key
    raise UnsupportedAlgorithm(f"unsupported private key type {type(key).__name__}")


def public_key_algorithm(public_key: PublicKeyTypes) -> KeyAlgorithm:
    """Return the :class:`KeyAlgorithm` of a public key (from a CSR or a certificate)."""
    if isinstance(public_key, rsa.RSAPublicKey):
        try:
            return KeyAlgorithm(f"rsa{public_key.key_size}")
        except ValueError:
            raise UnsupportedAlgorithm(
                f"unsupported RSA key size {public_key.key_size} (2048, 3072 or 4096)"
            ) from None
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if isinstance(public_key.curve, ec.SECP256R1):
            return KeyAlgorithm.EC_P256
        if isinstance(public_key.curve, ec.SECP384R1):
            return KeyAlgorithm.EC_P384
        raise UnsupportedAlgorithm(f"unsupported elliptic curve {public_key.curve.name}")
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return KeyAlgorithm.ED25519
    raise UnsupportedAlgorithm(f"unsupported public key type {type(public_key).__name__}")


def algorithm_of(key: PrivateKeyTypes) -> KeyAlgorithm:
    """Return the :class:`KeyAlgorithm` of a private key."""
    return public_key_algorithm(_supported(key).public_key())


def signature_hash(key: PrivateKeyTypes) -> hashes.SHA256 | hashes.SHA384 | None:
    """Hash to sign with ``key``: SHA-256 (RSA, P-256), SHA-384 (P-384), None (Ed25519)."""
    match algorithm_of(key):
        case KeyAlgorithm.RSA2048 | KeyAlgorithm.RSA3072 | KeyAlgorithm.RSA4096:
            return hashes.SHA256()
        case KeyAlgorithm.EC_P256:
            return hashes.SHA256()
        case KeyAlgorithm.EC_P384:
            return hashes.SHA384()
        case KeyAlgorithm.ED25519:
            return None
        case _ as unreachable:  # pragma: no cover - exhaustive
            assert_never(unreachable)


def serialize_encrypted(key: PrivateKeyTypes, passphrase: bytes) -> bytes:
    """Serialize ``key`` as encrypted PKCS#8 DER (B18)."""
    return key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def serialize_encrypted_pem(key: PrivateKeyTypes, password: bytes) -> bytes:
    """Encrypted PKCS#8 PEM, the form ``ssl.SSLContext.load_cert_chain`` can read."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )


def load_encrypted(data: bytes, passphrase: bytes) -> SupportedPrivateKey:
    """Load an encrypted PKCS#8 DER key; any failure gives a generic error without details."""
    try:
        key = serialization.load_der_private_key(data, password=passphrase)
    except (ValueError, TypeError):
        # The underlying message may describe the data; keep it out (and out of the chain).
        raise InvalidPassphrase("the private key cannot be decrypted") from None
    return _supported(key)


def public_key_der(key: PrivateKeyTypes) -> bytes:
    """SubjectPublicKeyInfo of ``key``, DER encoded."""
    return spki_der(key.public_key())


def spki_der(public_key: PublicKeyTypes) -> bytes:
    """SubjectPublicKeyInfo of a public key, DER encoded."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# --- sealed secrets (ADR-0011: secrets that must be read again, encrypted with the passphrase) ----

SEAL_MAGIC = b"h42seal1"
SEAL_SALT_BYTES = 16
SEAL_NONCE_BYTES = 12
# scrypt work for the sealing key: as for the EST passwords, a few tens of milliseconds.
SEAL_SCRYPT = {"n": 2**14, "r": 8, "p": 1}


def _seal_key(passphrase: bytes, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase, salt=salt, dklen=32, maxmem=64 * 1024 * 1024, **SEAL_SCRYPT)


def seal(data: bytes, passphrase: bytes) -> bytes:
    """AES-256-GCM under a key derived from the passphrase (new salt and nonce each time)."""
    salt, nonce = os.urandom(SEAL_SALT_BYTES), os.urandom(SEAL_NONCE_BYTES)
    sealed = AESGCM(_seal_key(passphrase, salt)).encrypt(nonce, data, SEAL_MAGIC)
    return SEAL_MAGIC + salt + nonce + sealed


def open_sealed(sealed: bytes, passphrase: bytes) -> bytes:
    """The data of ``seal``; a generic error for anything else, without details."""
    head = len(SEAL_MAGIC)
    if not sealed.startswith(SEAL_MAGIC) or len(sealed) < head + SEAL_SALT_BYTES + SEAL_NONCE_BYTES:
        raise InvalidPassphrase("the sealed data cannot be opened")
    salt = sealed[head : head + SEAL_SALT_BYTES]
    nonce = sealed[head + SEAL_SALT_BYTES : head + SEAL_SALT_BYTES + SEAL_NONCE_BYTES]
    try:
        return AESGCM(_seal_key(passphrase, salt)).decrypt(
            nonce, sealed[head + SEAL_SALT_BYTES + SEAL_NONCE_BYTES :], SEAL_MAGIC
        )
    except InvalidTag:
        raise InvalidPassphrase("the sealed data cannot be opened") from None
