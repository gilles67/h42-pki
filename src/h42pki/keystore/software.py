"""Software key store: keys stored as encrypted PKCS#8 DER in the database (B18)."""

import asyncio

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pydantic import SecretStr

from h42pki.core.keys import (
    KeyAlgorithm,
    SupportedPrivateKey,
    generate_private_key,
    load_encrypted,
    open_sealed,
    public_key_der,
    seal,
    serialize_encrypted,
    serialize_encrypted_pem,
)
from h42pki.keystore.base import KeyOperationFailed, StoredKey

# Same encoding as the former PkiConfiguration (config/pki.json).
TEXT_ENCODING = "utf-8"


class SoftwareKeyStore:
    """Encrypts keys with the CA passphrase. Crypto work runs in worker threads."""

    def __init__(self, passphrase: SecretStr) -> None:
        self._passphrase = passphrase

    def __repr__(self) -> str:
        return "SoftwareKeyStore(passphrase=**********)"

    def _secret(self) -> bytes:
        return self._passphrase.get_secret_value().encode(TEXT_ENCODING)

    async def generate(self, algorithm: KeyAlgorithm) -> StoredKey:
        key = await asyncio.to_thread(generate_private_key, algorithm)
        encrypted = await asyncio.to_thread(serialize_encrypted, key, self._secret())
        return StoredKey(encrypted_key=encrypted, public_key_der=public_key_der(key))

    async def load(self, stored: bytes) -> SupportedPrivateKey:
        return await asyncio.to_thread(load_encrypted, stored, self._secret())

    async def export_encrypted(self, stored: bytes, password: bytes) -> bytes:
        key = await self.load(stored)
        return await asyncio.to_thread(serialize_encrypted_pem, key, password)

    async def export_for_enrollment(self, stored: bytes) -> bytes:
        key = await self.load(stored)
        return await asyncio.to_thread(
            key.private_bytes,
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),  # EST serverkeygen, inside TLS (ADR-0018)
        )

    async def decrypt(self, stored: bytes, ciphertext: bytes) -> bytes:
        key = await self.load(stored)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise KeyOperationFailed("decryption failed")
        try:
            return await asyncio.to_thread(key.decrypt, ciphertext, padding.PKCS1v15())
        except ValueError:
            # Not a padding error (implicit rejection, OpenSSL >= 3.2): a public check, such as
            # a ciphertext above the modulus. Same message as any other failure.
            raise KeyOperationFailed("decryption failed") from None

    async def sign(self, stored: bytes, data: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
        key = await self.load(stored)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise KeyOperationFailed("signature failed")
        return await asyncio.to_thread(key.sign, data, padding.PKCS1v15(), algorithm)

    async def seal(self, data: bytes) -> bytes:
        return await asyncio.to_thread(seal, data, self._secret())

    async def open(self, sealed: bytes) -> bytes:
        return await asyncio.to_thread(open_sealed, sealed, self._secret())
