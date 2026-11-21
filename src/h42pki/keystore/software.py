"""Software key store: keys stored as encrypted PKCS#8 DER in the database (B18)."""

import asyncio

from pydantic import SecretStr

from h42pki.core.keys import (
    KeyAlgorithm,
    SupportedPrivateKey,
    generate_private_key,
    load_encrypted,
    public_key_der,
    serialize_encrypted,
)
from h42pki.keystore.base import StoredKey

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
