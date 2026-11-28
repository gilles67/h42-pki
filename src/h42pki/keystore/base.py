"""Key store interface (ADR-0004).

The key store is the only component that holds the passphrase and turns stored key material
into usable private keys. Services ask it for keys; ``h42pki.core`` receives the resulting
``cryptography`` objects and never sees a passphrase.

This v1 interface hands a ``cryptography`` private key to the builders, which only the software
backend can do. A PKCS#11 backend (phase 7) keeps the key on the token and cannot return such an
object: the interface will then evolve towards ``sign(key_ref, data)`` and the builders will
assemble the TBS structures themselves (spike required, see ADR-0004).
"""

from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives import hashes

from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey


@dataclass(frozen=True, repr=False)
class StoredKey:
    """What a key store returns for a new key, ready to be persisted."""

    encrypted_key: bytes
    public_key_der: bytes

    def __repr__(self) -> str:
        return f"StoredKey(<{len(self.encrypted_key)} encrypted bytes>)"


class KeyOperationFailed(Exception):
    """A key store operation failed; never says why (no oracle, no detail about the key)."""


class KeyStore(Protocol):
    async def generate(self, algorithm: KeyAlgorithm) -> StoredKey:
        """Generate a key and return its protected form and its public key."""
        ...

    async def load(self, stored: bytes) -> SupportedPrivateKey:
        """Turn the stored (protected) form back into a usable private key."""
        ...

    async def export_encrypted(self, stored: bytes, password: bytes) -> bytes:
        """Re-encrypt a stored key as PKCS#8 PEM under ``password`` (CLAUDE.md section 6.2).

        Used to load the key of the built-in HTTPS server into an ``SSLContext``: the key only
        leaves the key store encrypted, with a one-time password kept in memory.
        """
        ...

    async def export_for_enrollment(self, stored: bytes) -> bytes:
        """The key as **unencrypted** PKCS#8 DER, for EST ``serverkeygen`` only (ADR-0018).

        The single plaintext export of the key store: the EST service hands it to the client
        that asked for it, inside the TLS session (RFC 7030 section 4.4.2), once. Never logged.
        """
        ...

    async def decrypt(self, stored: bytes, ciphertext: bytes) -> bytes:
        """RSA PKCS#1 v1.5 decryption with a stored key (SCEP RA: content-encryption keys).

        Raises ``KeyOperationFailed`` for any failure, without detail. With OpenSSL 3.2 or later a
        wrong padding is not even an error (implicit rejection): pseudo-random bytes come back.
        """
        ...

    async def sign(self, stored: bytes, data: bytes, algorithm: hashes.HashAlgorithm) -> bytes:
        """Signature of ``data`` by a stored RSA key (PKCS#1 v1.5): the SCEP RA answers."""
        ...

    async def seal(self, data: bytes) -> bytes:
        """Encrypt a secret that must be read again (ADR-0011), under the passphrase."""
        ...

    async def open(self, sealed: bytes) -> bytes:
        """The data of ``seal``."""
        ...
