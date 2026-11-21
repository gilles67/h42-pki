"""Private key holders (ADR-0004)."""

from h42pki.config import Settings
from h42pki.keystore.base import KeyStore, StoredKey
from h42pki.keystore.software import SoftwareKeyStore


def get_keystore(settings: Settings) -> KeyStore:
    """Key store for these settings (software only until the PKCS#11 backend, phase 7)."""
    return SoftwareKeyStore(settings.ca_passphrase)


__all__ = ["KeyStore", "SoftwareKeyStore", "StoredKey", "get_keystore"]
