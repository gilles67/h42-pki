"""Private key holders (ADR-0004)."""

from h42pki.config import Settings
from h42pki.errors import MissingPassphrase
from h42pki.keystore.base import KeyStore, StoredKey
from h42pki.keystore.software import SoftwareKeyStore

KEY_OPERATIONS_REQUIREMENT = (
    "H42_PKI_CA_PASSPHRASE (or H42_PKI_CA_PASSPHRASE_FILE, or the Docker secret "
    "h42_pki_ca_passphrase) is required for operations on private keys"
)


def get_keystore(settings: Settings) -> KeyStore:
    """Key store for these settings (software only until the PKCS#11 backend, phase 7)."""
    if settings.ca_passphrase is None:
        raise MissingPassphrase(KEY_OPERATIONS_REQUIREMENT)
    return SoftwareKeyStore(settings.ca_passphrase)


__all__ = [
    "KEY_OPERATIONS_REQUIREMENT",
    "KeyStore",
    "SoftwareKeyStore",
    "StoredKey",
    "get_keystore",
]
