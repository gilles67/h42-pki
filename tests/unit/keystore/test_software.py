import asyncio
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from pydantic import SecretStr

from h42pki.config import Settings
from h42pki.core import keys
from h42pki.core.errors import InvalidPassphrase
from h42pki.core.keys import KeyAlgorithm
from h42pki.keystore import KeyStore, SoftwareKeyStore, get_keystore

PASSPHRASE = "keystore-test-passphrase"  # noqa: S105 - not a real secret


@pytest.fixture
def keystore() -> SoftwareKeyStore:
    return SoftwareKeyStore(SecretStr(PASSPHRASE))


async def test_generate_and_load_round_trip(keystore: SoftwareKeyStore) -> None:
    stored = await keystore.generate(KeyAlgorithm.EC_P256)

    key = await keystore.load(stored.encrypted_key)

    assert keys.public_key_der(key) == stored.public_key_der
    # Encrypted PKCS#8 DER (B18): unusable without the passphrase.
    with pytest.raises(TypeError):
        serialization.load_der_private_key(stored.encrypted_key, password=None)


async def test_crypto_runs_in_worker_threads(
    keystore: SoftwareKeyStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    called: list[Callable[..., Any]] = []
    real_to_thread = asyncio.to_thread

    async def spy(func: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
        called.append(func)
        return await real_to_thread(func, *args, **kwargs)

    monkeypatch.setattr(asyncio, "to_thread", spy)

    stored = await keystore.generate(KeyAlgorithm.RSA2048)
    await keystore.load(stored.encrypted_key)

    assert called == [keys.generate_private_key, keys.serialize_encrypted, keys.load_encrypted]


async def test_wrong_passphrase_is_not_disclosed(keystore: SoftwareKeyStore) -> None:
    stored = await keystore.generate(KeyAlgorithm.ED25519)
    other = SoftwareKeyStore(SecretStr("another-passphrase"))

    with pytest.raises(InvalidPassphrase) as excinfo:
        await other.load(stored.encrypted_key)

    message = str(excinfo.value) + repr(excinfo.value)
    assert PASSPHRASE not in message
    assert "another-passphrase" not in message
    assert excinfo.value.__cause__ is None


def test_repr_hides_passphrase(keystore: SoftwareKeyStore) -> None:
    assert PASSPHRASE not in repr(keystore)
    assert PASSPHRASE not in str(vars(keystore))


async def test_stored_key_repr_hides_material(keystore: SoftwareKeyStore) -> None:
    stored = await keystore.generate(KeyAlgorithm.ED25519)

    assert repr(stored).startswith("StoredKey(<")
    assert stored.encrypted_key.hex() not in repr(stored)


def test_get_keystore_uses_settings_passphrase() -> None:
    settings = Settings(ca_passphrase=SecretStr(PASSPHRASE), environment="test")

    keystore: KeyStore = get_keystore(settings)

    assert isinstance(keystore, SoftwareKeyStore)
