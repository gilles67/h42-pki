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


# --- decryption, signature, sealing (SCEP RA, ADR-0019) ---------------------------------------


@pytest.fixture(scope="module")
def rsa_stored() -> Any:
    store = SoftwareKeyStore(SecretStr(PASSPHRASE))
    return asyncio.run(store.generate(KeyAlgorithm.RSA2048))


async def test_decrypt_with_the_stored_key(keystore: SoftwareKeyStore, rsa_stored: Any) -> None:
    from cryptography.hazmat.primitives.asymmetric import padding

    public = serialization.load_der_public_key(rsa_stored.public_key_der)
    ciphertext = public.encrypt(b"content key 1234", padding.PKCS1v15())  # type: ignore[union-attr]

    assert await keystore.decrypt(rsa_stored.encrypted_key, ciphertext) == b"content key 1234"


async def test_wrong_ciphertext_gives_no_padding_error(
    keystore: SoftwareKeyStore, rsa_stored: Any
) -> None:
    """OpenSSL implicit rejection: no oracle, pseudo-random bytes come back."""
    import os

    first = await keystore.decrypt(rsa_stored.encrypted_key, os.urandom(256))
    again = await keystore.decrypt(rsa_stored.encrypted_key, os.urandom(256))

    assert isinstance(first, bytes) and isinstance(again, bytes)


async def test_decrypt_and_sign_need_an_rsa_key(keystore: SoftwareKeyStore) -> None:
    from cryptography.hazmat.primitives import hashes

    from h42pki.keystore import KeyOperationFailed

    stored = await keystore.generate(KeyAlgorithm.EC_P256)

    with pytest.raises(KeyOperationFailed, match="^decryption failed$"):
        await keystore.decrypt(stored.encrypted_key, b"x" * 64)
    with pytest.raises(KeyOperationFailed, match="^signature failed$"):
        await keystore.sign(stored.encrypted_key, b"data", hashes.SHA256())


async def test_sign_with_the_stored_key(keystore: SoftwareKeyStore, rsa_stored: Any) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    signature = await keystore.sign(rsa_stored.encrypted_key, b"signed attributes", hashes.SHA256())

    public = serialization.load_der_public_key(rsa_stored.public_key_der)
    public.verify(signature, b"signed attributes", padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr, call-arg]


async def test_seal_and_open(keystore: SoftwareKeyStore) -> None:
    sealed = await keystore.seal(b"a CSR with a challenge")
    again = await keystore.seal(b"a CSR with a challenge")

    assert sealed.startswith(b"h42seal1") and b"challenge" not in sealed
    assert sealed != again  # new salt and nonce each time
    assert await keystore.open(sealed) == b"a CSR with a challenge"
    other = SoftwareKeyStore(SecretStr("another passphrase"))
    with pytest.raises(InvalidPassphrase, match="cannot be opened"):
        await other.open(sealed)
    tampered = sealed[:-1] + bytes([sealed[-1] ^ 1])
    with pytest.raises(InvalidPassphrase):
        await keystore.open(tampered)
    with pytest.raises(InvalidPassphrase):
        await keystore.open(b"not sealed")
