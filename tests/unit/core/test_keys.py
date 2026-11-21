from collections.abc import Callable

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from h42pki.core.errors import InvalidPassphrase, UnsupportedAlgorithm
from h42pki.core.keys import (
    KeyAlgorithm,
    SupportedPrivateKey,
    algorithm_of,
    load_encrypted,
    public_key_der,
    serialize_encrypted,
    signature_hash,
)
from tests.conftest import ALL_ALGORITHMS

PASSPHRASE = b"unit-test-passphrase"
KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]

EXPECTED_TYPE: dict[KeyAlgorithm, type] = {
    KeyAlgorithm.RSA2048: rsa.RSAPrivateKey,
    KeyAlgorithm.RSA3072: rsa.RSAPrivateKey,
    KeyAlgorithm.RSA4096: rsa.RSAPrivateKey,
    KeyAlgorithm.EC_P256: ec.EllipticCurvePrivateKey,
    KeyAlgorithm.EC_P384: ec.EllipticCurvePrivateKey,
    KeyAlgorithm.ED25519: ed25519.Ed25519PrivateKey,
}
EXPECTED_HASH: dict[KeyAlgorithm, type | None] = {
    KeyAlgorithm.RSA2048: hashes.SHA256,
    KeyAlgorithm.RSA3072: hashes.SHA256,
    KeyAlgorithm.RSA4096: hashes.SHA256,
    KeyAlgorithm.EC_P256: hashes.SHA256,
    KeyAlgorithm.EC_P384: hashes.SHA384,
    KeyAlgorithm.ED25519: None,
}


@pytest.mark.parametrize("algorithm", ALL_ALGORITHMS)
def test_generate(algorithm: KeyAlgorithm, key_for: KeyFor) -> None:
    key = key_for(algorithm)

    assert isinstance(key, EXPECTED_TYPE[algorithm])
    assert algorithm_of(key) is algorithm


@pytest.mark.parametrize("algorithm", ALL_ALGORITHMS)
def test_encrypted_pkcs8_round_trip(algorithm: KeyAlgorithm, key_for: KeyFor) -> None:
    key = key_for(algorithm)

    data = serialize_encrypted(key, PASSPHRASE)
    loaded = load_encrypted(data, PASSPHRASE)

    assert not data.startswith(b"-----")  # DER, not PEM
    assert public_key_der(loaded) == public_key_der(key)
    with pytest.raises(TypeError):  # encrypted: unusable without the passphrase
        serialization.load_der_private_key(data, password=None)


@pytest.mark.parametrize("algorithm", ALL_ALGORITHMS)
def test_wrong_passphrase_rejected(algorithm: KeyAlgorithm, key_for: KeyFor) -> None:
    data = serialize_encrypted(key_for(algorithm), PASSPHRASE)

    with pytest.raises(InvalidPassphrase) as excinfo:
        load_encrypted(data, b"wrong-passphrase")

    assert excinfo.value.__cause__ is None
    assert excinfo.value.__suppress_context__
    assert "wrong-passphrase" not in str(excinfo.value)
    assert excinfo.value.status_code == 500


def test_garbage_rejected() -> None:
    with pytest.raises(InvalidPassphrase):
        load_encrypted(b"not a key", PASSPHRASE)


@pytest.mark.parametrize("algorithm", ALL_ALGORITHMS)
def test_signature_hash(algorithm: KeyAlgorithm, key_for: KeyFor) -> None:
    hash_algorithm = signature_hash(key_for(algorithm))
    expected = EXPECTED_HASH[algorithm]

    if expected is None:
        assert hash_algorithm is None
    else:
        assert isinstance(hash_algorithm, expected)


def test_unsupported_curve_rejected() -> None:
    key = ec.generate_private_key(ec.SECP521R1())

    with pytest.raises(UnsupportedAlgorithm):
        algorithm_of(key)
    assert UnsupportedAlgorithm.status_code == 422
