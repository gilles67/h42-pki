"""Shared fixtures.

The ``settings`` fixture configures the test environment through ``H42_PKI_*`` variables, as a
deployment would, and returns the resulting settings; ``client`` builds the app from them.
"""

import os
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from pathlib import Path

import pytest
from asgi_lifespan import LifespanManager
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient

from h42pki.config import ENV_PREFIX, Settings, get_settings
from h42pki.core.keys import (
    KeyAlgorithm,
    SupportedPrivateKey,
    generate_private_key,
    serialize_encrypted,
)
from h42pki.main import create_app
from h42pki.models import PrivateKey

PrivateKeyFactory = Callable[[], Awaitable[PrivateKey]]

TEST_PASSPHRASE = "test-only-passphrase"  # noqa: S105 - not a real secret


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Drop any H42_PKI_* variable from the developer environment and the settings cache."""
    for name in list(os.environ):
        if name.upper().startswith(ENV_PREFIX):
            monkeypatch.delenv(name)
    monkeypatch.setenv(f"{ENV_PREFIX}SECRETS_DIR", str(tmp_path / "no-secrets"))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "test")
    monkeypatch.setenv(f"{ENV_PREFIX}DATABASE_URL", "sqlite://:memory:")
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE", TEST_PASSPHRASE)
    get_settings.cache_clear()
    return get_settings()


@pytest.fixture
async def client(settings: Settings) -> AsyncIterator[AsyncClient]:
    app = create_app(settings)
    async with (
        LifespanManager(app) as manager,
        AsyncClient(transport=ASGITransport(app=manager.app), base_url="http://testserver") as ac,
    ):
        yield ac


@pytest.fixture(scope="session")
def rsa2048_key() -> rsa.RSAPrivateKey:
    """One RSA 2048 key for the whole session (key generation is slow)."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def make_private_key(client: AsyncClient, rsa2048_key: rsa.RSAPrivateKey) -> PrivateKeyFactory:
    """Store the session key in the database, encrypted like the application does."""
    encrypted = serialize_encrypted(rsa2048_key, TEST_PASSPHRASE.encode())
    public_key_der = rsa2048_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    async def factory() -> PrivateKey:
        return await PrivateKey.create(
            algorithm=KeyAlgorithm.RSA2048,
            encrypted_key=encrypted,
            public_key_der=public_key_der,
        )

    return factory


_SLOW_ALGORITHMS = {KeyAlgorithm.RSA4096}

# Every algorithm, with RSA 4096 marked slow (docs/testing.md section 4).
ALL_ALGORITHMS = [
    pytest.param(alg, marks=pytest.mark.slow) if alg in _SLOW_ALGORITHMS else alg
    for alg in KeyAlgorithm
]


@pytest.fixture(scope="session")
def session_keys() -> dict[KeyAlgorithm, SupportedPrivateKey]:
    """Cache of keys generated once per session and per algorithm."""
    return {}


@pytest.fixture
def key_for(
    session_keys: dict[KeyAlgorithm, SupportedPrivateKey],
) -> Callable[[KeyAlgorithm], SupportedPrivateKey]:
    def get(algorithm: KeyAlgorithm) -> SupportedPrivateKey:
        if algorithm not in session_keys:
            session_keys[algorithm] = generate_private_key(algorithm)
        return session_keys[algorithm]

    return get
