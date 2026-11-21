"""Private key management."""

from uuid import UUID

from tortoise.transactions import in_transaction

from h42pki.core.keys import KeyAlgorithm
from h42pki.errors import Conflict
from h42pki.keystore import KeyStore
from h42pki.models import AuditLog, Authority, Certificate, PrivateKey


class KeyService:
    def __init__(self, keystore: KeyStore) -> None:
        self._keystore = keystore

    async def generate(self, algorithm: KeyAlgorithm, *, actor: str) -> PrivateKey:
        stored = await self._keystore.generate(algorithm)
        async with in_transaction():
            key = await PrivateKey.create(
                algorithm=algorithm,
                encrypted_key=stored.encrypted_key,
                public_key_der=stored.public_key_der,
            )
            await AuditLog.record(
                actor=actor,
                action="private_key.generate",
                object_type="private_key",
                object_id=key.id,
                details={"algorithm": algorithm.value, "backend": key.backend.value},
            )
        return key

    async def get(self, key_id: UUID) -> PrivateKey:
        return await PrivateKey.get(id=key_id)

    async def delete(self, key_id: UUID, *, actor: str) -> None:
        key = await PrivateKey.get(id=key_id)
        # Explicit checks give a clear 409; the RESTRICT foreign keys remain as a safety net.
        if await Certificate.exists(private_key_id=key_id):
            raise Conflict("the private key is used by at least one certificate")
        if await Authority.exists(private_key_id=key_id):
            raise Conflict("the private key is used by a certificate authority")
        async with in_transaction():
            await key.delete()
            await AuditLog.record(
                actor=actor,
                action="private_key.delete",
                object_type="private_key",
                object_id=key_id,
                details={"algorithm": key.algorithm.value},
            )
