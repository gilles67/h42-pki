"""Certificate management (self-signed root CA certificates for now)."""

import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from cryptography.hazmat.primitives import hashes, serialization
from tortoise.transactions import in_transaction

from h42pki.core.extensions import Extensions, validate_for_key
from h42pki.core.issuance import (
    DEFAULT_CA_VALIDITY_DAYS,
    build_self_signed,
    check_root_ca,
    check_validity_days,
)
from h42pki.core.keys import public_key_der
from h42pki.core.names import Subject, rfc4514
from h42pki.errors import Conflict, Unprocessable
from h42pki.keystore import KeyStore
from h42pki.models import AuditLog, Certificate, CertificateStatus, PrivateKey


class CertificateService:
    def __init__(self, keystore: KeyStore) -> None:
        self._keystore = keystore

    async def create(
        self,
        *,
        private_key_id: UUID | None,
        subject: Subject,
        extensions: Extensions,
        actor: str,
    ) -> Certificate:
        if private_key_id is not None and not await PrivateKey.exists(id=private_key_id):
            raise Unprocessable(f"private key {private_key_id} does not exist")
        async with in_transaction():
            cert = await Certificate.create(
                private_key_id=private_key_id, subject=subject, extensions=extensions
            )
            await AuditLog.record(
                actor=actor,
                action="certificate.create",
                object_type="certificate",
                object_id=cert.id,
                details={
                    "serial_hex": cert.serial_hex,
                    "private_key_id": str(private_key_id) if private_key_id else None,
                },
            )
        return cert

    async def get(self, cert_id: UUID) -> Certificate:
        return await Certificate.get(id=cert_id)

    async def self_sign(
        self,
        cert_id: UUID,
        *,
        validity_days: int = DEFAULT_CA_VALIDITY_DAYS,
        actor: str,
    ) -> Certificate:
        cert = await Certificate.get(id=cert_id).prefetch_related("private_key")
        if cert.status != CertificateStatus.PENDING:
            raise Conflict(f"the certificate is already signed (status {cert.status.value})")
        stored_key = cert.private_key
        if stored_key is None:
            raise Unprocessable("the certificate has no private key to self-sign with")
        # Cheap checks before decrypting the key.
        check_validity_days(validity_days)
        check_root_ca(cert.extensions)
        validate_for_key(cert.extensions, stored_key.algorithm)

        private_key = await self._keystore.load(stored_key.encrypted_key)
        signed = await asyncio.to_thread(
            build_self_signed,
            cert.subject,
            cert.extensions,
            private_key,
            serial_hex=cert.serial_hex,
            validity_days=validity_days,
            now=datetime.now(UTC),
        )

        values: dict[str, Any] = {
            "der": signed.public_bytes(serialization.Encoding.DER),
            "public_key_der": public_key_der(private_key),
            "sha256_fingerprint": signed.fingerprint(hashes.SHA256()).hex(),
            "subject_dn": rfc4514(signed.subject),
            "not_before": signed.not_valid_before_utc,
            "not_after": signed.not_valid_after_utc,
            "status": CertificateStatus.VALID,
        }
        async with in_transaction():
            # Conditional update: a concurrent self-sign of the same certificate loses here.
            updated = await Certificate.filter(id=cert.id, status=CertificateStatus.PENDING).update(
                **values
            )
            if not updated:
                raise Conflict("the certificate is already signed")
            await AuditLog.record(
                actor=actor,
                action="certificate.self_sign",
                object_type="certificate",
                object_id=cert.id,
                details={
                    "serial_hex": cert.serial_hex,
                    "sha256_fingerprint": values["sha256_fingerprint"],
                    "subject_dn": values["subject_dn"],
                    "validity_days": validity_days,
                },
            )

        await cert.refresh_from_db()
        return cert
