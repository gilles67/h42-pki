# Legacy CA operations, being split into core/, keystore/ and services/ during lot 4.
# Keys now come from h42pki.core.keys (B8, B18); signing is still the legacy one.
import asyncio
import datetime
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from tortoise.transactions import in_transaction

from h42pki.ca.pki_models import Extensions, Subject
from h42pki.config import get_settings
from h42pki.core.keys import (
    KeyAlgorithm,
    generate_private_key,
    load_encrypted,
    serialize_encrypted,
)
from h42pki.errors import Conflict, Unprocessable
from h42pki.models import (
    AuditLog,
    Authority,
    Certificate,
    CertificateStatus,
    PrivateKey,
)

DEFAULT_ENCODING = "utf-8"


def _ca_passphrase() -> bytes:
    # Replaces the former PkiConfiguration (config/pki.json): same passphrase, same encoding.
    return get_settings().ca_passphrase.get_secret_value().encode(DEFAULT_ENCODING)


def _public_key_der(pvkey: PrivateKeyTypes) -> bytes:
    return pvkey.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class PkiPrivateKey:
    @classmethod
    async def generate(cls, algorithm: KeyAlgorithm, *, actor: str) -> PrivateKey:
        passphrase = _ca_passphrase()

        pvkey = await asyncio.to_thread(generate_private_key, algorithm)
        key_data = await asyncio.to_thread(serialize_encrypted, pvkey, passphrase)

        async with in_transaction():
            key = await PrivateKey.create(
                algorithm=algorithm,
                encrypted_key=key_data,
                public_key_der=_public_key_der(pvkey),
            )
            await AuditLog.record(
                actor=actor,
                action="private_key.generate",
                object_type="private_key",
                object_id=key.id,
                details={"algorithm": algorithm.value, "backend": key.backend.value},
            )
        return key

    @classmethod
    async def get_key(cls, key_id: UUID) -> PrivateKey:
        return await PrivateKey.get(id=key_id)

    @classmethod
    async def load_key(cls, key_id: UUID) -> tuple[PrivateKey, PrivateKeyTypes]:
        passphrase = _ca_passphrase()

        datakey = await PrivateKey.get(id=key_id)
        pvkey = await asyncio.to_thread(load_encrypted, datakey.encrypted_key, passphrase)

        return (datakey, pvkey)

    @classmethod
    async def delete_key(cls, key_id: UUID, *, actor: str) -> None:
        datakey = await PrivateKey.get(id=key_id)
        # Explicit checks give a clear 409; the RESTRICT foreign keys remain as a safety net.
        if await Certificate.filter(private_key_id=key_id).exists():
            raise Conflict("the private key is used by at least one certificate")
        if await Authority.filter(private_key_id=key_id).exists():
            raise Conflict("the private key is used by a certificate authority")
        async with in_transaction():
            await datakey.delete()
            await AuditLog.record(
                actor=actor,
                action="private_key.delete",
                object_type="private_key",
                object_id=key_id,
                details={"algorithm": datakey.algorithm.value},
            )


class PkiCertificate:
    @classmethod
    async def generate(
        cls,
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

    @classmethod
    async def self_sign(cls, cert_id: UUID, *, actor: str) -> Certificate:
        cert = await Certificate.get(id=cert_id)
        if cert.status != CertificateStatus.PENDING:
            raise Conflict(f"the certificate is already signed (status {cert.status.value})")
        if cert.private_key_id is None:
            raise Unprocessable("the certificate has no private key to self-sign with")

        (datakey, pvkey) = await PkiPrivateKey.load_key(cert.private_key_id)
        days = 3653
        expire_at = datetime.datetime.utcnow() + datetime.timedelta(days=days)

        subject = issuer = cert.subject.x509_subject()
        x509_cert = x509.CertificateBuilder()
        x509_cert = x509_cert.subject_name(subject)
        x509_cert = x509_cert.issuer_name(issuer)

        x509_cert = x509_cert.public_key(pvkey.public_key())
        x509_cert = x509_cert.serial_number(int(cert.serial_hex, 16))
        x509_cert = x509_cert.not_valid_before(datetime.datetime.utcnow())
        x509_cert = x509_cert.not_valid_after(expire_at)

        x509_cert = cert.extensions.append_extension(x509_cert)

        x509_cert = x509_cert.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(pvkey.public_key()), critical=False
        )

        x509_cert_sign = await asyncio.to_thread(x509_cert.sign, pvkey, hashes.SHA512())

        values = {
            "der": x509_cert_sign.public_bytes(serialization.Encoding.DER),
            "public_key_der": _public_key_der(pvkey),
            "sha256_fingerprint": x509_cert_sign.fingerprint(hashes.SHA256()).hex(),
            "subject_dn": x509_cert_sign.subject.rfc4514_string(),
            "not_before": x509_cert_sign.not_valid_before_utc,
            "not_after": x509_cert_sign.not_valid_after_utc,
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
                },
            )

        await cert.refresh_from_db()
        return cert

    @classmethod
    async def get_certificate(cls, cert_id: UUID) -> Certificate:
        return await Certificate.get(id=cert_id)
