"""The local certificate authority (one active CA per container, ADR-0001)."""

import asyncio
from datetime import UTC, datetime

from cryptography import x509
from tortoise.transactions import in_transaction

from h42pki.core.extensions import BasicConstraints, Extensions, KeyUsage
from h42pki.core.issuance import DEFAULT_CA_VALIDITY_DAYS, build_self_signed, check_validity_days
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.core.names import Subject
from h42pki.core.publication import (
    PublicBaseUrl,
    normalize_public_base_url,
    validate_authority_name,
)
from h42pki.core.serial import new_serial_hex
from h42pki.errors import Conflict, InvalidRequest, MissingPassphrase, NoActiveAuthority
from h42pki.keystore import KEY_OPERATIONS_REQUIREMENT, KeyStore
from h42pki.models import (
    AuditLog,
    Authority,
    AuthorityKind,
    AuthorityStatus,
    Certificate,
    CertificateStatus,
    Channel,
    KeyPurpose,
    PrivateKey,
)
from h42pki.services.x509_fields import signed_fields

ROOT_KEY_USAGE = KeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=True)


class AuthorityService:
    def __init__(self, keystore: KeyStore | None = None) -> None:
        """``keystore`` is only needed by operations that use a private key (B32)."""
        self._key_store = keystore

    @property
    def _keystore(self) -> KeyStore:
        if self._key_store is None:
            raise MissingPassphrase(KEY_OPERATIONS_REQUIREMENT)
        return self._key_store

    async def init_root(
        self,
        *,
        name: str,
        subject: Subject,
        key_algorithm: KeyAlgorithm = KeyAlgorithm.EC_P384,
        validity_days: int = DEFAULT_CA_VALIDITY_DAYS,
        path_length: int | None = None,
        public_base_url: str | None = None,
        actor: str,
    ) -> Authority:
        """Create the local root CA: a new key, its root certificate, an active Authority."""
        check_validity_days(validity_days)
        validate_authority_name(name)
        if public_base_url is not None:
            public_base_url = normalize_public_base_url(public_base_url).url
        if path_length is not None and path_length < 0:
            raise InvalidRequest("path_length must be zero or positive")
        if (
            await Authority.filter(kind=AuthorityKind.LOCAL)
            .exclude(status=AuthorityStatus.RETIRED)
            .exists()
        ):
            raise Conflict(
                "a local certificate authority already exists (see `h42pki authority status`)"
            )
        if await Authority.exists(name=name):
            raise Conflict(f"an authority named {name!r} already exists")

        extensions = Extensions(
            basic_constraints=BasicConstraints(ca=True, path_length=path_length),
            key_usage=ROOT_KEY_USAGE,
        )
        # One key per CA (B31): always a fresh key, never an existing one.
        stored = await self._keystore.generate(key_algorithm)
        private_key = await self._keystore.load(stored.encrypted_key)
        serial_hex = new_serial_hex()
        certificate = await asyncio.to_thread(
            build_self_signed,
            subject,
            extensions,
            private_key,
            serial_hex=serial_hex,
            validity_days=validity_days,
            now=datetime.now(UTC),
        )
        fields = signed_fields(certificate)

        async with in_transaction():
            key = await PrivateKey.create(
                algorithm=key_algorithm,
                purpose=KeyPurpose.CA,
                encrypted_key=stored.encrypted_key,
                public_key_der=stored.public_key_der,
            )
            authority = await Authority.create(
                name=name,
                kind=AuthorityKind.LOCAL,
                status=AuthorityStatus.ACTIVE,
                private_key=key,
                path_length=path_length,
                public_base_url=public_base_url,
            )
            await Certificate.create(
                authority=authority,
                private_key=key,
                channel=Channel.CLI,
                status=CertificateStatus.VALID,
                **fields,
            )
            await AuditLog.record(
                actor=actor,
                action="authority.init",
                object_type="authority",
                object_id=authority.id,
                details={
                    "name": name,
                    "mode": "root",
                    "key_algorithm": key_algorithm.value,
                    "validity_days": validity_days,
                    "path_length": path_length,
                    "subject_dn": fields["subject_dn"],
                    "sha256_fingerprint": fields["sha256_fingerprint"],
                },
            )
        return await self.get_local()

    async def update_public_base_url(
        self, public_base_url: str | None, *, actor: str
    ) -> tuple[Authority, PublicBaseUrl | None]:
        """Change (or remove, with None) the public base URL of the local CA.

        Only certificates issued afterwards carry the new AIA URL; issued ones are unchanged.
        """
        authority = await self.get_local()
        normalized = (
            normalize_public_base_url(public_base_url) if public_base_url is not None else None
        )
        previous = authority.public_base_url
        new = normalized.url if normalized is not None else None
        async with in_transaction():
            await Authority.filter(id=authority.id).update(public_base_url=new)
            await AuditLog.record(
                actor=actor,
                action="authority.update",
                object_type="authority",
                object_id=authority.id,
                details={"field": "public_base_url", "previous": previous, "new": new},
            )
        authority.public_base_url = new
        return authority, normalized

    async def find_local(self) -> Authority | None:
        """The active local CA, if any (certificate and key prefetched)."""
        return (
            await Authority.filter(kind=AuthorityKind.LOCAL, status=AuthorityStatus.ACTIVE)
            .prefetch_related("certificate", "private_key", "parent__certificate")
            .first()
        )

    @staticmethod
    async def local_status() -> AuthorityStatus | None:
        """Status of the current local CA, waiting for its certificate or not."""
        authority = (
            await Authority.filter(
                kind=AuthorityKind.LOCAL,
                status__in=[AuthorityStatus.ACTIVE, AuthorityStatus.PENDING_SIGNATURE],
            )
            .order_by("status")  # active first
            .first()
        )
        return authority.status if authority is not None else None

    async def get_local(self) -> Authority:
        authority = await self.find_local()
        if authority is None:
            raise NoActiveAuthority(
                "no active certificate authority: run `h42pki authority init` first"
            )
        return authority

    async def signing_material(
        self, authority: Authority, *, now: datetime
    ) -> tuple[x509.Certificate, SupportedPrivateKey]:
        """Certificate and private key of ``authority``; 503 if its certificate has expired."""
        record = await authority.certificate
        if record.not_after <= now:
            raise NoActiveAuthority("the certificate of the local CA has expired")
        if authority.private_key is None:  # pragma: no cover - set by init_root
            raise NoActiveAuthority("the local CA has no private key")
        key = await self._keystore.load(authority.private_key.encrypted_key)
        return x509.load_der_x509_certificate(record.der), key

    async def certificate_of(self, authority: Authority) -> Certificate:
        return await authority.certificate
