"""Schemas of the federation API."""

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from h42pki.api.admin.schemas import MAX_CSR_PEM_LENGTH, Schema, certificate_pem
from h42pki.core.federation import DEFAULT_EXPIRES_IN_HOURS, MAX_EXPIRES_IN_HOURS
from h42pki.core.validity import MAX_VALIDITY_DAYS, MIN_VALIDITY_DAYS
from h42pki.models import Authority, AuthorityStatus, FederationInvitation, InvitationStatus
from h42pki.services.federation import (
    CaRevocationReason,
    CreatedInvitation,
    Enrolment,
    effective_status,
)


class InvitationCreate(Schema):
    label: str | None = Field(default=None, min_length=1, max_length=128)
    path_length: int | None = Field(
        default=None,
        ge=0,
        le=255,
        description="Maximum pathLen of the child CA; as much as this CA allows when omitted.",
    )
    validity_days: int | None = Field(
        default=None,
        ge=MIN_VALIDITY_DAYS,
        le=MAX_VALIDITY_DAYS,
        description="Validity of the child CA; the default of the sub_ca profile when omitted.",
    )
    auto_approve: bool = Field(
        default=False, description="Issue at once instead of waiting for a manual decision."
    )
    expires_in_hours: int = Field(default=DEFAULT_EXPIRES_IN_HOURS, ge=1, le=MAX_EXPIRES_IN_HOURS)


class InvitationOut(Schema):
    id: UUID
    label: str | None
    path_length: int | None
    validity_days: int | None
    auto_approve: bool
    status: InvitationStatus
    expires_at: datetime
    created_by: str
    created_at: datetime
    used_at: datetime | None
    request_id: UUID | None

    @classmethod
    def from_model(cls, invitation: FederationInvitation) -> "InvitationOut":
        return cls(
            id=invitation.id,
            label=invitation.label,
            path_length=invitation.path_length,
            validity_days=invitation.validity_days,
            auto_approve=invitation.auto_approve,
            status=effective_status(invitation, datetime.now(UTC)),
            expires_at=invitation.expires_at,
            created_by=invitation.created_by,
            created_at=invitation.created_at,
            used_at=invitation.used_at,
            request_id=invitation.request_id,
        )


class InvitationCreated(Schema):
    """The only response that carries the token."""

    invitation: InvitationOut
    token: str = Field(description="Shown this one time: it is not stored.")
    parent_fingerprint: str = Field(description="SHA-256 of the certificate of this CA.")
    parent_url: str | None = Field(
        description="Suggested URL of this CA (port inside the container); null without hostname."
    )
    effective_path_length: int | None = Field(
        description="pathLen the child CA will get; null = unlimited."
    )
    expires_at: datetime

    @classmethod
    def from_created(
        cls, created: CreatedInvitation, *, parent_url: str | None
    ) -> "InvitationCreated":
        return cls(
            invitation=InvitationOut.from_model(created.invitation),
            token=created.token.reveal(),
            parent_fingerprint=created.parent_fingerprint,
            parent_url=parent_url,
            effective_path_length=created.effective_path_length,
            expires_at=created.invitation.expires_at,
        )


class EnrollRequest(Schema):
    csr_pem: str = Field(max_length=MAX_CSR_PEM_LENGTH)
    name: str = Field(max_length=128, description="Name of the child CA.")
    public_base_url: str | None = Field(default=None, max_length=255)


class EnrollOut(Schema):
    status: Literal["pending", "issued", "rejected", "failed"]
    enrollment_id: UUID
    certificate_pem: str | None = None
    chain_pem: str | None = Field(
        default=None, description="Chain of the parent CA, root included (issued only)."
    )
    reason: str | None = Field(default=None, description="Why it was rejected or failed.")

    @classmethod
    def from_enrolment(cls, enrolment: Enrolment) -> "EnrollOut":
        request = enrolment.request
        certificate = enrolment.certificate
        return cls(
            status=request.status.value,
            enrollment_id=request.id,
            certificate_pem=certificate_pem(certificate.der).decode() if certificate else None,
            chain_pem=(
                b"".join(certificate_pem(c.der) for c in enrolment.chain).decode()
                if certificate
                else None
            ),
            reason=request.rejection_reason or request.metadata.get("failure"),
        )


class ChildOut(Schema):
    name: str
    status: AuthorityStatus
    subject_dn: str
    certificate_id: UUID
    serial_hex: str
    sha256_fingerprint: str
    not_before: datetime
    not_after: datetime
    path_length: int | None
    public_base_url: str | None
    revoked_at: datetime | None
    revocation_reason: CaRevocationReason | None

    @classmethod
    def from_model(cls, child: Authority) -> "ChildOut":
        """``child.certificate`` must be prefetched."""
        certificate = child.certificate
        reason = certificate.revocation_reason
        return cls(
            name=child.name,
            status=child.status,
            subject_dn=certificate.subject_dn,
            certificate_id=certificate.id,
            serial_hex=certificate.serial_hex,
            sha256_fingerprint=certificate.sha256_fingerprint,
            not_before=certificate.not_before,
            not_after=certificate.not_after,
            path_length=child.path_length,
            public_base_url=child.public_base_url,
            revoked_at=certificate.revoked_at,
            revocation_reason=CaRevocationReason(reason.name) if reason is not None else None,
        )


class ChildRevoke(Schema):
    reason: CaRevocationReason
