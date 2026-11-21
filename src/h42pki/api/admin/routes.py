"""Admin API ``/api/v1`` (no authentication until the first release, ADR-0008)."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Response, status

from h42pki.api.admin.schemas import (
    CertificateCreate,
    CertificateOut,
    PrivateKeyCreate,
    PrivateKeyOut,
    certificate_pem,
)
from h42pki.ca.pki import PkiCertificate, PkiPrivateKey
from h42pki.errors import Conflict

PEM_MEDIA_TYPE = "application/x-pem-file"
DER_CERT_MEDIA_TYPE = "application/pkix-cert"

router = APIRouter(prefix="/api/v1", tags=["admin"])


def current_actor() -> str:
    """Identity recorded in the audit log; replaced by real authentication before release."""
    return "anonymous"


Actor = Annotated[str, Depends(current_actor)]


# --- private keys ---------------------------------------------------------------------------


@router.post("/private-keys", status_code=status.HTTP_201_CREATED)
async def create_private_key(body: PrivateKeyCreate, actor: Actor) -> PrivateKeyOut:
    key = await PkiPrivateKey.generate(body.algorithm, actor=actor)
    return PrivateKeyOut.from_model(key)


@router.get("/private-keys/{private_key_id}")
async def get_private_key(private_key_id: UUID) -> PrivateKeyOut:
    return PrivateKeyOut.from_model(await PkiPrivateKey.get_key(private_key_id))


@router.delete("/private-keys/{private_key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_private_key(private_key_id: UUID, actor: Actor) -> Response:
    await PkiPrivateKey.delete_key(private_key_id, actor=actor)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- certificates ---------------------------------------------------------------------------


@router.post("/certificates", status_code=status.HTTP_201_CREATED)
async def create_certificate(body: CertificateCreate, actor: Actor) -> CertificateOut:
    cert = await PkiCertificate.generate(
        private_key_id=body.private_key_id,
        subject=body.subject,
        extensions=body.extensions,
        actor=actor,
    )
    return CertificateOut.from_model(cert)


@router.post("/certificates/{certificate_id}/self-sign")
async def self_sign_certificate(certificate_id: UUID, actor: Actor) -> CertificateOut:
    cert = await PkiCertificate.self_sign(certificate_id, actor=actor)
    return CertificateOut.from_model(cert)


async def _signed_der(certificate_id: UUID) -> bytes:
    cert = await PkiCertificate.get_certificate(certificate_id)
    if cert.der is None:
        raise Conflict("the certificate is not signed yet")
    return cert.der


# The download routes are declared before /certificates/{certificate_id}.


@router.get(
    "/certificates/{certificate_id}.pem",
    response_class=Response,
    responses={200: {"content": {PEM_MEDIA_TYPE: {}}}},
)
async def download_certificate_pem(certificate_id: UUID) -> Response:
    der = await _signed_der(certificate_id)
    return Response(content=certificate_pem(der), media_type=PEM_MEDIA_TYPE)


@router.get(
    "/certificates/{certificate_id}.crt",
    response_class=Response,
    responses={200: {"content": {DER_CERT_MEDIA_TYPE: {}}}},
)
async def download_certificate_der(certificate_id: UUID) -> Response:
    der = await _signed_der(certificate_id)
    return Response(content=der, media_type=DER_CERT_MEDIA_TYPE)


@router.get("/certificates/{certificate_id}")
async def get_certificate(certificate_id: UUID) -> CertificateOut:
    return CertificateOut.from_model(await PkiCertificate.get_certificate(certificate_id))
