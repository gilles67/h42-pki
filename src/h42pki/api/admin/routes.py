"""Admin API ``/api/v1`` (no authentication until the first release, ADR-0008)."""

from uuid import UUID

from fastapi import APIRouter, Response, status

from h42pki.api.admin.deps import Actor, CertificateServiceDep, KeyServiceDep
from h42pki.api.admin.schemas import (
    CertificateOut,
    PrivateKeyCreate,
    PrivateKeyOut,
    certificate_pem,
)

PEM_MEDIA_TYPE = "application/x-pem-file"
DER_CERT_MEDIA_TYPE = "application/pkix-cert"

router = APIRouter(prefix="/api/v1", tags=["admin"])


# --- private keys ---------------------------------------------------------------------------


@router.post("/private-keys", status_code=status.HTTP_201_CREATED)
async def create_private_key(
    body: PrivateKeyCreate, actor: Actor, keys: KeyServiceDep
) -> PrivateKeyOut:
    return PrivateKeyOut.from_model(await keys.generate(body.algorithm, actor=actor))


@router.get("/private-keys/{private_key_id}")
async def get_private_key(private_key_id: UUID, keys: KeyServiceDep) -> PrivateKeyOut:
    return PrivateKeyOut.from_model(await keys.get(private_key_id))


@router.delete("/private-keys/{private_key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_private_key(private_key_id: UUID, actor: Actor, keys: KeyServiceDep) -> Response:
    await keys.delete(private_key_id, actor=actor)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- certificates ---------------------------------------------------------------------------


async def _der(certificates: CertificateServiceDep, certificate_id: UUID) -> bytes:
    return (await certificates.get(certificate_id)).der


# The download routes are declared before /certificates/{certificate_id}.


@router.get(
    "/certificates/{certificate_id}.pem",
    response_class=Response,
    responses={200: {"content": {PEM_MEDIA_TYPE: {}}}},
)
async def download_certificate_pem(
    certificate_id: UUID, certificates: CertificateServiceDep
) -> Response:
    der = await _der(certificates, certificate_id)
    return Response(content=certificate_pem(der), media_type=PEM_MEDIA_TYPE)


@router.get(
    "/certificates/{certificate_id}.crt",
    response_class=Response,
    responses={200: {"content": {DER_CERT_MEDIA_TYPE: {}}}},
)
async def download_certificate_der(
    certificate_id: UUID, certificates: CertificateServiceDep
) -> Response:
    der = await _der(certificates, certificate_id)
    return Response(content=der, media_type=DER_CERT_MEDIA_TYPE)


@router.get("/certificates/{certificate_id}")
async def get_certificate(
    certificate_id: UUID, certificates: CertificateServiceDep
) -> CertificateOut:
    return CertificateOut.from_model(await certificates.get(certificate_id))
