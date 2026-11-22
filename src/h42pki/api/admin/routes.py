"""Admin API ``/api/v1`` (no authentication until the first release, ADR-0008)."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query, Response, status

from h42pki.api.admin.deps import (
    Actor,
    AuthorityServiceDep,
    CertificateServiceDep,
    IssuanceServiceDep,
    KeyServiceDep,
    ProfileServiceDep,
)
from h42pki.api.admin.schemas import (
    AuthorityOut,
    CertificateList,
    CertificateOut,
    PrivateKeyCreate,
    PrivateKeyOut,
    ProfileOut,
    RequestCreate,
    RequestOut,
    RequestReject,
    certificate_pem,
)
from h42pki.api.problems import PROBLEM_RESPONSES
from h42pki.errors import NotFound
from h42pki.models import CertificateStatus, Channel, RequestStatus
from h42pki.services.certificates import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE

PEM_MEDIA_TYPE = "application/x-pem-file"
DER_CERT_MEDIA_TYPE = "application/pkix-cert"

router = APIRouter(prefix="/api/v1", tags=["admin"], responses=PROBLEM_RESPONSES)


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


@router.get("/certificates")
async def list_certificates(
    certificates: CertificateServiceDep,
    status: Annotated[CertificateStatus | None, Query()] = None,
    profile: Annotated[str | None, Query(max_length=64)] = None,
    channel: Annotated[Channel | None, Query()] = None,
    q: Annotated[
        str | None, Query(max_length=256, description="Substring of the subject DN, any case.")
    ] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> CertificateList:
    """Certificates, newest first."""
    now = datetime.now(UTC)
    page = await certificates.search(
        status=status, profile=profile, channel=channel, q=q, limit=limit, offset=offset, now=now
    )
    return CertificateList(
        items=[CertificateOut.from_model(cert, now=now) for cert in page.items],
        total=page.total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/certificates/{certificate_id}/chain.pem",
    response_class=Response,
    responses={200: {"content": {PEM_MEDIA_TYPE: {}}}},
)
async def download_certificate_chain(
    certificate_id: UUID, certificates: CertificateServiceDep
) -> Response:
    """The certificate followed by its issuers up to the root, ready to deploy on a server."""
    chain = await certificates.chain(await certificates.get(certificate_id))
    body = b"".join(certificate_pem(cert.der) for cert in chain)
    return Response(content=body, media_type=PEM_MEDIA_TYPE)


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


# --- authority ------------------------------------------------------------------------------


@router.get("/authority")
async def get_authority(authorities: AuthorityServiceDep) -> AuthorityOut:
    """The local CA, created by `h42pki authority init`."""
    authority = await authorities.find_local()
    if authority is None:
        raise NotFound("no local certificate authority: run `h42pki authority init` first")
    return AuthorityOut.from_model(authority, await authorities.certificate_of(authority))


# --- profiles (read-only, ADR-0009) ---------------------------------------------------------


@router.get("/profiles")
async def list_profiles(profiles: ProfileServiceDep) -> list[ProfileOut]:
    return [ProfileOut.from_model(profile) for profile in await profiles.list()]


@router.get("/profiles/{name}")
async def get_profile(name: str, profiles: ProfileServiceDep) -> ProfileOut:
    return ProfileOut.from_model(await profiles.get(name))


# --- certificate requests -------------------------------------------------------------------


@router.post("/requests", status_code=status.HTTP_201_CREATED)
async def submit_request(
    body: RequestCreate, actor: Actor, issuance: IssuanceServiceDep
) -> RequestOut:
    """Submit a CSR. Issued at once if the profile auto-approves, otherwise left pending."""
    request = await issuance.submit(
        csr=body.csr_pem, profile_name=body.profile, validity_days=body.validity_days, actor=actor
    )
    return RequestOut.from_model(request)


@router.get("/requests")
async def list_requests(
    issuance: IssuanceServiceDep, status: RequestStatus | None = None
) -> list[RequestOut]:
    return [RequestOut.from_model(request) for request in await issuance.list(status)]


@router.get("/requests/{request_id}")
async def get_request(request_id: UUID, issuance: IssuanceServiceDep) -> RequestOut:
    return RequestOut.from_model(await issuance.get(request_id))


@router.post("/requests/{request_id}/approve")
async def approve_request(
    request_id: UUID, actor: Actor, issuance: IssuanceServiceDep
) -> RequestOut:
    return RequestOut.from_model(await issuance.approve(request_id, actor=actor))


@router.post("/requests/{request_id}/reject")
async def reject_request(
    request_id: UUID, body: RequestReject, actor: Actor, issuance: IssuanceServiceDep
) -> RequestOut:
    return RequestOut.from_model(await issuance.reject(request_id, reason=body.reason, actor=actor))
