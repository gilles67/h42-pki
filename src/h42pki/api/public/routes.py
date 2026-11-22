"""Public HTTP endpoints (no authentication, served over plain HTTP: RFC 5280 4.2.2.1).

They only read published certificates: no request here ever triggers an operation on a key.
"""

import hashlib

from fastapi import APIRouter, Request, Response

from h42pki.api.admin.schemas import certificate_pem
from h42pki.api.problems import PROBLEM_RESPONSES
from h42pki.api.public.cache import cacheable
from h42pki.services.publication import PublicationService

PEM_MEDIA_TYPE = "application/x-pem-file"
DER_CERT_MEDIA_TYPE = "application/pkix-cert"

router = APIRouter(prefix="/ca", tags=["public"], responses=PROBLEM_RESPONSES)


# Declared before /ca/{name}.pem, which would otherwise match "chain" ("chain" is a reserved name).
@router.get(
    "/chain.pem",
    response_class=Response,
    responses={200: {"content": {PEM_MEDIA_TYPE: {}}}},
    summary="Certificate chain of the active local CA, root included",
)
async def chain_pem(request: Request) -> Response:
    certificates = await PublicationService().chain()
    body = b"".join(certificate_pem(certificate.der) for certificate in certificates)
    return cacheable(
        request,
        body=body,
        media_type=PEM_MEDIA_TYPE,
        etag=f'"{hashlib.sha256(body).hexdigest()}"',
        last_modified=max(certificate.not_before for certificate in certificates),
    )


@router.get(
    "/{name}.crt",
    response_class=Response,
    responses={200: {"content": {DER_CERT_MEDIA_TYPE: {}}}},
    summary="CA certificate in DER (target of the AIA caIssuers of issued certificates)",
)
async def ca_certificate_der(name: str, request: Request) -> Response:
    certificate = await PublicationService().ca_certificate(name)
    return cacheable(
        request,
        body=certificate.der,
        media_type=DER_CERT_MEDIA_TYPE,
        etag=f'"{certificate.sha256_fingerprint}"',
        last_modified=certificate.not_before,
    )


@router.get(
    "/{name}.pem",
    response_class=Response,
    responses={200: {"content": {PEM_MEDIA_TYPE: {}}}},
    summary="CA certificate in PEM",
)
async def ca_certificate_pem(name: str, request: Request) -> Response:
    certificate = await PublicationService().ca_certificate(name)
    return cacheable(
        request,
        body=certificate_pem(certificate.der),
        media_type=PEM_MEDIA_TYPE,
        etag=f'"{certificate.sha256_fingerprint}"',
        last_modified=certificate.not_before,
    )
