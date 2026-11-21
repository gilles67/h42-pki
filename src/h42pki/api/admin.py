# Legacy admin routes moved verbatim from src/api.py; rewritten in lot 4.
from uuid import UUID

from fastapi import APIRouter, Response

from h42pki.ca import models, pki

router = APIRouter()


@router.get("/")
async def index():
    return {"Do something!"}


@router.post("/private_key/generate")
async def private_key_generate(settings: models.PrivateKeyCreateMixin):
    key = await pki.PkiPrivateKey.generate(settings)
    return models.PrivateKeyOutput.model_validate(key)


@router.get("/private_key/{key_id}")
async def get_private_key(key_id: UUID):
    (key, pvkey) = await pki.PkiPrivateKey.load_key(key_id)
    return models.PrivateKeyOutput.model_validate(key)


@router.delete("/private_key/{key_id}")
async def delete_private_key(key_id: UUID):
    await pki.PkiPrivateKey.delete_key(key_id)
    return {"Done"}


@router.post("/certificate/generate")
async def certificate_generate(settings: models.CertificateCreateMixin):
    cert = await pki.PkiCertificate.generate(settings)
    return cert


@router.post("/certificate/{cert_id}/self_sign")
async def certificate_self_sign(cert_id: UUID):
    cert = await pki.PkiCertificate.self_sign(cert_id)
    return cert


@router.get("/certificate/{cert_id}")
async def certificate_get(cert_id: UUID):
    cert = await pki.PkiCertificate.get_certificate(cert_id)
    return Response(content=cert.crt, media_type="application/pkix-cert")
