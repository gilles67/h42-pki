from typing import Annotated
from fastapi import APIRouter, Response
from .certdb import CertDatabase, Request



router = APIRouter()


@router.post("/api/pki/ca/request")
async def certificat_request(csr: Request):
    cdb = CertDatabase()
    rcsr = cdb.ReceiveRequest(csr)
    return {"sn": rcsr.sn}


@router.get("/api/pki/ca/sign")
async def certificat_sign(sn: int):
    cdb = CertDatabase()
    cert = cdb.SignRequest(sn)
    return Response(content=cert.crt_data, media_type="application/x-pem-file")
