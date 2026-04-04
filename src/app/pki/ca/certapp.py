from typing import Annotated
from fastapi import APIRouter
from .certdb import certdb


router = APIRouter()

cdb = certdb()





@router.post("/api/pki/ca/request")
async def certificat_request(model: str = "Server"):
    



    return {"ok": true}
