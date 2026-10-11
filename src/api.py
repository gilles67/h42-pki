from fastapi import FastAPI, Response 
import uvicorn
from tortoise.contrib.fastapi import register_tortoise
from ca import models
from ca import pki
from uuid import UUID


app = FastAPI()


register_tortoise(
    app,
    db_url="sqlite://db.sqlite3",
    modules={"models": ["ca.models"]},
    generate_schemas=True,
    add_exception_handlers=True,
)

@app.get("/")
async def index():
    return {"Do something!"}


@app.post("/private_key/generate")
async def private_key_generate(settings:models.PrivateKeyCreateMixin):
    key = await pki.PkiPrivateKey.generate(settings)
    return models.PrivateKeyOutput.model_validate(key)

@app.get("/private_key/{key_id}")
async def get_private_key(key_id:UUID):
    (key, pvkey) = await pki.PkiPrivateKey.load_key(key_id)
    return models.PrivateKeyOutput.model_validate(key)

@app.delete("/private_key/{key_id}")
async def delete_private_key(key_id:UUID):
    await pki.PkiPrivateKey.delete(key_id)
    return {"Done"}

@app.post("/certificate/generate")
async def certificate_generate(settings:models.CertificateCreateMixin):
    cert = await pki.PkiCertificate.generate(settings)
    return cert

@app.post("/certificate/{cert_id}/self_sign")
async def certificate_self_sign(cert_id:UUID):
    cert = await pki.PkiCertificate.self_sign(cert_id)
    return cert

@app.get("/certificate/{cert_id}")
async def certificate_get(cert_id:UUID):
    cert = await pki.PkiCertificate.get_certificate(cert_id)
    return Response(content=cert.crt, media_type="application/pkix-cert")


if __name__ == "__main__":
    uvicorn.run("api:app", host="127.0.0.1",port= 8080, reload=True)