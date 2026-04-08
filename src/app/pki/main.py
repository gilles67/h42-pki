from fastapi import Depends, FastAPI
from .ca import certapp

app = FastAPI()
app.include_router(certapp.router)
