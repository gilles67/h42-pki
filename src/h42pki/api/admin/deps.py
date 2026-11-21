"""FastAPI dependencies of the admin API."""

from typing import Annotated

from fastapi import Depends, Request

from h42pki.config import Settings
from h42pki.keystore import KeyStore, get_keystore
from h42pki.services import CertificateService, KeyService


def current_actor() -> str:
    """Identity recorded in the audit log; replaced by real authentication before release."""
    return "anonymous"


def app_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def keystore(settings: Annotated[Settings, Depends(app_settings)]) -> KeyStore:
    return get_keystore(settings)


def key_service(store: Annotated[KeyStore, Depends(keystore)]) -> KeyService:
    return KeyService(store)


def certificate_service(store: Annotated[KeyStore, Depends(keystore)]) -> CertificateService:
    return CertificateService(store)


Actor = Annotated[str, Depends(current_actor)]
KeyServiceDep = Annotated[KeyService, Depends(key_service)]
CertificateServiceDep = Annotated[CertificateService, Depends(certificate_service)]
