"""FastAPI dependencies of the admin API."""

from typing import Annotated

from fastapi import Depends, Request

from h42pki.config import Settings
from h42pki.keystore import KeyStore, get_keystore
from h42pki.services import (
    AuthorityService,
    CertificateService,
    IssuanceService,
    KeyService,
    ProfileService,
    SettingsService,
)


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


def certificate_service() -> CertificateService:
    return CertificateService()


def authority_service(store: Annotated[KeyStore, Depends(keystore)]) -> AuthorityService:
    return AuthorityService(store)


def issuance_service(store: Annotated[KeyStore, Depends(keystore)]) -> IssuanceService:
    return IssuanceService(store)


def profile_service() -> ProfileService:
    return ProfileService()


def settings_service() -> SettingsService:
    return SettingsService()


Actor = Annotated[str, Depends(current_actor)]
AuthorityServiceDep = Annotated[AuthorityService, Depends(authority_service)]
IssuanceServiceDep = Annotated[IssuanceService, Depends(issuance_service)]
ProfileServiceDep = Annotated[ProfileService, Depends(profile_service)]
KeyServiceDep = Annotated[KeyService, Depends(key_service)]
CertificateServiceDep = Annotated[CertificateService, Depends(certificate_service)]
SettingsServiceDep = Annotated[SettingsService, Depends(settings_service)]
