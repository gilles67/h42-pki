"""Certificate of the built-in HTTPS server, issued by the local CA for itself (ADR-0013)."""

import ipaddress
from datetime import UTC, datetime, timedelta

import pytest
import time_machine
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from httpx import AsyncClient

from h42pki.errors import NoActiveAuthority
from h42pki.keystore import KeyStore
from h42pki.models import AuditLog, Certificate, CertificateRequest, Channel, KeyPurpose
from h42pki.services import SettingsService
from h42pki.services.issuance import IssuanceService
from h42pki.services.tls_service import TlsServiceManager
from tests.conftest import RootFactory
from tests.integration.test_requests_api import KeyFor, _server_csr, _submit

NAMES = ["pki.home42.test", "localhost", "127.0.0.1"]


def _x509(record: Certificate) -> x509.Certificate:
    return x509.load_der_x509_certificate(record.der)


async def test_no_certificate_without_an_active_ca(client: AsyncClient, keystore: KeyStore) -> None:
    manager = TlsServiceManager(keystore, NAMES)

    result = await manager.ensure()

    assert result.certificate is None and not result.issued
    assert await manager.current() is None


async def test_issued_once_the_ca_is_active(
    client: AsyncClient, make_root: RootFactory, keystore: KeyStore
) -> None:
    await make_root()
    manager = TlsServiceManager(keystore, NAMES)

    result = await manager.ensure()

    assert result.issued and result.reason == "no certificate yet"
    record = result.certificate
    assert record is not None
    cert = _x509(record)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "pki.home42.test"
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sans.get_values_for_type(x509.DNSName) == ["pki.home42.test", "localhost"]
    assert sans.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address("127.0.0.1")]
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=47)
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    # Same path as any other certificate: a request, the system channel, a TLS key.
    assert record.channel is Channel.SYSTEM
    await record.fetch_related("private_key", "profile")
    assert record.private_key is not None
    assert record.private_key.purpose is KeyPurpose.TLS
    assert record.profile is not None and record.profile.name == "service_tls"
    request = await CertificateRequest.get(certificate_id=record.id)
    assert (request.channel, request.requester, request.decided_by) == (
        Channel.SYSTEM,
        "system",
        "auto-approve",
    )
    issue = await AuditLog.get(action="certificate.issue")
    assert issue.actor == "system" and issue.details["channel"] == "system"
    key_entry = await AuditLog.filter(action="private_key.generate").order_by("-timestamp").first()
    assert key_entry is not None and key_entry.details["purpose"] == "tls"


async def test_the_ca_key_is_never_the_tls_key(
    client: AsyncClient, make_root: RootFactory, keystore: KeyStore
) -> None:
    authority = await make_root()
    record = (await TlsServiceManager(keystore, NAMES).ensure()).certificate
    assert record is not None

    await record.fetch_related("private_key")
    await authority.fetch_related("private_key")

    assert record.private_key is not None and authority.private_key is not None
    assert record.private_key.id != authority.private_key.id
    assert authority.private_key.purpose is KeyPurpose.CA


async def test_kept_while_valid(
    client: AsyncClient, make_root: RootFactory, keystore: KeyStore
) -> None:
    await make_root()
    manager = TlsServiceManager(keystore, NAMES)
    first = await manager.ensure()

    second = await manager.ensure()

    assert not second.issued
    assert second.certificate is not None and first.certificate is not None
    assert second.certificate.id == first.certificate.id


async def test_reissued_when_the_names_change(
    client: AsyncClient, make_root: RootFactory, keystore: KeyStore
) -> None:
    await make_root()
    first = await TlsServiceManager(keystore, NAMES).ensure()

    result = await TlsServiceManager(keystore, [*NAMES, "pki-int"]).ensure()

    assert result.issued and result.reason == "server names changed"
    assert result.certificate is not None and first.certificate is not None
    assert result.certificate.serial_hex != first.certificate.serial_hex
    assert "pki-int" in _x509(result.certificate).extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName)


async def test_reissued_when_the_hostname_changes(
    client: AsyncClient, make_root: RootFactory, keystore: KeyStore
) -> None:
    await make_root()
    await TlsServiceManager(keystore, NAMES).ensure()

    result = await TlsServiceManager(keystore, ["pki2.home42.test", *NAMES[1:]]).ensure()

    assert result.issued and result.reason == "server names changed"


async def test_renewed_15_days_before_expiry(
    client: AsyncClient, make_root: RootFactory, keystore: KeyStore
) -> None:
    await make_root()
    manager = TlsServiceManager(keystore, NAMES)
    first = (await manager.ensure()).certificate
    assert first is not None
    not_after = first.not_after

    with time_machine.travel(not_after - timedelta(days=15, seconds=1), tick=False):
        assert not (await manager.ensure()).issued  # 15 days and 1 second left
    with time_machine.travel(not_after - timedelta(days=15), tick=False):
        renewed = await manager.ensure()

    assert renewed.issued and renewed.reason is not None and "renewal due" in renewed.reason
    assert renewed.certificate is not None
    assert renewed.certificate.not_after > not_after
    current = await manager.current()
    assert current is not None and current.id == renewed.certificate.id


async def test_renewal_follows_the_hot_settings(
    client: AsyncClient, make_root: RootFactory, keystore: KeyStore
) -> None:
    await make_root()
    manager = TlsServiceManager(keystore, NAMES)
    await manager.ensure()
    settings = SettingsService()
    await settings.set("tls_service.validity_days", 90, actor="cli")
    await settings.set("tls_service.renew_before_days", 60, actor="cli")

    renewed = await manager.ensure()  # 47 days left <= 60: renewal due at once

    assert renewed.issued and renewed.certificate is not None
    cert = _x509(renewed.certificate)
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=90)


async def test_reissued_when_expired(
    client: AsyncClient, make_root: RootFactory, keystore: KeyStore
) -> None:
    await make_root()
    manager = TlsServiceManager(keystore, NAMES)
    first = (await manager.ensure()).certificate
    assert first is not None

    with time_machine.travel(first.not_after + timedelta(days=1), tick=False):
        result = await manager.ensure()

    assert result.issued and result.reason == "expired"


async def test_material_loads_into_an_ssl_context(
    client: AsyncClient, make_root: RootFactory, keystore: KeyStore
) -> None:
    await make_root()
    manager = TlsServiceManager(keystore, NAMES)
    record = (await manager.ensure()).certificate
    assert record is not None

    material = await manager.material(record)

    # Leaf first, then the CA chain; the key is encrypted PKCS#8 (CLAUDE.md section 6.2).
    chain = x509.load_pem_x509_certificates(material.chain_pem)
    assert [c.serial_number for c in chain][0] == int(record.serial_hex, 16)
    assert chain[1].subject == chain[0].issuer
    assert material.key_pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    with pytest.raises(TypeError):
        serialization.load_pem_private_key(material.key_pem, password=None)
    key = serialization.load_pem_private_key(material.key_pem, password=material.password)
    assert key.public_key() == chain[0].public_key()
    assert x509.load_pem_x509_certificates(material.anchors_pem.encode()) == chain[1:]
    assert material.password.decode() not in repr(material)


async def test_service_tls_cannot_be_requested(
    client: AsyncClient, make_root: RootFactory, key_for: KeyFor
) -> None:
    await make_root()

    response = await _submit(client, _server_csr(key_for), "service_tls")

    assert response.status_code == 422
    assert "internal" in response.json()["detail"]
    assert await AuditLog.filter(action="request.refuse").count() == 1


async def test_issue_service_certificate_needs_an_active_ca(
    client: AsyncClient, keystore: KeyStore
) -> None:
    with pytest.raises(NoActiveAuthority):
        await IssuanceService(keystore).issue_service_certificate(NAMES, validity_days=47)


def test_manager_needs_a_hostname(keystore: KeyStore) -> None:
    with pytest.raises(ValueError, match="H42_PKI_SERVER_HOSTNAME"):
        TlsServiceManager(keystore, [])


async def test_truncated_to_the_ca_validity(
    client: AsyncClient, make_root: RootFactory, keystore: KeyStore
) -> None:
    await make_root(validity_days=10)

    record = (await TlsServiceManager(keystore, NAMES).ensure()).certificate

    assert record is not None
    ca_not_after = datetime.now(UTC) + timedelta(days=10)
    assert record.not_after <= ca_not_after
