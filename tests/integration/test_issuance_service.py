"""IssuanceService: submit, auto-approval, approve / reject, failures."""

from collections.abc import Callable
from datetime import timedelta

import pytest
from cryptography import x509
from httpx import AsyncClient

from h42pki.core.errors import InvalidSan, InvalidValidity
from h42pki.core.keys import KeyAlgorithm, SupportedPrivateKey
from h42pki.errors import Conflict, NoActiveAuthority, Unprocessable
from h42pki.keystore import KeyStore
from h42pki.models import (
    AuditLog,
    Authority,
    AuthorityStatus,
    Certificate,
    CertificateRequest,
    Channel,
    RequestStatus,
)
from h42pki.services import IssuanceService
from tests.conftest import RootFactory
from tests.x509_helpers import csr_pem, make_csr, name

KeyFor = Callable[[KeyAlgorithm], SupportedPrivateKey]


@pytest.fixture
def issuance(keystore: KeyStore) -> IssuanceService:
    return IssuanceService(keystore)


def _server_csr(key_for: KeyFor, host: str = "www.example.test", **kwargs: object) -> str:
    return csr_pem(
        make_csr(key_for(KeyAlgorithm.EC_P256), name(CN=host), sans=[f"dns:{host}"], **kwargs)  # type: ignore[arg-type]
    )


async def _certificate(request: CertificateRequest) -> x509.Certificate:
    assert request.certificate_id is not None
    record = await Certificate.get(id=request.certificate_id)
    assert record.der is not None
    return x509.load_der_x509_certificate(record.der)


async def _root_certificate(authority: Authority) -> x509.Certificate:
    record = await Certificate.get(authority=authority)
    assert record.der is not None
    return x509.load_der_x509_certificate(record.der)


async def test_auto_approved_tls_server(
    make_root: RootFactory, issuance: IssuanceService, key_for: KeyFor
) -> None:
    root = await make_root()

    request = await issuance.submit(
        csr=_server_csr(
            key_for, extensions=[(x509.BasicConstraints(ca=True, path_length=None), True)]
        ),
        profile_name="tls_server",
        validity_days=None,
        actor="anonymous",
    )

    assert request.status is RequestStatus.ISSUED
    assert request.decided_by == "auto-approve"
    assert request.metadata["ignored_extensions"] == ["BasicConstraints (2.5.29.19)"]
    assert request.metadata["validity_truncated"] is False
    cert = await _certificate(request)
    cert.verify_directly_issued_by(await _root_certificate(root))
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=90)
    record = await Certificate.get(id=request.certificate_id).prefetch_related("profile", "issuer")
    assert record.profile is not None and record.profile.name == "tls_server"
    assert record.issuer is not None and record.issuer.id == root.id
    assert record.channel is Channel.API

    entry = await AuditLog.get(action="certificate.issue")
    assert entry.actor == "anonymous"
    assert entry.details["decided_by"] == "auto-approve"


async def test_validity_up_to_the_profile_maximum(
    make_root: RootFactory, issuance: IssuanceService, key_for: KeyFor
) -> None:
    await make_root()

    request = await issuance.submit(
        csr=_server_csr(key_for), profile_name="tls_server", validity_days=200, actor="anonymous"
    )

    cert = await _certificate(request)
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(days=200)
    with pytest.raises(InvalidValidity):
        await issuance.submit(
            csr=_server_csr(key_for), profile_name="tls_server", validity_days=201, actor="x"
        )
    assert await CertificateRequest.all().count() == 1  # the refused request is not stored


async def test_validity_truncated_to_the_root(
    make_root: RootFactory, issuance: IssuanceService, key_for: KeyFor
) -> None:
    root = await make_root(validity_days=30)

    request = await issuance.submit(
        csr=_server_csr(key_for), profile_name="tls_server", validity_days=None, actor="x"
    )

    assert request.metadata["validity_truncated"] is True
    root_cert = await _root_certificate(root)
    assert (await _certificate(request)).not_valid_after_utc == root_cert.not_valid_after_utc


async def test_profile_violation_is_refused_at_submission(
    make_root: RootFactory, issuance: IssuanceService, key_for: KeyFor
) -> None:
    await make_root()
    csr = csr_pem(make_csr(key_for(KeyAlgorithm.EC_P256), name(CN="no-san.example.test")))

    with pytest.raises(InvalidSan):
        await issuance.submit(csr=csr, profile_name="tls_server", validity_days=None, actor="x")
    assert not await CertificateRequest.exists()


async def test_manual_approval(
    make_root: RootFactory, issuance: IssuanceService, key_for: KeyFor
) -> None:
    root = await make_root()
    csr = csr_pem(make_csr(key_for(KeyAlgorithm.EC_P384), name(CN="Issuing CA", O="Home42")))

    request = await issuance.submit(csr=csr, profile_name="sub_ca", validity_days=None, actor="x")
    assert request.status is RequestStatus.PENDING
    assert request.certificate_id is None
    assert request.subject_dn == "CN=Issuing CA,O=Home42"

    approved = await issuance.approve(request.id, actor="admin")

    assert approved.status is RequestStatus.ISSUED and approved.decided_by == "admin"
    cert = await _certificate(approved)
    cert.verify_directly_issued_by(await _root_certificate(root))
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca and basic.path_length == 0
    with pytest.raises(Conflict, match="already been decided"):
        await issuance.approve(request.id, actor="admin")
    with pytest.raises(Conflict):
        await issuance.reject(request.id, reason="too late", actor="admin")


async def test_rejection(
    make_root: RootFactory, issuance: IssuanceService, key_for: KeyFor
) -> None:
    await make_root()
    csr = csr_pem(make_csr(key_for(KeyAlgorithm.EC_P384), name(CN="Issuing CA")))
    request = await issuance.submit(csr=csr, profile_name="sub_ca", validity_days=None, actor="x")

    rejected = await issuance.reject(request.id, reason="not planned", actor="admin")

    assert rejected.status is RequestStatus.REJECTED
    assert rejected.rejection_reason == "not planned"
    assert rejected.decided_by == "admin" and rejected.decided_at is not None
    with pytest.raises(Conflict):
        await issuance.approve(request.id, actor="admin")
    assert await Certificate.filter(profile_id__isnull=False).count() == 0  # only the root


async def test_failure_when_the_ca_disappears_before_approval(
    make_root: RootFactory, issuance: IssuanceService, key_for: KeyFor
) -> None:
    root = await make_root()
    csr = csr_pem(make_csr(key_for(KeyAlgorithm.EC_P384), name(CN="Issuing CA")))
    request = await issuance.submit(csr=csr, profile_name="sub_ca", validity_days=None, actor="x")
    await Authority.filter(id=root.id).update(status=AuthorityStatus.RETIRED)

    with pytest.raises(NoActiveAuthority):
        await issuance.approve(request.id, actor="admin")

    failed = await issuance.get(request.id)
    assert failed.status is RequestStatus.FAILED
    assert "no active certificate authority" in failed.metadata["failure"]


async def test_submit_without_authority(
    client: AsyncClient, issuance: IssuanceService, key_for: KeyFor
) -> None:
    with pytest.raises(NoActiveAuthority):
        await issuance.submit(
            csr=_server_csr(key_for), profile_name="tls_server", validity_days=None, actor="x"
        )


async def test_unknown_profile(
    make_root: RootFactory, issuance: IssuanceService, key_for: KeyFor
) -> None:
    await make_root()

    with pytest.raises(Unprocessable, match="unknown profile 'code_signing'"):
        await issuance.submit(
            csr=_server_csr(key_for), profile_name="code_signing", validity_days=None, actor="x"
        )


async def test_list_by_status(
    make_root: RootFactory, issuance: IssuanceService, key_for: KeyFor
) -> None:
    await make_root()
    await issuance.submit(
        csr=_server_csr(key_for), profile_name="tls_server", validity_days=None, actor="x"
    )
    sub_ca = csr_pem(make_csr(key_for(KeyAlgorithm.EC_P384), name(CN="Issuing CA")))
    await issuance.submit(csr=sub_ca, profile_name="sub_ca", validity_days=None, actor="x")

    assert len(await issuance.list()) == 2
    pending = await issuance.list(RequestStatus.PENDING)
    assert [request.profile.name for request in pending] == ["sub_ca"]
