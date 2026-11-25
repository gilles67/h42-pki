"""Child side of the federation with a simulated parent: lost answers, bad certificates, polling."""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import AsyncClient
from typer.testing import CliRunner

from h42pki.cli import app
from h42pki.config import ENV_PREFIX, get_settings
from h42pki.core.csr import build_ca_csr, parse_csr
from h42pki.core.errors import InvalidChain, InvalidIssuedCertificate
from h42pki.core.extensions import BasicConstraints, Extensions, KeyUsage
from h42pki.core.federation import SubCaConstraints, constrain_sub_ca, new_token
from h42pki.core.issuance import build_issued, build_self_signed
from h42pki.core.keys import KeyAlgorithm
from h42pki.core.names import Subject
from h42pki.core.profiles import BUILTIN_PROFILES
from h42pki.errors import Conflict, H42Error, NotFound
from h42pki.keystore import KeyStore
from h42pki.models import (
    AuditLog,
    Authority,
    AuthorityKind,
    AuthorityStatus,
    Certificate,
    PrivateKey,
)
from h42pki.services import federation_client, subordinate
from h42pki.services.authority import AuthorityService
from h42pki.services.federation_client import (
    EnrollAnswer,
    FederationClient,
    InvalidParentUrl,
    ParentRefused,
    ParentUnreachable,
    fetch_chain,
    normalize_parent_url,
)
from h42pki.services.subordinate import EnrolmentRejected, SubordinateService
from tests.cli_helpers import plain

TOKEN = new_token(uuid4()).reveal()
URL = "https://parent.test"


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@dataclass
class FakeParent:
    """Answers scripted one by one; signs for real."""

    script: list[Any] = field(default_factory=list)
    calls: list[tuple[Any, ...]] = field(default_factory=list)
    enrolment: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cert = build_self_signed(
            Subject(common_name="Parent CA"),
            Extensions(
                basic_constraints=BasicConstraints(ca=True, path_length=2),
                key_usage=KeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=True),
            ),
            self.key,
            serial_hex="01",
            validity_days=4000,
            now=datetime.now(UTC),
        )
        self.fingerprint = self.cert.fingerprint(hashes.SHA256()).hex()

    def sign(self, csr_pem: str | bytes) -> x509.Certificate:
        spec = constrain_sub_ca(BUILTIN_PROFILES["sub_ca"], SubCaConstraints(None, None, True))
        return build_issued(
            parse_csr(csr_pem), spec, self.cert, self.key, validity_days=None, now=datetime.now(UTC)
        ).certificate

    def issued(self, cert: x509.Certificate, chain: str | None = None) -> EnrollAnswer:
        return EnrollAnswer(
            status="issued",
            enrollment_id=self.enrolment,
            certificate_pem=pem(cert),
            chain_pem=pem(self.cert) if chain is None else chain,
        )

    def pending(self, retry_after: int | None = None) -> EnrollAnswer:
        return EnrollAnswer(status="pending", enrollment_id=self.enrolment, retry_after=retry_after)

    def _next(self) -> EnrollAnswer:
        step = self.script.pop(0) if self.script else "sign"
        if isinstance(step, Exception):
            raise step
        if step == "sign":
            return self.issued(self.sign(self.csr))
        assert isinstance(step, EnrollAnswer)
        return step

    async def enroll(
        self, token: str, *, csr_pem: str, name: str, public_base_url: str | None
    ) -> EnrollAnswer:
        self.calls.append(("enroll", csr_pem, name, public_base_url))
        self.csr = csr_pem
        return self._next()

    async def status(self, token: str, enrollment_id: UUID) -> EnrollAnswer:
        self.calls.append(("status", enrollment_id))
        return self._next()


@pytest.fixture
def parent(client: AsyncClient, monkeypatch: pytest.MonkeyPatch) -> FakeParent:
    fake = FakeParent()

    async def chain(url: str) -> bytes:
        assert url == URL
        return pem(fake.cert).encode()

    monkeypatch.setattr(federation_client, "fetch_chain", chain)
    monkeypatch.setattr(subordinate, "FederationClient", lambda url, anchor: fake)
    return fake


@pytest.fixture
def service(parent: FakeParent, keystore: KeyStore) -> SubordinateService:
    return SubordinateService(keystore)


async def start(service: SubordinateService, parent: FakeParent, **changes: Any) -> Authority:
    values: dict[str, Any] = {
        "parent_url": URL,
        "parent_fingerprint": parent.fingerprint,
        "token": TOKEN,
        "name": "child",
        "subject": Subject(common_name="Child CA"),
        "key_algorithm": KeyAlgorithm.EC_P256,
        "public_base_url": None,
        "actor": "test",
        **changes,
    }
    return await service.start(**values)


async def assert_nothing_left() -> None:
    assert await Authority.all().count() == 0
    assert await PrivateKey.all().count() == 0
    assert await Certificate.all().count() == 0


# --- lost answers ---------------------------------------------------------------------------


async def test_lost_answer_is_asked_again_with_the_same_request(
    service: SubordinateService, parent: FakeParent
) -> None:
    parent.script = [ParentUnreachable("no answer")]
    with pytest.raises(ParentUnreachable):
        await start(service, parent, public_base_url="http://child.test/")
    pending = await service.pending()
    assert pending.pending_enrollment_id is None

    authority = await SubordinateService().resume(TOKEN, actor="test")  # no keystore needed

    assert authority.status is AuthorityStatus.ACTIVE
    assert parent.calls[0] == parent.calls[1]  # byte for byte, CSR included
    assert parent.calls[0][3] == "http://child.test"


async def test_refused_resume_keeps_the_pending_ca(
    service: SubordinateService, parent: FakeParent
) -> None:
    parent.script = [parent.pending(), ParentRefused("401", code=401)]
    await start(service, parent)

    with pytest.raises(ParentRefused):
        await service.resume(TOKEN, actor="test")

    assert (await service.pending()).pending_enrollment_id == parent.enrolment
    with pytest.raises(Conflict, match="--resume"):
        await start(service, parent, name="another")
    assert await service.abandon(actor="test") == "child"
    await assert_nothing_left()
    with pytest.raises(NotFound):
        await service.abandon(actor="test")


async def test_definitive_refusal_leaves_nothing(
    service: SubordinateService, parent: FakeParent
) -> None:
    parent.script = [ParentRefused("the parent refuses (409)", code=409)]
    with pytest.raises(ParentRefused):
        await start(service, parent)
    await assert_nothing_left()


@pytest.mark.parametrize("status", ["rejected", "failed"])
async def test_negative_decision(
    service: SubordinateService, parent: FakeParent, status: Any
) -> None:
    parent.script = [EnrollAnswer(status=status, enrollment_id=parent.enrolment, reason="because")]
    with pytest.raises(EnrolmentRejected, match=f"{status} the enrolment: because"):
        await start(service, parent)
    await assert_nothing_left()
    entry = await AuditLog.get(action="authority.abandon")
    assert entry.details["reason"] == "because"


# --- received certificate -------------------------------------------------------------------


async def test_inconsistent_answers_are_refused(
    service: SubordinateService, parent: FakeParent
) -> None:
    other_key = ec.generate_private_key(ec.SECP256R1())
    other_parent = FakeParent()
    for_other_key = parent.sign(build_ca_csr(other_key, Subject(common_name="Child CA")))
    parent.script = [parent.pending()]
    await start(service, parent)
    mine = parent.sign(parent.csr)
    parent.script = [
        parent.issued(for_other_key),
        parent.issued(other_parent.sign(parent.csr)),
        parent.issued(mine, chain=pem(other_parent.cert)),
        parent.issued(mine, chain=""),
        EnrollAnswer(status="issued", enrollment_id=parent.enrolment),
    ]

    while parent.script:
        with pytest.raises((InvalidIssuedCertificate, InvalidChain)):
            await service.resume(TOKEN, actor="test")
        assert (await service.pending()).status is AuthorityStatus.PENDING_SIGNATURE
    assert await AuthorityService().find_local() is None

    assert (await service.resume(TOKEN, actor="test")).status is AuthorityStatus.ACTIVE


# --- waiting --------------------------------------------------------------------------------


async def test_polling_follows_retry_after(parent: FakeParent, keystore: KeyStore) -> None:
    waits: list[float] = []

    async def sleep(seconds: float) -> None:
        waits.append(seconds)

    service = SubordinateService(keystore, sleep=sleep)
    parent.script = [parent.pending()]
    await start(service, parent)
    parent.script = [
        parent.pending(5),
        ParentUnreachable("blip"),
        parent.pending(0),
        parent.pending(9999),
        "sign",
    ]

    authority = await service.wait(TOKEN, seconds=600, actor="test")

    assert authority.status is AuthorityStatus.ACTIVE
    assert waits == [10, 5, 5, 10, 60]
    assert [call[0] for call in parent.calls] == ["enroll", *["status"] * 5]


async def test_waiting_ends(service: SubordinateService, parent: FakeParent) -> None:
    parent.script = [parent.pending()]
    await start(service, parent)

    authority = await service.wait(TOKEN, seconds=0, actor="test")

    assert authority.status is AuthorityStatus.PENDING_SIGNATURE
    assert len(parent.calls) == 1


# --- checks before anything is sent ---------------------------------------------------------


async def test_refused_before_anything_is_sent(
    service: SubordinateService, parent: FakeParent
) -> None:
    for changes in (
        {"token": "garbage"},
        {"parent_fingerprint": "abc"},
        {"parent_fingerprint": "0" * 64},
        {"name": "chain"},
        {"parent_url": "http://parent.test"},
        {"public_base_url": "ftp://x"},
    ):
        with pytest.raises(H42Error):
            await start(service, parent, **changes)
    assert parent.calls == []
    await assert_nothing_left()


async def test_one_local_ca_only(
    service: SubordinateService, parent: FakeParent, make_root: Callable[..., Any]
) -> None:
    await make_root()
    with pytest.raises(Conflict, match="already exists"):
        await start(service, parent)


async def test_root_cannot_be_created_while_an_enrolment_is_pending(
    service: SubordinateService, parent: FakeParent, make_root: Callable[..., Any]
) -> None:
    parent.script = [parent.pending()]
    await start(service, parent)
    with pytest.raises(Conflict):
        await make_root()


async def test_tampered_pin_is_detected(service: SubordinateService, parent: FakeParent) -> None:
    parent.script = [parent.pending()]
    await start(service, parent)
    await Authority.filter(kind=AuthorityKind.PARENT).update(pinned_fingerprint="0" * 64)

    with pytest.raises(InvalidChain, match="not the pinned one"):
        await service.resume(TOKEN, actor="test")


async def test_ancestors_shared_with_a_retired_ca_are_kept(
    service: SubordinateService, parent: FakeParent
) -> None:
    first = await start(service, parent)
    await Authority.filter(id=first.id).update(status=AuthorityStatus.RETIRED)
    parent.script = [parent.pending()]
    await start(service, parent, name="child-2")
    assert await Authority.filter(kind=AuthorityKind.PARENT).count() == 1

    await service.abandon(actor="test")

    assert await Authority.filter(kind=AuthorityKind.PARENT).count() == 1
    assert (await Authority.get(id=first.id)).status is AuthorityStatus.RETIRED


# --- HTTP client ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://Parent.test/", "https://parent.test"),
        (" https://parent.test:8443/pki/ ", "https://parent.test:8443/pki"),
    ],
)
def test_parent_url(url: str, expected: str) -> None:
    assert normalize_parent_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://parent.test",
        "https://",
        "https://u:p@parent.test",
        "https://parent.test?x",
        "https://parent.test#x",
        "https://parent.test:99999",
        "https://[",
    ],
)
def test_invalid_parent_url(url: str) -> None:
    with pytest.raises(InvalidParentUrl):
        normalize_parent_url(url)


async def call(handler: Callable[[httpx.Request], httpx.Response]) -> EnrollAnswer:
    client = FederationClient(URL, FakeParent().cert, transport=httpx.MockTransport(handler))
    return await client.enroll(TOKEN, csr_pem="csr", name="child", public_base_url=None)


async def test_client_request_and_answer() -> None:
    seen: list[httpx.Request] = []
    enrolment = uuid4()

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = {"status": "pending", "enrollment_id": str(enrolment), "new_field": 1}
        return httpx.Response(202, json=body, headers={"Retry-After": "7"})

    answer = await call(handler)

    assert (answer.status, answer.enrollment_id, answer.retry_after) == ("pending", enrolment, 7)
    [request] = seen
    assert str(request.url) == f"{URL}/api/v1/federation/enroll"
    assert request.headers["authorization"] == f"Bearer {TOKEN}"


@pytest.mark.parametrize(
    ("response", "error", "message"),
    [
        (httpx.Response(401, json={"detail": "nope"}), ParentRefused, "401.*nope"),
        (httpx.Response(409, text="<html>"), ParentRefused, "no detail"),
        (httpx.Response(302, headers={"location": "https://evil.test"}), ParentRefused, "302"),
        (httpx.Response(422, json={"detail": "a\x1b[31mb\n"}), ParentRefused, r"a \[31mb $"),
        (httpx.Response(503, json={"detail": "no CA"}), ParentUnreachable, "503.*no CA"),
        (httpx.Response(429), ParentUnreachable, "429"),
        (httpx.Response(201, text="garbage"), ParentUnreachable, "unexpected answer"),
        (httpx.Response(201, content=b"x" * 300_000), ParentUnreachable, "too large"),
    ],
)
async def test_client_errors(response: httpx.Response, error: type[H42Error], message: str) -> None:
    with pytest.raises(error, match=message) as caught:
        await call(lambda request: response)
    assert TOKEN not in str(caught.value) and "evil" not in str(caught.value)


async def test_client_timeout() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(ParentUnreachable, match="does not answer in time") as caught:
        await call(handler)
    assert TOKEN not in str(caught.value)


async def test_chain_download_sends_nothing_and_is_bounded() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"x" * 70_000)

    with pytest.raises(ParentUnreachable, match="too large"):
        await fetch_chain(URL, transport=httpx.MockTransport(handler))
    [request] = seen
    assert (request.method, str(request.url)) == ("GET", f"{URL}/ca/chain.pem")
    assert "authorization" not in request.headers and request.content == b""

    missing = httpx.MockTransport(lambda request: httpx.Response(503))
    with pytest.raises(ParentUnreachable, match="503"):
        await fetch_chain(URL, transport=missing)


# --- command line ---------------------------------------------------------------------------

BASE = ["authority", "init", "--name", "child", "--common-name", "Child CA"]
PARENT = ["--parent-url", URL, "--parent-fingerprint", "0" * 64]


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["authority", "init"], "--name and --common-name are required"),
        ([*BASE, *PARENT], "--token is required"),
        ([*BASE, "--parent-url", URL, "--token", TOKEN], "--parent-fingerprint is required"),
        ([*BASE, "--token", TOKEN], "go with --parent-url"),
        ([*BASE, *PARENT, "--token", TOKEN, "--path-length", "1"], "decided by the parent"),
        ([*BASE, *PARENT, "--token", TOKEN, "--validity-days", "9"], "decided by the parent"),
        (["authority", "init", "--resume"], "--token is required"),
        ([*BASE, "--resume", "--token", TOKEN], "--resume only takes"),
    ],
)
def test_command_line_usage(
    args: list[str], message: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    database = tmp_path / "h42pki.sqlite3"
    monkeypatch.setenv(f"{ENV_PREFIX}DATABASE_URL", f"sqlite://{database.as_posix()}")
    get_settings.cache_clear()

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 2
    assert message in plain(result)
    assert TOKEN not in plain(result)
    assert not database.exists()


def test_malformed_token_is_not_repeated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    database = tmp_path / "h42pki.sqlite3"
    monkeypatch.setenv(f"{ENV_PREFIX}DATABASE_URL", f"sqlite://{database.as_posix()}")
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE", "x")
    get_settings.cache_clear()

    result = CliRunner().invoke(app, [*BASE, *PARENT, "--token", "-"], input="s3cret-typo\n")

    assert result.exit_code == 1
    assert "not an invitation token" in plain(result) and "s3cret" not in plain(result)
