"""Enrolment of a child CA with a real parent: `h42pki serve` in another process, over HTTPS.

Tortoise is global to a process: the parent has its own process and database. It is driven by its
API (never by its CLI while it runs), so that these tests also work on WSL1 (B42). The child is
the CLI in this process, or a launcher in this event loop.
"""

import shutil
import ssl
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from click.testing import Result
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import verification
from typer.testing import CliRunner

from h42pki.cli import app
from h42pki.cli._runtime import run
from h42pki.config import ENV_PREFIX, Settings, get_settings
from h42pki.core.chain import fingerprint_of
from h42pki.core.keys import KeyAlgorithm
from h42pki.core.names import Subject
from h42pki.keystore import KeyStore, get_keystore
from h42pki.models import (
    AuditLog,
    Authority,
    AuthorityKind,
    AuthorityStatus,
    Certificate,
    PrivateKey,
)
from h42pki.services import CertificateService, IssuanceService, PublicationService
from h42pki.services.federation_client import pinned_context
from h42pki.services.subordinate import SubordinateService
from tests.cli_helpers import plain
from tests.conftest import TEST_PASSPHRASE
from tests.integration.server.conftest import Running, free_port, wait_for
from tests.integration.server.instance import Instance, listening
from tests.x509_helpers import csr_pem, make_csr, name

runner = CliRunner()


@dataclass
class Parent:
    """A running CA and an HTTPS client that trusts its root."""

    instance: Instance
    root_pem: str
    certificate: x509.Certificate
    http: httpx.Client

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.instance.https_port}"

    @property
    def fingerprint(self) -> str:
        return fingerprint_of(self.certificate)

    def post(self, path: str, **body: Any) -> Any:
        response = self.http.post(f"/api/v1/{path}", json=body)
        assert response.status_code < 300, response.text
        return response.json()

    def get(self, path: str) -> Any:
        return self.http.get(f"/api/v1/{path}").json()

    def invite(self, **body: Any) -> str:
        token: str = self.post("federation/invitations", **body)["token"]
        return token


def started(instance: Instance, root_pem: str) -> Parent:
    instance.serve()
    instance.wait(lambda: listening(instance.https_port), "HTTPS")
    http = httpx.Client(
        base_url=f"https://127.0.0.1:{instance.https_port}",
        verify=ssl.create_default_context(cadata=root_pem),
    )
    chain = x509.load_pem_x509_certificates(http.get("/ca/chain.pem").content)
    return Parent(instance, root_pem, chain[0], http)


@pytest.fixture(scope="module")
def root(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Parent]:
    """Root CA, pathLen 3, reachable as 127.0.0.1 and pki.home42.test but not as localhost."""
    instance = Instance(tmp_path_factory.mktemp("root"), SERVER_ALT_NAMES="127.0.0.1")
    init = instance.cli(
        "authority", "init", "--name", "root", "--common-name", "Root CA", "--path-length", "3"
    )
    assert init.returncode == 0, init.stderr
    root_pem = instance.cli("authority", "export").stdout
    try:
        parent = started(instance, root_pem)
        yield parent
        parent.http.close()
    finally:
        instance.kill()


@pytest.fixture
def child(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Environment of the child: its own database, in this process."""
    database = tmp_path / "data" / "h42pki.sqlite3"
    monkeypatch.setenv(f"{ENV_PREFIX}DATABASE_URL", f"sqlite://{database.as_posix()}")
    monkeypatch.setenv(f"{ENV_PREFIX}CA_PASSPHRASE", TEST_PASSPHRASE)
    monkeypatch.setenv(f"{ENV_PREFIX}ENVIRONMENT", "test")
    get_settings.cache_clear()


def invoke(*args: str, stdin: str | None = None) -> Result:
    result = runner.invoke(app, list(args), input=stdin)
    assert "Traceback" not in plain(result)
    return result


def enrol(parent: Parent, token: str, *extra: str, **overrides: str) -> Result:
    values = {
        "parent-url": parent.url,
        "parent-fingerprint": parent.fingerprint,
        "name": "child",
        "common-name": "Child CA",
        **{key.replace("_", "-"): value for key, value in overrides.items()},
    }
    options = [part for key, value in values.items() for part in (f"--{key}", value)]
    result = invoke("authority", "init", *options, "--token", "-", *extra, stdin=token + "\n")
    assert token.partition(".")[2] not in plain(result)
    return result


async def _state(settings: Settings) -> dict[str, Any]:
    return {
        "authorities": {a.name: a for a in await Authority.all()},
        "local": await Authority.get_or_none(kind=AuthorityKind.LOCAL),
        "keys": await PrivateKey.all().count(),
        "certificates": await Certificate.all().count(),
        "actions": [entry.action for entry in await AuditLog.all()],
        "audit": str([entry.details for entry in await AuditLog.all()]),
    }


def state() -> dict[str, Any]:
    return run(_state)


def requests_of(parent: Parent) -> int:
    return len(parent.get("requests"))


# --- enrolment -----------------------------------------------------------------------------


def test_auto_approved_enrolment(root: Parent, child: None) -> None:
    token = root.invite(auto_approve=True, path_length=1)

    result = enrol(root, token, "--public-base-url", "http://auto.test", name="auto")

    assert result.exit_code == 0, plain(result)
    assert "Subordinate CA active." in plain(result)
    after = state()
    local = after["local"]
    assert (local.status, local.path_length) == (AuthorityStatus.ACTIVE, 1)
    assert local.pending_csr_der is None and local.pending_enrollment_id is None
    [parent] = [a for a in after["authorities"].values() if a.kind is AuthorityKind.PARENT]
    assert parent.federation_url == root.url and parent.pinned_fingerprint == root.fingerprint
    assert after["actions"].count("authority.init") == 1
    assert after["actions"].count("authority.activate") == 1
    assert token.partition(".")[2] not in after["audit"]

    status = plain(invoke("authority", "status"))
    for text in ("subordinate", "CN=Root CA", root.url, root.fingerprint):
        assert text in status
    listing = plain(invoke("certificate", "list"))
    assert "(root)" in listing and "(ca)" in listing
    assert "auto" in [c["name"] for c in root.get("federation/children")]


def test_manual_enrolment_then_resume(root: Parent, child: None) -> None:
    token = root.invite()

    waiting = enrol(root, token, "--wait-minutes", "0", name="manual")

    assert waiting.exit_code == 3
    assert "still waiting" in plain(waiting) and "--resume" in plain(waiting)
    status = plain(invoke("authority", "status"))
    assert "pending_signature" in status
    assert invoke("authority", "export").exit_code == 1
    again = enrol(root, token, name="other")
    assert again.exit_code == 1 and "--resume" in plain(again)

    still = invoke(
        "authority", "init", "--resume", "--token", "-", "--wait-minutes", "0", stdin=token
    )
    assert still.exit_code == 3
    request_id = str(state()["local"].pending_enrollment_id)
    root.post(f"requests/{request_id}/approve")
    result = invoke("authority", "init", "--resume", "--token", token)

    assert result.exit_code == 0, plain(result)
    assert state()["local"].status is AuthorityStatus.ACTIVE
    assert invoke("authority", "init", "--resume", "--token", token).exit_code == 1


def test_rejection_leaves_nothing(root: Parent, child: None) -> None:
    token = root.invite()
    enrol(root, token, "--wait-minutes", "0", name="rejected")
    request_id = str(state()["local"].pending_enrollment_id)
    root.post(f"requests/{request_id}/reject", reason="not planned")

    result = invoke("authority", "init", "--resume", "--token", "-", stdin=token)

    assert result.exit_code == 1
    assert "rejected the enrolment: not planned" in plain(result)
    after = state()
    assert after["authorities"] == {} and after["keys"] == 0 and after["certificates"] == 0
    assert "authority.abandon" in after["actions"] and "private_key.delete" in after["actions"]
    # A new attempt works.
    assert enrol(root, root.invite(auto_approve=True), name="rejected-2").exit_code == 0


# --- refusals ------------------------------------------------------------------------------


def test_wrong_fingerprint_stops_before_anything_is_sent(root: Parent, child: None) -> None:
    before = requests_of(root)
    token = root.invite(auto_approve=True)

    result = enrol(root, token, parent_fingerprint="0" * 64, name="wrong")

    assert result.exit_code == 1 and "expected fingerprint" in plain(result)
    assert requests_of(root) == before
    after = state()
    assert after["authorities"] == {} and after["keys"] == 0
    # The token was not consumed.
    assert enrol(root, token, name="right").exit_code == 0


def test_host_name_missing_from_the_parent_certificate(root: Parent, child: None) -> None:
    before = requests_of(root)
    url = root.url.replace("127.0.0.1", "localhost")

    result = enrol(root, root.invite(auto_approve=True), parent_url=url, name="host")

    assert result.exit_code == 1
    assert "TLS certificate" in plain(result) and "H42_PKI_SERVER_ALT_NAMES" in plain(result)
    assert "abandon" in plain(result)
    assert requests_of(root) == before
    dropped = invoke("authority", "abandon")
    assert dropped.exit_code == 0 and "abandoned" in plain(dropped)
    assert state()["authorities"] == {}


def test_refused_token_leaves_nothing(root: Parent, child: None) -> None:
    token = root.invite(auto_approve=True)
    assert enrol(root, token, name="first").exit_code == 0
    run(_reset)

    result = enrol(root, token, name="second")  # used for another request

    assert result.exit_code == 1 and "401" in plain(result)
    assert state()["authorities"] == {}


async def _reset(settings: Settings) -> None:
    """Forget the local hierarchy, as a brand new container would."""
    await Certificate.all().delete()
    for kind in (AuthorityKind.LOCAL, AuthorityKind.PARENT):
        await Authority.filter(kind=kind).delete()
    await PrivateKey.all().delete()


def test_name_already_taken_on_the_parent(root: Parent, child: None) -> None:
    enrol(root, root.invite(auto_approve=True), name="twin")
    run(_reset)

    result = enrol(root, root.invite(auto_approve=True), name="twin")

    assert result.exit_code == 1 and "409" in plain(result) and "twin" in plain(result)
    assert state()["authorities"] == {}


def test_unreachable_parent(root: Parent, child: None) -> None:
    result = enrol(root, root.invite(), parent_url=f"https://127.0.0.1:{free_port()}")

    assert result.exit_code == 1 and "cannot reach" in plain(result)
    assert state()["authorities"] == {}


# --- hierarchy -----------------------------------------------------------------------------


@pytest.fixture(scope="module")
def intermediate(root: Parent, tmp_path_factory: pytest.TempPathFactory) -> Iterator[Parent]:
    instance = Instance(tmp_path_factory.mktemp("intermediate"))
    init = instance.cli(
        *("authority", "init", "--name", "intermediate", "--common-name", "Intermediate CA"),
        *("--parent-url", root.url, "--parent-fingerprint", root.fingerprint, "--token", "-"),
        stdin=root.invite(auto_approve=True) + "\n",
    )
    assert init.returncode == 0, init.stderr
    try:
        parent = started(instance, root.root_pem)
        yield parent
        parent.http.close()
    finally:
        instance.kill()


def test_three_levels(root: Parent, intermediate: Parent, child: None, tmp_path: Path) -> None:
    """The anchor pinned here is the intermediate CA, not the root (partial chain)."""
    published = x509.load_pem_x509_certificates(
        httpx.get(f"http://127.0.0.1:{intermediate.instance.http_port}/ca/chain.pem").content
    )
    assert [c.subject.rfc4514_string() for c in published] == [
        "CN=Intermediate CA",
        "CN=Root CA",
    ]
    authority = intermediate.get("authority")
    assert authority["mode"] == "subordinate" and authority["path_length"] == 2
    assert authority["parent"]["url"] == root.url
    assert authority["parent"]["sha256_fingerprint"] == root.fingerprint
    assert root.get("authority")["mode"] == "root" and root.get("authority")["parent"] is None

    result = enrol(intermediate, intermediate.invite(auto_approve=True), name="issuing")
    assert result.exit_code == 0, plain(result)

    key = ec.generate_private_key(ec.SECP256R1())
    csr = csr_pem(make_csr(key, name(CN="www.home42.test"), sans=["dns:www.home42.test"]))

    async def issue(settings: Settings) -> tuple[bytes, list[bytes], list[bytes]]:
        request = await IssuanceService(get_keystore(settings)).submit(
            csr=csr, profile_name="tls_server", validity_days=None, actor="test"
        )
        leaf = await Certificate.get(id=request.certificate_id)

        full = await CertificateService().chain(leaf)
        return (
            leaf.der,
            [c.der for c in await PublicationService().chain()],
            [c.der for c in full],
        )

    leaf_der, chain_ders, full_ders = run(issue)
    chain = [x509.load_der_x509_certificate(der) for der in chain_ders]
    leaf = x509.load_der_x509_certificate(leaf_der)
    assert [c.subject.rfc4514_string() for c in chain] == [
        "CN=Child CA",
        "CN=Intermediate CA",
        "CN=Root CA",
    ]
    assert full_ders == [leaf_der, *chain_ders]
    lengths = [
        c.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length for c in chain
    ]
    assert lengths == [1, 2, 3]
    root_cert = x509.load_pem_x509_certificate(root.root_pem.encode())
    verified = (
        verification.PolicyBuilder()
        .store(verification.Store([root_cert]))
        .time(datetime.now(UTC))
        .build_server_verifier(x509.DNSName("www.home42.test"))
        .verify(leaf, chain[:2])
    )
    assert len(verified) == 4

    openssl = shutil.which("openssl")
    if openssl is None:
        return
    pem = serialization.Encoding.PEM
    (tmp_path / "root.pem").write_text(root.root_pem)
    (tmp_path / "chain.pem").write_bytes(b"".join(c.public_bytes(pem) for c in chain))
    (tmp_path / "leaf.pem").write_bytes(leaf.public_bytes(pem))
    check = subprocess.run(  # noqa: S603 - fixed arguments
        [openssl, "verify", "-CAfile", "root.pem", "-untrusted", "chain.pem", "leaf.pem"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert check.returncode == 0, check.stderr


def test_pinned_context_flags(root: Parent) -> None:
    context = pinned_context(root.certificate)

    assert context.verify_mode is ssl.CERT_REQUIRED and context.check_hostname
    assert context.verify_flags & ssl.VerifyFlags.VERIFY_X509_PARTIAL_CHAIN
    assert context.verify_flags & ssl.VerifyFlags.VERIFY_X509_STRICT
    assert len(context.get_ca_certs()) == 1  # no system trust store
    default = ssl.create_default_context()
    assert default.verify_flags & ssl.VerifyFlags.VERIFY_X509_PARTIAL_CHAIN
    assert default.verify_flags & ssl.VerifyFlags.VERIFY_X509_STRICT


def test_pinned_context_refuses_another_hierarchy(root: Parent) -> None:
    other = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    impostor = (
        x509.CertificateBuilder()
        .subject_name(root.certificate.subject)
        .issuer_name(root.certificate.subject)
        .public_key(other.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(root.certificate.not_valid_after_utc)
        .add_extension(x509.BasicConstraints(True, None), critical=True)
        .sign(other, root.certificate.signature_hash_algorithm)  # type: ignore[arg-type]
    )
    with pytest.raises(httpx.ConnectError):
        httpx.get(f"{root.url}/health", verify=pinned_context(impostor))


async def test_https_of_the_child_opens_after_activation(
    root: Parent,
    run_launcher: Any,
    server_settings: Callable[..., Settings],
    keystore: KeyStore,
) -> None:
    running: Running
    async with run_launcher(server_settings()) as running:
        async with httpx.AsyncClient() as http:
            service = SubordinateService(keystore)
            token = root.invite()
            await service.start(
                parent_url=root.url,
                parent_fingerprint=root.fingerprint,
                token=token,
                name="launched",
                subject=Subject(common_name="Launched CA"),
                key_algorithm=KeyAlgorithm.EC_P256,
                public_base_url=None,
                actor="test",
            )
            pending = (await http.get(running.http("/health"))).json()
            assert (pending["authority"], pending["https"]) == ("pending_signature", "waiting")
            assert (await http.get(running.http("/ca/chain.pem"))).status_code == 503

            authority = await service.pending()
            root.post(f"requests/{authority.pending_enrollment_id}/approve")
            await service.resume(token, actor="test")

            await running.wait_https()
            await wait_for(lambda: not running.launcher.status.https_waiting, "HTTPS")
        # The child is trusted from the root of the hierarchy.
        context = ssl.create_default_context(cadata=root.root_pem)
        async with httpx.AsyncClient(verify=context) as https:
            health = (await https.get(running.https("/health"))).json()
            chain = await https.get(running.https("/ca/chain.pem"))
            authority_out = (await https.get(running.https("/api/v1/authority"))).json()
    assert health["authority"] == "active"
    assert len(x509.load_pem_x509_certificates(chain.content)) == 2
    assert authority_out["mode"] == "subordinate"
