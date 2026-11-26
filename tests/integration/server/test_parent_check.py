"""A child CA checks its own status with the OCSP of a real parent (another process, ADR-0017).

The parent is `h42pki serve` with its own database, created with --crl --ocsp and a public base URL
on its HTTP port; the child is the CLI of this process (its own database).
"""

from collections.abc import Iterator
from pathlib import Path

import click
import pytest
import typer

from h42pki.cli._runtime import run
from h42pki.config import Settings
from h42pki.keystore import get_keystore
from h42pki.models import AuditLog, Authority, AuthorityKind, AuthorityStatus
from h42pki.services import IssuanceService
from tests.cli_helpers import plain
from tests.integration.server.instance import Instance
from tests.integration.server.test_federation import (
    Parent,
    child,  # noqa: F401 - fixture: the child's environment
    enrol,
    invoke,
    started,
)
from tests.integration.test_cli import _server_csr


def make_parent(directory: Path, *options: str) -> Parent:
    instance = Instance(directory, SERVER_ALT_NAMES="127.0.0.1")
    init = instance.cli(
        "authority", "init", "--name", "parent", "--common-name", "Parent CA",
        "--path-length", "2", "--public-base-url", f"http://127.0.0.1:{instance.http_port}",
        *options,
    )  # fmt: skip
    assert init.returncode == 0, init.stderr
    return started(instance, instance.cli("authority", "export").stdout)


@pytest.fixture(scope="module")
def parent(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Parent]:
    running = make_parent(tmp_path_factory.mktemp("parent"), "--crl", "--ocsp")
    try:
        yield running
    finally:
        running.http.close()
        running.instance.kill()


def enrolled(parent: Parent, name: str) -> None:
    token = parent.invite(auto_approve=True)
    result = enrol(parent, token, "--crl", "--ocsp", name=name, common_name=f"{name} CA")
    assert result.exit_code == 0, result.output


def local_status() -> tuple[AuthorityStatus, str | None]:
    async def operation(settings: Settings) -> tuple[AuthorityStatus, str | None]:
        authority = await Authority.get(kind=AuthorityKind.LOCAL)
        return authority.status, authority.parent_check_result

    return run(operation)


def issue_here() -> None:
    async def operation(settings: Settings) -> None:
        await IssuanceService(get_keystore(settings)).submit(
            csr=_server_csr("www.example.test"),
            profile_name="tls_server",
            validity_days=None,
            actor="cli",
        )

    run(operation)


@pytest.mark.usefixtures("child")
def test_good(parent: Parent) -> None:
    enrolled(parent, "good-child")

    result = invoke("authority", "check-parent")
    status = plain(invoke("authority", "status"))

    assert result.exit_code == 0, result.output
    assert "good" in plain(result) and f"127.0.0.1:{parent.instance.http_port}/ocsp" in plain(
        result
    )
    assert local_status() == (AuthorityStatus.ACTIVE, "good")
    assert "Parent check" in status and "good" in status
    issue_here()  # still issues


@pytest.mark.usefixtures("child")
def test_revoked_stops_issuance(parent: Parent, capsys: pytest.CaptureFixture[str]) -> None:
    enrolled(parent, "revoked-child")
    parent.post("federation/children/revoked-child/revoke", reason="key_compromise")

    result = invoke("authority", "check-parent")

    assert result.exit_code == 1
    assert "revoked this CA" in plain(result) and "key_compromise" in plain(result)
    assert local_status() == (AuthorityStatus.REVOKED, "revoked")
    capsys.readouterr()
    with pytest.raises(typer.Exit):  # NoActiveAuthority (503), shown by the CLI runtime
        issue_here()
    assert "revoked by its parent" in click.unstyle(capsys.readouterr().err)
    # Still publishing: its CRL is signed, its status shown.
    assert invoke("crl", "generate").exit_code == 0
    assert "revoked" in plain(invoke("authority", "status"))

    async def audited(settings: Settings) -> bool:
        return await AuditLog.exists(action="authority.revoked_by_parent")

    assert run(audited)
    again = invoke("authority", "check-parent")  # idempotent
    assert again.exit_code == 1 and local_status()[0] is AuthorityStatus.REVOKED


@pytest.mark.usefixtures("child")
def test_unreachable_parent_changes_nothing(tmp_path: Path) -> None:
    lost = make_parent(tmp_path / "lost", "--ocsp")
    try:
        enrolled(lost, "lonely-child")
    finally:
        lost.http.close()
        lost.instance.kill()

    result = invoke("authority", "check-parent")

    assert result.exit_code == 1 and "unreachable" in plain(result)
    assert local_status() == (AuthorityStatus.ACTIVE, "unreachable")
    issue_here()


@pytest.mark.usefixtures("child")
def test_parent_without_ocsp(tmp_path: Path) -> None:
    plain_parent = make_parent(tmp_path / "plain")
    try:
        enrolled(plain_parent, "plain-child")
        result = invoke("authority", "check-parent")
    finally:
        plain_parent.http.close()
        plain_parent.instance.kill()

    assert result.exit_code == 1 and "no_ocsp" in plain(result)
    assert local_status() == (AuthorityStatus.ACTIVE, "no_ocsp")


@pytest.mark.usefixtures("child")
def test_a_root_has_no_parent() -> None:
    invoke("authority", "init", "--name", "root", "--common-name", "Root CA")

    result = invoke("authority", "check-parent")

    assert result.exit_code == 1 and "has no parent" in plain(result)
