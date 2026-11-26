"""`h42pki authority …`: the local certificate authority."""

import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pydantic import ValidationError

from h42pki.cli._runtime import CLI_ACTOR, fail, run, validation_message
from h42pki.config import Settings
from h42pki.core.keys import KeyAlgorithm
from h42pki.core.names import Subject
from h42pki.core.publication import PublicBaseUrl, normalize_public_base_url
from h42pki.core.validity import DEFAULT_CA_VALIDITY_DAYS, MAX_VALIDITY_DAYS, MIN_VALIDITY_DAYS
from h42pki.errors import H42Error
from h42pki.keystore import get_keystore, optional_keystore
from h42pki.models import Authority, AuthorityStatus, Certificate
from h42pki.services import AuthorityService
from h42pki.services.authority import check_not_idle
from h42pki.services.crl import CrlService
from h42pki.services.subordinate import SubordinateService

app = typer.Typer(help="Manage the local certificate authority.", no_args_is_help=True)


class ExportFormat(StrEnum):
    PEM = "pem"
    DER = "der"


def _parent_rows(authority: Authority) -> list[tuple[str, str]]:
    """``parent__certificate`` must be prefetched."""
    parent = authority.parent
    if parent is None:
        return [("Mode", "root")]
    return [
        ("Mode", "subordinate"),
        ("Parent", parent.certificate.subject_dn),
        ("Parent SHA-256", parent.certificate.sha256_fingerprint),
        ("Parent URL", parent.federation_url or "-"),
    ]


def _describe(authority: Authority, certificate: Certificate) -> list[tuple[str, str]]:
    path_length = "unlimited" if authority.path_length is None else str(authority.path_length)
    return [
        ("Name", authority.name),
        ("Status", authority.status.value),
        *_parent_rows(authority),
        ("Subject", certificate.subject_dn),
        ("SHA-256", certificate.sha256_fingerprint),
        ("Not before", certificate.not_before.isoformat()),
        ("Not after", certificate.not_after.isoformat()),
        ("Path length", path_length),
        ("Public base URL", authority.public_base_url or "-"),
        *_revocation_rows(authority),
    ]


def _enabled(value: bool) -> str:
    return "enabled" if value else "disabled"


def _revocation_rows(authority: Authority) -> list[tuple[str, str]]:
    rows = [("CRL", _enabled(authority.crl_enabled)), ("OCSP", _enabled(authority.ocsp_enabled))]
    if authority.parent_check_result is not None and authority.parent_check_at is not None:
        checked = authority.parent_check_at.isoformat(timespec="seconds")
        rows.append(("Parent check", f"{authority.parent_check_result} ({checked})"))
    return rows


def _describe_pending(authority: Authority) -> list[tuple[str, str]]:
    enrolment = authority.pending_enrollment_id
    return [
        ("Name", authority.name),
        ("Status", authority.status.value),
        *_parent_rows(authority),
        ("Enrolment", str(enrolment) if enrolment is not None else "not acknowledged yet"),
        ("Public base URL", authority.public_base_url or "-"),
        *_revocation_rows(authority),
    ]


def _normalized_url(url: str) -> PublicBaseUrl:
    try:
        return normalize_public_base_url(url)
    except H42Error as exc:
        fail(exc.detail, code=2)


def _warn(warnings: list[str]) -> None:
    for message in warnings:
        typer.secho(f"warning: {message}", err=True, fg=typer.colors.YELLOW)


def _print(rows: list[tuple[str, str]]) -> None:
    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        typer.echo(f"{label.ljust(width)}  {value}")


def _read_token(token: str | None) -> str:
    if token is None:
        fail("--token is required (- reads it on standard input)", code=2)
    return sys.stdin.readline().strip() if token == "-" else token  # noqa: S105 - stdin marker


async def _first_crl(settings: Settings, authority: Authority) -> None:
    """Publish a CRL as soon as the CA is active: issued certificates already point to it."""
    keystore = optional_keystore(settings)
    if authority.crl_enabled and keystore is not None:
        await CrlService(keystore).ensure_fresh(authority, actor=CLI_ACTOR)


async def _finish(
    settings: Settings,
    service: SubordinateService,
    authority: Authority,
    token: str,
    wait_minutes: int,
) -> list[tuple[str, str]] | None:
    """Wait for the decision if needed; the description of the active CA, None if pending."""
    if authority.status is AuthorityStatus.PENDING_SIGNATURE:
        typer.echo("Enrolment sent: waiting for the decision of the parent CA...", err=True)
        authority = await service.wait(token, seconds=wait_minutes * 60, actor=CLI_ACTOR)
    if authority.status is AuthorityStatus.PENDING_SIGNATURE:
        return None
    local = await AuthorityService().get_local()
    await _first_crl(settings, local)
    return _describe(local, local.certificate)


def _conclude(rows: list[tuple[str, str]] | None) -> None:
    if rows is None:
        fail(
            "still waiting for the approval of the parent CA; resume later with "
            "`h42pki authority init --resume --token -`",
            code=3,
        )
    typer.secho("Subordinate CA active.", fg=typer.colors.GREEN)
    _print(rows)


def _enrol(
    *,
    parent_url: str,
    parent_fingerprint: str,
    token: str,
    name: str,
    subject: Subject,
    key_algorithm: KeyAlgorithm,
    public_base_url: str | None,
    crl: bool,
    ocsp: bool,
    wait_minutes: int,
) -> None:
    async def operation(settings: Settings) -> list[tuple[str, str]] | None:
        check_not_idle(idle=settings.idle, name=name, crl=crl, ocsp=ocsp)
        service = SubordinateService(get_keystore(settings))
        try:
            authority = await service.start(
                parent_url=parent_url,
                parent_fingerprint=parent_fingerprint,
                token=token,
                name=name,
                subject=subject,
                key_algorithm=key_algorithm,
                public_base_url=public_base_url,
                crl=crl,
                ocsp=ocsp,
                actor=CLI_ACTOR,
            )
            return await _finish(settings, service, authority, token, wait_minutes)
        except H42Error:
            await _hint(service)
            raise

    _conclude(run(operation))


def _resume(token: str, wait_minutes: int) -> None:
    async def operation(settings: Settings) -> list[tuple[str, str]] | None:
        service = SubordinateService()
        try:
            authority = await service.resume(token, actor=CLI_ACTOR)
            return await _finish(settings, service, authority, token, wait_minutes)
        except H42Error:
            await _hint(service)
            raise

    _conclude(run(operation))


async def _hint(service: SubordinateService) -> None:
    """After a failure that leaves the CA pending: what can be done."""
    if await service.find_pending() is not None:
        typer.echo(
            "The enrolment is kept: try again with `h42pki authority init --resume --token -`, "
            "or drop it with `h42pki authority abandon`.",
            err=True,
        )


@app.command()
def abandon() -> None:
    """Drop the enrolment in progress: the CA waiting for its certificate, and its key."""

    async def operation(settings: Settings) -> str:
        return await SubordinateService().abandon(actor=CLI_ACTOR)

    typer.secho(f"Enrolment of {run(operation)} abandoned, its key is deleted.", fg="green")
    typer.echo("If the parent already signed it, revoke it there (`h42pki federation`).")


@app.command()
def init(
    name: Annotated[str | None, typer.Option(help="Name of the CA (unique).")] = None,
    common_name: Annotated[str | None, typer.Option(help="Subject common name (CN).")] = None,
    organization: Annotated[str | None, typer.Option(help="Subject organization (O).")] = None,
    organizational_unit: Annotated[
        str | None, typer.Option(help="Subject organizational unit (OU).")
    ] = None,
    country: Annotated[str | None, typer.Option(help="Subject country (C), 2 letters.")] = None,
    key_algorithm: Annotated[
        KeyAlgorithm, typer.Option(help="Algorithm of the new CA key.")
    ] = KeyAlgorithm.EC_P384,
    validity_days: Annotated[
        int | None,
        typer.Option(
            min=MIN_VALIDITY_DAYS,
            max=MAX_VALIDITY_DAYS,
            help=f"Validity of the root certificate in days ({MIN_VALIDITY_DAYS}-"
            f"{MAX_VALIDITY_DAYS}, default {DEFAULT_CA_VALIDITY_DAYS}). Root only.",
        ),
    ] = None,
    path_length: Annotated[
        int | None,
        typer.Option(
            min=0, help="Maximum number of CAs below this one (default: unlimited). Root only."
        ),
    ] = None,
    public_base_url: Annotated[
        str | None,
        typer.Option(help="Public HTTP base URL of this CA (stored for AIA publication)."),
    ] = None,
    parent_url: Annotated[
        str | None, typer.Option(help="https URL of the parent CA: makes a subordinate CA.")
    ] = None,
    token: Annotated[
        str | None,
        typer.Option(help="Invitation token; - reads it on standard input (recommended)."),
    ] = None,
    parent_fingerprint: Annotated[
        str | None, typer.Option(help="SHA-256 of the parent CA certificate.")
    ] = None,
    wait_minutes: Annotated[
        int, typer.Option(min=0, max=1440, help="How long to wait for a manual approval.")
    ] = 10,
    resume: Annotated[
        bool, typer.Option("--resume", help="Go on with the enrolment in progress.")
    ] = False,
    crl: Annotated[
        bool,
        typer.Option(
            "--crl",
            help="Publish a CRL and write its URL (CDP) in issued certificates. Fixed for the "
            "life of the CA; needs a listener (no idle mode).",
        ),
    ] = False,
    ocsp: Annotated[
        bool,
        typer.Option(
            "--ocsp",
            help="Answer OCSP and write its URL (AIA) in issued certificates. Fixed for the "
            "life of the CA; needs a listener (no idle mode).",
        ),
    ] = False,
) -> None:
    """Create the local CA: a root (default), or the child of another CA (--parent-url).

    A subordinate CA needs --parent-url, --token and --parent-fingerprint, all given by
    `h42pki federation invite` on the parent, which decides its validity and path length.
    """
    if resume:
        if any((name, common_name, parent_url, parent_fingerprint, public_base_url, crl, ocsp)):
            fail("--resume only takes --token and --wait-minutes", code=2)
        _resume(_read_token(token), wait_minutes)
        return
    if name is None or common_name is None:
        fail("--name and --common-name are required", code=2)
    try:
        subject = Subject(
            common_name=common_name,
            organization_name=organization,
            organizational_unit_name=organizational_unit,
            country_name=country,
        )
    except ValidationError as exc:
        fail(f"invalid subject: {validation_message(exc)}", code=2)

    if public_base_url is not None:
        _warn(_normalized_url(public_base_url).warnings)
    if parent_url is not None:
        if validity_days is not None or path_length is not None:
            fail("--validity-days and --path-length are decided by the parent CA", code=2)
        if parent_fingerprint is None:
            fail("--parent-fingerprint is required with --parent-url", code=2)
        _enrol(
            parent_url=parent_url,
            parent_fingerprint=parent_fingerprint,
            token=_read_token(token),
            name=name,
            subject=subject,
            key_algorithm=key_algorithm,
            public_base_url=public_base_url,
            crl=crl,
            ocsp=ocsp,
            wait_minutes=wait_minutes,
        )
        return
    if token is not None or parent_fingerprint is not None:
        fail("--token and --parent-fingerprint go with --parent-url", code=2)

    async def operation(settings: Settings) -> list[tuple[str, str]]:
        check_not_idle(idle=settings.idle, name=name, crl=crl, ocsp=ocsp)
        service = AuthorityService(get_keystore(settings))
        authority = await service.init_root(
            name=name,
            subject=subject,
            key_algorithm=key_algorithm,
            validity_days=validity_days or DEFAULT_CA_VALIDITY_DAYS,
            path_length=path_length,
            public_base_url=public_base_url,
            crl=crl,
            ocsp=ocsp,
            actor=CLI_ACTOR,
        )
        await _first_crl(settings, authority)
        return _describe(authority, await service.certificate_of(authority))

    rows = run(operation)
    typer.secho("Root CA created.", fg=typer.colors.GREEN)
    _print(rows)


@app.command()
def update(
    public_base_url: Annotated[
        str,
        typer.Option(
            help="New public HTTP base URL of the CA (written in the AIA of issued "
            'certificates); "" removes it.'
        ),
    ],
) -> None:
    """Change the settings of the local CA."""
    url = public_base_url.strip() or None
    if url is not None:
        _warn(_normalized_url(url).warnings)

    async def operation(settings: Settings) -> str | None:
        service = AuthorityService()  # no private key involved
        authority, _ = await service.update_public_base_url(url, actor=CLI_ACTOR)
        return authority.public_base_url

    stored = run(operation)
    if stored is None:
        typer.secho("Public base URL removed: issued certificates will carry no AIA.", fg="green")
    else:
        typer.secho(f"Public base URL set to {stored}", fg=typer.colors.GREEN)
    typer.echo("Certificates already issued are unchanged; only new ones use this setting.")


@app.command()
def status() -> None:
    """Show the local CA."""

    async def operation(settings: Settings) -> list[tuple[str, str]] | None:
        service = AuthorityService()  # read-only: no passphrase needed (B32)
        authority = await service.find_local()
        if authority is None:
            pending = await SubordinateService.find_pending()
            return _describe_pending(pending) if pending is not None else None
        return _describe(authority, await service.certificate_of(authority))

    rows = run(operation)
    if rows is None:
        fail("no local certificate authority: run `h42pki authority init` first")
    _print(rows)


@app.command()
def export(
    format_: Annotated[
        ExportFormat, typer.Option("--format", help="Output encoding.")
    ] = ExportFormat.PEM,
    output: Annotated[
        Path | None, typer.Option(help="Write to this file instead of standard output.")
    ] = None,
) -> None:
    """Export the certificate of the local CA."""

    async def operation(settings: Settings) -> bytes:
        service = AuthorityService()  # read-only: no passphrase needed (B32)
        return (await service.certificate_of(await service.get_local())).der

    der = run(operation)
    data = (
        der
        if format_ is ExportFormat.DER
        else x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)
    )
    if output is None:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        output.write_bytes(data)
        typer.echo(f"Written to {output}", err=True)
