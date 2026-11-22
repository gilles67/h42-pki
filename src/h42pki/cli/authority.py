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
from h42pki.core.validity import DEFAULT_CA_VALIDITY_DAYS, MAX_VALIDITY_DAYS, MIN_VALIDITY_DAYS
from h42pki.keystore import get_keystore
from h42pki.models import Authority, Certificate
from h42pki.services import AuthorityService

app = typer.Typer(help="Manage the local certificate authority.", no_args_is_help=True)


class ExportFormat(StrEnum):
    PEM = "pem"
    DER = "der"


def _describe(authority: Authority, certificate: Certificate) -> list[tuple[str, str]]:
    path_length = "unlimited" if authority.path_length is None else str(authority.path_length)
    return [
        ("Name", authority.name),
        ("Status", authority.status.value),
        ("Subject", certificate.subject_dn),
        ("SHA-256", certificate.sha256_fingerprint),
        ("Not before", certificate.not_before.isoformat()),
        ("Not after", certificate.not_after.isoformat()),
        ("Path length", path_length),
        ("Public base URL", authority.public_base_url or "-"),
    ]


def _print(rows: list[tuple[str, str]]) -> None:
    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        typer.echo(f"{label.ljust(width)}  {value}")


@app.command()
def init(
    name: Annotated[str, typer.Option(help="Name of the CA (unique).")],
    common_name: Annotated[str, typer.Option(help="Subject common name (CN).")],
    organization: Annotated[str | None, typer.Option(help="Subject organization (O).")] = None,
    organizational_unit: Annotated[
        str | None, typer.Option(help="Subject organizational unit (OU).")
    ] = None,
    country: Annotated[str | None, typer.Option(help="Subject country (C), 2 letters.")] = None,
    key_algorithm: Annotated[
        KeyAlgorithm, typer.Option(help="Algorithm of the new CA key.")
    ] = KeyAlgorithm.EC_P384,
    validity_days: Annotated[
        int,
        typer.Option(
            min=MIN_VALIDITY_DAYS,
            max=MAX_VALIDITY_DAYS,
            help=f"Validity of the root certificate in days ({MIN_VALIDITY_DAYS}-"
            f"{MAX_VALIDITY_DAYS}).",
        ),
    ] = DEFAULT_CA_VALIDITY_DAYS,
    path_length: Annotated[
        int | None,
        typer.Option(min=0, help="Maximum number of CAs below this one (default: unlimited)."),
    ] = None,
    public_base_url: Annotated[
        str | None,
        typer.Option(help="Public HTTP base URL of this CA (stored for AIA publication)."),
    ] = None,
) -> None:
    """Create the local root CA: a new key and its root certificate (ADR-0010)."""
    try:
        subject = Subject(
            common_name=common_name,
            organization_name=organization,
            organizational_unit_name=organizational_unit,
            country_name=country,
        )
    except ValidationError as exc:
        fail(f"invalid subject: {validation_message(exc)}", code=2)

    async def operation(settings: Settings) -> list[tuple[str, str]]:
        service = AuthorityService(get_keystore(settings))
        authority = await service.init_root(
            name=name,
            subject=subject,
            key_algorithm=key_algorithm,
            validity_days=validity_days,
            path_length=path_length,
            public_base_url=public_base_url,
            actor=CLI_ACTOR,
        )
        return _describe(authority, await service.certificate_of(authority))

    rows = run(operation)
    typer.secho("Root CA created.", fg=typer.colors.GREEN)
    _print(rows)


@app.command()
def status() -> None:
    """Show the local CA."""

    async def operation(settings: Settings) -> list[tuple[str, str]] | None:
        service = AuthorityService()  # read-only: no passphrase needed (B32)
        authority = await service.find_local()
        if authority is None:
            return None
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
