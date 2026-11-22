"""`h42pki certificate …`: issued certificates (read-only, no passphrase needed)."""

import sys
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from h42pki.cli._runtime import fail, run
from h42pki.config import Settings
from h42pki.errors import NotFound
from h42pki.models import Certificate, CertificateStatus
from h42pki.services import CertificateService
from h42pki.services.certificates import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, effective_status

app = typer.Typer(help="List and export certificates.", no_args_is_help=True)

COLUMNS = ("SERIAL", "SUBJECT", "PROFILE", "STATUS", "NOT AFTER")


class ExportFormat(StrEnum):
    PEM = "pem"
    DER = "der"


@app.command("list")
def list_certificates(
    status: Annotated[
        CertificateStatus | None, typer.Option(help="Effective status (expired included).")
    ] = None,
    profile: Annotated[str | None, typer.Option(help="Profile name.")] = None,
    limit: Annotated[
        int, typer.Option(min=1, max=MAX_PAGE_SIZE, help="Maximum number of rows.")
    ] = DEFAULT_PAGE_SIZE,
) -> None:
    """List certificates, newest first."""
    now = datetime.now(UTC)

    async def operation(settings: Settings) -> tuple[list[tuple[str, str, str, str, str]], int]:
        page = await CertificateService().search(
            status=status, profile=profile, limit=limit, now=now
        )
        rows: list[tuple[str, str, str, str, str]] = [
            (
                cert.serial_hex,
                cert.subject_dn or "-",
                cert.profile.name if cert.profile is not None else "(root)",
                effective_status(cert, now).value,
                cert.not_after.isoformat(),
            )
            for cert in page.items
        ]
        return rows, page.total

    rows, total = run(operation)
    widths = [max(len(row[i]) for row in [COLUMNS, *rows]) for i in range(len(COLUMNS))]
    for row in [COLUMNS, *rows]:
        typer.echo("  ".join(value.ljust(width) for value, width in zip(row, widths, strict=True)))
    typer.echo(f"{len(rows)} of {total} certificate(s)", err=True)


@app.command()
def export(
    certificate_id: Annotated[UUID, typer.Argument(metavar="ID", help="Certificate id.")],
    chain: Annotated[
        bool, typer.Option("--chain", help="Append the issuers up to the root (PEM only).")
    ] = False,
    format_: Annotated[
        ExportFormat, typer.Option("--format", help="Output encoding.")
    ] = ExportFormat.PEM,
    output: Annotated[
        Path | None, typer.Option(help="Write to this file instead of standard output.")
    ] = None,
) -> None:
    """Export a certificate (optionally with its chain)."""
    if chain and format_ is ExportFormat.DER:
        fail("--chain is only available in PEM (a DER file holds one certificate)", code=2)

    async def operation(settings: Settings) -> list[bytes]:
        service = CertificateService()
        certificate = await Certificate.get_or_none(id=certificate_id)
        if certificate is None:
            raise NotFound(f"certificate {certificate_id} does not exist")
        certificates = await service.chain(certificate) if chain else [certificate]
        return [cert.der for cert in certificates]

    ders = run(operation)
    if format_ is ExportFormat.DER:
        data = ders[0]
    else:
        data = b"".join(
            x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM)
            for der in ders
        )
    if output is None:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        output.write_bytes(data)
        typer.echo(f"Written to {output}", err=True)
