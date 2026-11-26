"""`h42pki crl …`: the CRL of the local CA (ADR-0017)."""

import sys
from typing import Annotated

import typer
from cryptography import x509

from h42pki.cli._runtime import CLI_ACTOR, run
from h42pki.config import Settings
from h42pki.core.publication import crl_url
from h42pki.keystore import get_keystore
from h42pki.models import Authority, Crl
from h42pki.services import AuthorityService
from h42pki.services.crl import CrlService

app = typer.Typer(help="CRL of the local CA.", no_args_is_help=True)


def _print(authority: Authority, crl: Crl) -> None:
    rows = [
        ("CA", authority.name),
        ("CRL number", str(crl.crl_number)),
        ("This update", crl.this_update.isoformat()),
        ("Next update", crl.next_update.isoformat()),
        ("Entries", str(crl.entries)),
        (
            "URL",
            crl_url(authority.public_base_url, authority.name)
            if authority.public_base_url is not None
            else "- (no public base URL)",
        ),
    ]
    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        typer.echo(f"{label.ljust(width)}  {value}")


@app.command()
def show(
    der: Annotated[
        bool, typer.Option("--der", help="Write the CRL itself (DER) to standard output.")
    ] = False,
) -> None:
    """Show the current CRL (no passphrase needed)."""

    async def operation(settings: Settings) -> tuple[Authority, Crl]:
        authority = await AuthorityService().get_local()
        return authority, await CrlService.local(authority)

    authority, crl = run(operation)
    if der:
        sys.stdout.buffer.write(crl.der)
        sys.stdout.buffer.flush()
        return
    _print(authority, crl)
    revoked = x509.load_der_x509_crl(crl.der)
    for entry in revoked:
        typer.echo(f"  {entry.serial_number:x}  {entry.revocation_date_utc.isoformat()}")


@app.command()
def generate() -> None:
    """Sign a new CRL now (operations and tests; the server keeps it fresh by itself)."""

    async def operation(settings: Settings) -> tuple[Authority, Crl]:
        authority = await AuthorityService().get_local()
        await CrlService.local_enabled(authority)
        crl = await CrlService(get_keystore(settings)).generate(authority, actor=CLI_ACTOR)
        return authority, crl

    authority, crl = run(operation)
    typer.secho(f"CRL {crl.crl_number} generated.", fg=typer.colors.GREEN)
    _print(authority, crl)
