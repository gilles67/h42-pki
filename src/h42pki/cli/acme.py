"""`h42pki acme …`: ACME accounts (ADR-0020)."""

from typing import Annotated
from uuid import UUID

import typer

from h42pki.cli._runtime import CLI_ACTOR, print_table, run
from h42pki.config import Settings
from h42pki.models import AcmeAccount, AcmeOrder
from h42pki.services.acme.accounts import AccountService

app = typer.Typer(help="ACME (RFC 8555).", no_args_is_help=True)
account_app = typer.Typer(help="ACME accounts.", no_args_is_help=True)
app.add_typer(account_app, name="account")

IdArgument = Annotated[UUID, typer.Argument(metavar="ID", help="Account id.")]


@account_app.command("list")
def list_accounts() -> None:
    """List the ACME accounts, most recent first."""

    async def operation(settings: Settings) -> list[tuple[AcmeAccount, int]]:
        return [
            (a, await AcmeOrder.filter(account_id=a.id).count())
            for a in await AccountService.list()
        ]

    print_table(
        ("ID", "STATUS", "ORDERS", "CONTACT", "CREATED"),
        [
            (
                str(account.id),
                account.status.value,
                str(orders),
                ",".join(account.contact) or "-",
                account.created_at.isoformat(timespec="seconds"),
            )
            for account, orders in run(operation)
        ],
    )


@account_app.command()
def show(account_id: IdArgument) -> None:
    """Show an account."""

    async def operation(settings: Settings) -> tuple[AcmeAccount, int]:
        account = await AccountService.get(account_id)
        return account, await AcmeOrder.filter(account_id=account.id).count()

    account, orders = run(operation)
    rows = [
        ("ID", str(account.id)),
        ("Status", account.status.value),
        ("Contact", ", ".join(account.contact) or "-"),
        ("Key", f"{account.jwk.get('kty', '?')} (thumbprint {account.jwk_thumbprint})"),
        ("Orders", str(orders)),
        ("Terms agreed", account.tos_agreed_at.isoformat() if account.tos_agreed_at else "-"),
        ("Created", account.created_at.isoformat(timespec="seconds")),
    ]
    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        typer.echo(f"{label.ljust(width)}  {value}")


@account_app.command()
def deactivate(account_id: IdArgument) -> None:
    """Deactivate an account: it can no longer sign any request (final)."""

    async def operation(settings: Settings) -> AcmeAccount:
        return await AccountService().deactivate(account_id, actor=CLI_ACTOR)

    account = run(operation)
    typer.secho(f"ACME account {account.id} {account.status.value}.", fg="green")
