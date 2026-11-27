"""`h42pki est …`: EST accounts (HTTP Basic, ADR-0018).

A password is read on standard input (``--password -``), never as an argument (it would show in
``ps`` and the shell history), or generated: then printed once, alone on standard output.
"""

import sys
from datetime import UTC, datetime
from typing import Annotated

import typer

from h42pki.cli._runtime import CLI_ACTOR, fail, print_table, run
from h42pki.config import Settings
from h42pki.models import CredentialStatus, EnrollmentCredential
from h42pki.services.est_accounts import AccountSecret, EstAccountService

app = typer.Typer(help="EST enrollment (RFC 7030).", no_args_is_help=True)
account_app = typer.Typer(help="EST accounts (HTTP Basic).", no_args_is_help=True)
app.add_typer(account_app, name="account")

COLUMNS = ("USERNAME", "STATUS", "EXPIRES", "LAST USED", "DESCRIPTION")
PasswordOption = Annotated[
    str | None,
    typer.Option(
        "--password", help="- reads the password on standard input; generated when absent."
    ),
]


def _when(value: datetime | None) -> str:
    return value.isoformat(timespec="seconds") if value is not None else "-"


def _read_password(option: str | None) -> str | None:
    if option is None:
        return None
    if option != "-":
        fail("give the password on standard input: --password -", code=2)
    return sys.stdin.readline().rstrip("\r\n")


def _show_generated(secret: AccountSecret) -> None:
    if secret.generated_password is None:
        return
    typer.echo("Generated password, shown this one time:", err=True)
    typer.echo(secret.generated_password)


def _rows(account: EnrollmentCredential) -> list[tuple[str, str]]:
    return [
        ("Username", account.identifier),
        ("Status", account.status.value),
        ("Expires", _when(account.expires_at)),
        ("Description", account.description or "-"),
        ("Created", f"{_when(account.created_at)} by {account.created_by}"),
        ("Last used", _when(account.last_used_at)),
    ]


def _print(rows: list[tuple[str, str]]) -> None:
    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        typer.echo(f"{label.ljust(width)}  {value}")


@account_app.command()
def create(
    username: Annotated[str, typer.Argument(help="User name (letters, digits, . - _).")],
    password: PasswordOption = None,
    expires_at: Annotated[
        datetime | None,
        typer.Option(formats=["%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"], help="Expiry (ISO 8601, UTC)."),
    ] = None,
    description: Annotated[str | None, typer.Option(help="Free text.")] = None,
) -> None:
    """Create an EST account; any enabled profile is allowed to it."""
    chosen = _read_password(password)
    when = expires_at
    if when is not None and when.tzinfo is None:
        when = when.replace(tzinfo=UTC)  # a date alone is read as UTC

    async def operation(settings: Settings) -> AccountSecret:
        return await EstAccountService().create(
            username, password=chosen, expires_at=when, description=description, actor=CLI_ACTOR
        )

    secret = run(operation)
    typer.secho(f"EST account {secret.account.identifier} created.", fg="green", err=True)
    _show_generated(secret)


@account_app.command("list")
def list_accounts() -> None:
    """List the EST accounts (never their password)."""

    async def operation(settings: Settings) -> list[EnrollmentCredential]:
        return await EstAccountService().list()

    print_table(
        COLUMNS,
        [
            (
                account.identifier,
                account.status.value,
                _when(account.expires_at),
                _when(account.last_used_at),
                account.description or "-",
            )
            for account in run(operation)
        ],
    )


@account_app.command()
def show(username: Annotated[str, typer.Argument(help="User name.")]) -> None:
    """Show an EST account."""

    async def operation(settings: Settings) -> EnrollmentCredential:
        return await EstAccountService().get(username)

    _print(_rows(run(operation)))


def _set_status(username: str, status: CredentialStatus) -> None:
    async def operation(settings: Settings) -> EnrollmentCredential:
        return await EstAccountService().set_status(username, status, actor=CLI_ACTOR)

    account = run(operation)
    typer.secho(f"EST account {account.identifier} {account.status.value}.", fg="green")


@account_app.command()
def disable(username: Annotated[str, typer.Argument(help="User name.")]) -> None:
    """Disable an EST account (its enrolments are refused, 401)."""
    _set_status(username, CredentialStatus.DISABLED)


@account_app.command()
def enable(username: Annotated[str, typer.Argument(help="User name.")]) -> None:
    """Enable an EST account again."""
    _set_status(username, CredentialStatus.ACTIVE)


@account_app.command("reset-password")
def reset_password(
    username: Annotated[str, typer.Argument(help="User name.")],
    password: PasswordOption = None,
) -> None:
    """Give an EST account a new password (generated when --password is absent)."""
    chosen = _read_password(password)

    async def operation(settings: Settings) -> AccountSecret:
        return await EstAccountService().set_password(username, chosen, actor=CLI_ACTOR)

    secret = run(operation)
    typer.secho(f"Password of {secret.account.identifier} changed.", fg="green", err=True)
    _show_generated(secret)


@account_app.command()
def delete(username: Annotated[str, typer.Argument(help="User name.")]) -> None:
    """Delete an EST account."""

    async def operation(settings: Settings) -> None:
        await EstAccountService().delete(username, actor=CLI_ACTOR)

    run(operation)
    typer.secho(f"EST account {username} deleted.", fg="green")
