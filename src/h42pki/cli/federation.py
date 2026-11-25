"""`h42pki federation …`: invitations and child CAs of this CA (ADR-0015)."""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

import typer

from h42pki.cli._runtime import CLI_ACTOR, print_table, run
from h42pki.config import Settings
from h42pki.core.federation import DEFAULT_EXPIRES_IN_HOURS, MAX_EXPIRES_IN_HOURS
from h42pki.core.validity import MAX_VALIDITY_DAYS, MIN_VALIDITY_DAYS
from h42pki.models import Authority, FederationInvitation
from h42pki.services.federation import (
    CaRevocationReason,
    CreatedInvitation,
    FederationService,
    effective_status,
)

app = typer.Typer(help="Invite and manage child CAs.", no_args_is_help=True)

INVITATION_COLUMNS = ("ID", "STATUS", "LABEL", "APPROVAL", "PATH LENGTH", "EXPIRES", "REQUEST")
CHILD_COLUMNS = ("NAME", "STATUS", "SUBJECT", "PATH LENGTH", "NOT AFTER", "PUBLIC BASE URL")


@app.command()
def invite(
    label: Annotated[str | None, typer.Option(help="Free text, for the listings.")] = None,
    path_length: Annotated[
        int | None,
        typer.Option(
            min=0, max=255, help="CAs allowed below the child (default: as many as here)."
        ),
    ] = None,
    validity_days: Annotated[
        int | None,
        typer.Option(
            min=MIN_VALIDITY_DAYS,
            max=MAX_VALIDITY_DAYS,
            help="Validity of the child CA (default: the sub_ca profile).",
        ),
    ] = None,
    auto_approve: Annotated[
        bool, typer.Option("--auto-approve", help="Issue at once, without a manual decision.")
    ] = False,
    expires_in_hours: Annotated[
        int, typer.Option(min=1, max=MAX_EXPIRES_IN_HOURS, help="Lifetime of the invitation.")
    ] = DEFAULT_EXPIRES_IN_HOURS,
) -> None:
    """Create a single-use invitation.

    Standard output carries the token alone; the rest goes to standard error.
    """

    async def operation(settings: Settings) -> tuple[CreatedInvitation, str | None]:
        created = await FederationService().invite(
            label=label,
            path_length=path_length,
            validity_days=validity_days,
            auto_approve=auto_approve,
            expires_in_hours=expires_in_hours,
            actor=CLI_ACTOR,
        )
        return created, settings.https_url

    created, url = run(operation)
    allowed = created.effective_path_length
    decision = "issued at once" if auto_approve else "waits for `h42pki request approve`"
    for line in (
        f"Invitation {created.invitation.id}",
        f"Expires             {created.invitation.expires_at.isoformat(timespec='seconds')}",
        f"Child path length   {'unlimited' if allowed is None else allowed}",
        f"Approval            {decision}",
        f"Parent fingerprint  {created.parent_fingerprint}",
        "",
        "On the child, give the token below on standard input (adapt the URL to the published "
        "port):",
        f"  h42pki authority init --parent-url {url or 'https://THIS-CA'} --token - "
        f"--parent-fingerprint {created.parent_fingerprint} --name NAME --common-name CN",
        "",
        "Token, shown this one time:",
    ):
        typer.echo(line, err=True)
    typer.echo(created.token.reveal())


@app.command()
def invitations() -> None:
    """List the invitations, newest first (never their token)."""

    async def operation(settings: Settings) -> list[FederationInvitation]:
        return await FederationService().list()

    now = datetime.now(UTC)
    print_table(
        INVITATION_COLUMNS,
        [
            (
                str(item.id),
                effective_status(item, now).value,
                item.label or "-",
                "auto" if item.auto_approve else "manual",
                "-" if item.path_length is None else str(item.path_length),
                item.expires_at.isoformat(timespec="seconds"),
                str(item.request_id) if item.request_id is not None else "-",
            )
            for item in run(operation)
        ],
    )


@app.command("revoke-invitation")
def revoke_invitation(
    invitation_id: Annotated[UUID, typer.Argument(help="Invitation ID.")],
) -> None:
    """Revoke an unused invitation."""

    async def operation(settings: Settings) -> FederationInvitation:
        return await FederationService().revoke_invitation(invitation_id, actor=CLI_ACTOR)

    run(operation)
    typer.secho("Invitation revoked.", fg=typer.colors.GREEN)


@app.command()
def children() -> None:
    """List the child CAs signed through the federation."""

    async def operation(settings: Settings) -> list[Authority]:
        return await FederationService().children()

    print_table(
        CHILD_COLUMNS,
        [
            (
                child.name,
                child.status.value,
                child.certificate.subject_dn,
                "unlimited" if child.path_length is None else str(child.path_length),
                child.certificate.not_after.isoformat(timespec="seconds"),
                child.public_base_url or "-",
            )
            for child in run(operation)
        ],
    )


@app.command("revoke-child")
def revoke_child(
    name: Annotated[str, typer.Argument(help="Name of the child CA.")],
    reason: Annotated[CaRevocationReason, typer.Option(help="RFC 5280 reason.")],
) -> None:
    """Revoke a child CA."""

    async def operation(settings: Settings) -> Authority:
        return await FederationService().revoke_child(name, reason=reason, actor=CLI_ACTOR)

    run(operation)
    typer.secho(f"Child CA {name} revoked ({reason.value}).", fg=typer.colors.GREEN)
    typer.echo("Clients will only see it once CRL and OCSP exist (phase 3).")
