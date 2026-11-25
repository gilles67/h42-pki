"""`h42pki request …`: certificate requests and manual decisions."""

from typing import Annotated
from uuid import UUID

import typer

from h42pki.cli._runtime import CLI_ACTOR, print_table, run
from h42pki.config import Settings
from h42pki.keystore import get_keystore
from h42pki.models import CertificateRequest, RequestStatus
from h42pki.services import IssuanceService
from h42pki.services.issuance import child_of

app = typer.Typer(help="List and decide certificate requests.", no_args_is_help=True)

COLUMNS = ("ID", "STATUS", "PROFILE", "CHANNEL", "SUBJECT", "CREATED")

RequestId = Annotated[UUID, typer.Argument(help="Request ID (see `h42pki request list`).")]


def _describe(request: CertificateRequest) -> None:
    child = child_of(request)
    rows = [
        ("ID", str(request.id)),
        ("Status", request.status.value),
        ("Profile", request.profile.name),
        ("Channel", request.channel.value),
        ("Subject", request.subject_dn),
        ("Requester", request.requester),
        ("Created", request.created_at.isoformat()),
    ]
    if child is not None:
        rows += [
            ("Child CA", child.name),
            ("Child URL", child.public_base_url or "-"),
            ("Invitation", str(request.invitation.id)),
        ]
    if request.decided_at is not None:
        rows.append(("Decided", f"{request.decided_at.isoformat()} by {request.decided_by}"))
    if request.certificate_id is not None:
        rows.append(("Certificate", str(request.certificate_id)))
    reason = request.rejection_reason or request.metadata.get("failure")
    if reason:
        rows.append(("Reason", reason))
    if ignored := request.metadata.get("ignored_extensions"):
        rows.append(("Ignored CSR extensions", ", ".join(ignored)))
    width = max(len(label) for label, _ in rows)
    for label, value in rows:
        typer.echo(f"{label.ljust(width)}  {value}")


@app.command("list")
def list_requests(
    status: Annotated[RequestStatus | None, typer.Option(help="Only this status.")] = None,
) -> None:
    """List the certificate requests, oldest first."""

    async def operation(settings: Settings) -> list[CertificateRequest]:
        return await IssuanceService().list(status)

    print_table(
        COLUMNS,
        [
            (
                str(request.id),
                request.status.value,
                request.profile.name,
                request.channel.value,
                request.subject_dn or "-",
                request.created_at.isoformat(timespec="seconds"),
            )
            for request in run(operation)
        ],
    )


@app.command()
def show(request_id: RequestId) -> None:
    """Show a request."""

    async def operation(settings: Settings) -> CertificateRequest:
        return await IssuanceService().get(request_id)

    _describe(run(operation))


@app.command()
def approve(request_id: RequestId) -> None:
    """Approve a pending request: the certificate is issued at once."""

    async def operation(settings: Settings) -> CertificateRequest:
        return await IssuanceService(get_keystore(settings)).approve(request_id, actor=CLI_ACTOR)

    request = run(operation)
    typer.secho("Request approved, certificate issued.", fg=typer.colors.GREEN)
    _describe(request)


@app.command()
def reject(
    request_id: RequestId,
    reason: Annotated[str, typer.Option(help="Reason, told to the requester.")],
) -> None:
    """Reject a pending request."""

    async def operation(settings: Settings) -> CertificateRequest:
        return await IssuanceService().reject(request_id, reason=reason, actor=CLI_ACTOR)

    request = run(operation)
    typer.secho("Request rejected.", fg=typer.colors.GREEN)
    _describe(request)
