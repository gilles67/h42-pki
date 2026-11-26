"""Command-line interface (``h42pki``)."""

import asyncio
from pathlib import Path
from typing import Annotated

import typer

import h42pki
from h42pki import __version__
from h42pki.cli import authority, certificate, federation, health, profile, request
from h42pki.cli import config as config_cli
from h42pki.cli._runtime import fail, load_settings
from h42pki.config import Settings
from h42pki.keystore import KEY_OPERATIONS_REQUIREMENT

app = typer.Typer(
    help="h42-pki certificate authority server.",
    no_args_is_help=True,
    # Tokens and passphrases live in local variables: never in a traceback.
    pretty_exceptions_show_locals=False,
)
app.add_typer(authority.app, name="authority")
app.add_typer(profile.app, name="profile")
app.add_typer(certificate.app, name="certificate")
app.add_typer(request.app, name="request")
app.add_typer(federation.app, name="federation")
app.add_typer(config_cli.app, name="config")
app.command()(health.healthcheck)

HOSTNAME_REQUIREMENT = (
    "H42_PKI_SERVER_HOSTNAME (FQDN of the service, CN of its HTTPS certificate) is required"
)


@app.command()
def version() -> None:
    """Print the installed h42-pki version."""
    typer.echo(__version__)


def server_settings() -> Settings:
    """Settings of the server: passphrase and hostname are required (exit code 2 otherwise)."""
    settings = load_settings()
    if settings.ca_passphrase is None:
        fail(f"cannot start the server: {KEY_OPERATIONS_REQUIREMENT}", code=2)
    if settings.server_hostname is None:
        fail(f"cannot start the server: {HOSTNAME_REQUIREMENT}", code=2)
    return settings


def _serve_process() -> None:
    """Target of the reloader: a fresh process runs the whole launcher."""
    from h42pki.errors import RevocationNeedsListener
    from h42pki.server.run import run_server

    try:
        asyncio.run(run_server(server_settings()))
    except RevocationNeedsListener as exc:
        fail(f"cannot start the server: {exc.detail}", code=2)


@app.command()
def serve(
    reload: Annotated[
        bool, typer.Option(help="Restart the whole launcher on code changes (development).")
    ] = False,
) -> None:
    """Run the server: HTTP and HTTPS listeners in one process (ADR-0012).

    Addresses and ports come from H42_PKI_BIND_ADDRESS, H42_PKI_HTTP_* and H42_PKI_HTTPS_*.
    """
    server_settings()  # check before starting anything
    if reload:
        import watchfiles

        # The launcher is not a single ASGI app (Uvicorn's reloader only restarts one): restart
        # the whole process, listeners and tasks included, on any change of the package.
        watchfiles.run_process(Path(h42pki.__file__).parent, target=_serve_process)
        return
    _serve_process()
