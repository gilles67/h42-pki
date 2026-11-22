"""Command-line interface (``h42pki``)."""

from typing import Annotated

import typer
import uvicorn

from h42pki import __version__
from h42pki.cli import authority, profile
from h42pki.cli._runtime import fail, load_settings
from h42pki.keystore import KEY_OPERATIONS_REQUIREMENT

app = typer.Typer(help="h42-pki certificate authority server.", no_args_is_help=True)
app.add_typer(authority.app, name="authority")
app.add_typer(profile.app, name="profile")


@app.command()
def version() -> None:
    """Print the installed h42-pki version."""
    typer.echo(__version__)


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Address to bind to.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port to listen on.")] = 8000,
    reload: Annotated[bool, typer.Option(help="Reload on code changes (development).")] = False,
) -> None:
    """Run the development server (uvicorn). Production images use Granian."""
    if load_settings().ca_passphrase is None:
        fail(f"cannot start the server: {KEY_OPERATIONS_REQUIREMENT}", code=2)
    uvicorn.run("h42pki.main:create_app", factory=True, host=host, port=port, reload=reload)
