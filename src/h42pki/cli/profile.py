"""`h42pki profile …`: built-in certificate profiles (read-only, ADR-0009)."""

from typing import Annotated

import typer

from h42pki.cli._runtime import run
from h42pki.config import Settings
from h42pki.core.profiles import ProfileSpec
from h42pki.errors import NotFound
from h42pki.models import Profile
from h42pki.services import ProfileService
from h42pki.services.profiles import spec_of

app = typer.Typer(help="Show certificate profiles.", no_args_is_help=True)

COLUMNS = ("NAME", "KIND", "APPROVAL", "VALIDITY (DAYS)", "EKU")


@app.command("list")
def list_profiles() -> None:
    """List the profiles."""

    async def operation(settings: Settings) -> list[ProfileSpec]:
        return [spec_of(profile) for profile in await ProfileService().list()]

    rows = [
        (
            spec.name,
            spec.kind.value,
            "auto" if spec.auto_approve else "manual",
            f"{spec.validity_days} (max {spec.max_validity_days})",
            ", ".join(spec.extended_key_usage) or "-",
        )
        for spec in run(operation)
    ]
    widths = [max(len(row[i]) for row in [COLUMNS, *rows]) for i in range(len(COLUMNS))]
    for row in [COLUMNS, *rows]:
        typer.echo("  ".join(value.ljust(width) for value, width in zip(row, widths, strict=True)))


@app.command()
def show(name: Annotated[str, typer.Argument(help="Profile name.")]) -> None:
    """Show a profile in JSON."""

    async def operation(settings: Settings) -> ProfileSpec:
        profile = await Profile.get_or_none(name=name)
        if profile is None:
            raise NotFound(f"profile {name!r} does not exist (see `h42pki profile list`)")
        return spec_of(profile)

    typer.echo(run(operation).model_dump_json(indent=2))
