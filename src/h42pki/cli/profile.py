"""`h42pki profile …`: built-in certificate profiles (read-only, ADR-0009), enabled per CA."""

from typing import Annotated

import typer

from h42pki.cli._runtime import CLI_ACTOR, run
from h42pki.cli.config import effect_message
from h42pki.config import Settings
from h42pki.core.profiles import ProfileSpec
from h42pki.errors import NotFound
from h42pki.models import Profile
from h42pki.services import ProfileService
from h42pki.services.profiles import spec_of
from h42pki.services.settings import SettingChange

app = typer.Typer(help="Show certificate profiles, enable or disable them.", no_args_is_help=True)

COLUMNS = ("NAME", "KIND", "ENABLED", "APPROVAL", "VALIDITY (DAYS)", "EKU")


@app.command("list")
def list_profiles() -> None:
    """List the profiles."""

    async def operation(settings: Settings) -> tuple[list[ProfileSpec], set[str]]:
        service = ProfileService()
        return [spec_of(profile) for profile in await service.list()], await service.disabled()

    specs, disabled = run(operation)
    rows = [
        (
            spec.name,
            spec.kind.value,
            "internal" if spec.internal else "no" if spec.name in disabled else "yes",
            "auto" if spec.auto_approve else "manual",
            f"{spec.validity_days} (max {spec.max_validity_days})",
            ", ".join(spec.extended_key_usage) or "-",
        )
        for spec in specs
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


def _set_enabled(name: str, *, enabled: bool) -> None:
    async def operation(settings: Settings) -> SettingChange:
        return await ProfileService().set_enabled(name, enabled=enabled, actor=CLI_ACTOR)

    change = run(operation)
    state = "enabled" if enabled else "disabled"
    if not change.changed:
        typer.echo(f"profile {name} is already {state}")
        return
    typer.echo(f"profile {name} {state} (issuance.disabled_profiles = {change.new})")
    typer.echo(effect_message(change))


@app.command()
def disable(name: Annotated[str, typer.Argument(help="Profile name.")]) -> None:
    """Refuse new requests on a profile; its pending requests can only be rejected."""
    _set_enabled(name, enabled=False)


@app.command()
def enable(name: Annotated[str, typer.Argument(help="Profile name.")]) -> None:
    """Accept requests on a profile again."""
    _set_enabled(name, enabled=True)
