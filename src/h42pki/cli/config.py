"""`h42pki config …`: runtime settings stored in the database (ADR-0011).

The CLI is the only writer until the API has authentication (ADR-0008): the server reads the
database and picks the change up by itself (hot), restarts a listener, or needs a restart of the
container, depending on the level of the setting.
"""

import json
from typing import Annotated, Any

import typer

from h42pki.cli._runtime import CLI_ACTOR, run
from h42pki.config import Settings
from h42pki.core.settings_schema import ApplyLevel, parse_cli_value
from h42pki.services.settings import SettingChange, SettingsService, SettingView

app = typer.Typer(help="Show and change the runtime settings.", no_args_is_help=True)

COLUMNS = ("KEY", "VALUE", "DEFAULT", "ORIGIN", "LEVEL")
MAX_VALUE_WIDTH = 48


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _short(value: Any) -> str:
    text = _json(value)
    return text if len(text) <= MAX_VALUE_WIDTH else text[: MAX_VALUE_WIDTH - 1] + "…"


def _level(view: SettingView | SettingChange) -> str:
    if view.apply is ApplyLevel.LISTENER:
        return f"listener ({', '.join(view.listeners)})"
    return view.apply.value


def effect_message(change: SettingChange) -> str:
    """What happens to the running server after a write."""
    if not change.changed:
        return "effective value unchanged: nothing to apply"
    if change.apply is ApplyLevel.HOT:
        return "applied hot: the running server uses it without restart"
    if change.apply is ApplyLevel.LISTENER:
        names = " and ".join(name.upper() for name in change.listeners)
        noun = "listeners" if len(change.listeners) > 1 else "listener"
        return f"the {names} {noun} will restart within a few seconds (brief interruption)"
    return "takes effect at the next restart of the container"


@app.command()
def show() -> None:
    """List every setting: effective value, default, origin and application level."""

    async def operation(settings: Settings) -> list[SettingView]:
        return await SettingsService().describe()

    rows = [
        (view.key, _short(view.value), _short(view.default), view.origin, _level(view))
        for view in run(operation)
    ]
    widths = [max(len(row[i]) for row in [COLUMNS, *rows]) for i in range(len(COLUMNS))]
    for row in [COLUMNS, *rows]:
        line = "  ".join(value.ljust(width) for value, width in zip(row, widths, strict=True))
        typer.echo(line.rstrip())


@app.command()
def get(key: Annotated[str, typer.Argument(help="Setting key, section.name.")]) -> None:
    """Print the effective value of a setting (JSON), then its details on stderr."""

    async def operation(settings: Settings) -> SettingView:
        return await SettingsService().get(key)

    view = run(operation)
    typer.echo(_json(view.value))
    details = f"default {_json(view.default)}, origin {view.origin}, level {_level(view)}"
    if view.updated_by is not None and view.updated_at is not None:
        details += f", set by {view.updated_by} on {view.updated_at.isoformat()}"
    typer.echo(f"{details}\n{view.description}", err=True)


@app.command("set")
def set_(
    key: Annotated[str, typer.Argument(help="Setting key, section.name.")],
    value: Annotated[str, typer.Argument(help='JSON value (30, true, null, ["a"]) or plain text.')],
) -> None:
    """Change a setting (validated, audited)."""

    async def operation(settings: Settings) -> SettingChange:
        return await SettingsService().set(key, parse_cli_value(value), actor=CLI_ACTOR)

    change = run(operation)
    typer.echo(f"{key} = {_json(change.new)} (was {_json(change.previous)})")
    typer.echo(effect_message(change))


@app.command()
def unset(key: Annotated[str, typer.Argument(help="Setting key, section.name.")]) -> None:
    """Go back to the default value of a setting."""

    async def operation(settings: Settings) -> SettingChange:
        return await SettingsService().unset(key, actor=CLI_ACTOR)

    change = run(operation)
    typer.echo(f"{key} = {_json(change.new)} (default; was {_json(change.previous)})")
    typer.echo(effect_message(change))
