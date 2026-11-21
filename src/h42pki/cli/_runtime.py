"""Shared runtime of the CLI commands: settings, database, readable errors."""

import asyncio
from collections.abc import Awaitable, Callable
from typing import NoReturn

import typer
from pydantic import ValidationError
from tortoise import Tortoise
from tortoise.exceptions import DoesNotExist

from h42pki.config import Settings, get_settings
from h42pki.db import ensure_sqlite_directory, tortoise_config
from h42pki.errors import H42Error
from h42pki.services import ProfileService

# Recorded in the audit log for operations run on the container's command line.
CLI_ACTOR = "cli"


def fail(message: str, code: int = 1) -> NoReturn:
    """Print an error without a Python traceback and exit with a non-zero code."""
    typer.secho(f"error: {message}", err=True, fg=typer.colors.RED)
    raise typer.Exit(code)


def validation_message(exc: ValidationError) -> str:
    # hide_input_in_errors / no `input`: submitted values (secrets) are never printed.
    return "; ".join(
        f"{'.'.join(str(part) for part in error['loc']) or 'value'}: {error['msg']}"
        for error in exc.errors(include_input=False)
    )


def load_settings() -> Settings:
    try:
        return get_settings()
    except ValidationError as exc:
        fail(f"invalid configuration: {validation_message(exc)}", code=2)


async def _with_database[T](settings: Settings, operation: Callable[[Settings], Awaitable[T]]) -> T:
    """Same database as the server: schema and built-in profiles are prepared like at start-up."""
    ensure_sqlite_directory(settings.database_url)
    await Tortoise.init(config=tortoise_config(settings))
    try:
        await Tortoise.generate_schemas(safe=True)  # TODO(release): migrations (ADR-0007)
        await ProfileService().sync_builtin()
        return await operation(settings)
    finally:
        await Tortoise.close_connections()


def run[T](operation: Callable[[Settings], Awaitable[T]]) -> T:
    """Run an async operation against the database, turning business errors into messages."""
    settings = load_settings()
    try:
        return asyncio.run(_with_database(settings, operation))
    except H42Error as exc:
        fail(exc.detail)
    except DoesNotExist:
        fail("not found")
