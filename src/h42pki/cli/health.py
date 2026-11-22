"""`h42pki healthcheck`: health of the service without any port (Docker HEALTHCHECK, ADR-0012).

Healthy when the database answers and the launcher heartbeat is less than 60 seconds old. Works
in idle mode (no listener) and needs neither the passphrase nor the hostname.
"""

import asyncio

import typer
from tortoise import Tortoise, connections

from h42pki.cli._runtime import fail, load_settings
from h42pki.config import Settings
from h42pki.db import tortoise_config
from h42pki.heartbeat import HEARTBEAT_MAX_AGE_SECONDS, heartbeat_age, heartbeat_path

DATABASE_TIMEOUT_SECONDS = 5.0


async def _database_answers(settings: Settings) -> bool:
    try:
        async with asyncio.timeout(DATABASE_TIMEOUT_SECONDS):
            await Tortoise.init(config=tortoise_config(settings))
            await connections.get("default").execute_query("SELECT 1")
    except Exception:  # unhealthy whatever the reason; no detail that could leak a URL
        return False
    finally:
        await Tortoise.close_connections()
    return True


def check(settings: Settings, *, max_age: float = HEARTBEAT_MAX_AGE_SECONDS) -> tuple[bool, str]:
    """(healthy, short message)."""
    if not asyncio.run(_database_answers(settings)):
        return False, "unhealthy: the database does not answer"
    age = heartbeat_age(heartbeat_path(settings.database_url))
    if age is None:
        return False, "unhealthy: no heartbeat, the launcher (h42pki serve) is not running"
    if age > max_age:
        return (
            False,
            f"unhealthy: the launcher heartbeat is {age:.0f} s old (limit {max_age:.0f} s)",
        )
    return True, f"healthy: database answers, launcher heartbeat {age:.0f} s ago"


def healthcheck() -> None:
    """Exit 0 if the database answers and the launcher is alive, 1 otherwise."""
    healthy, message = check(load_settings())
    if not healthy:
        fail(message)
    typer.echo(message)
