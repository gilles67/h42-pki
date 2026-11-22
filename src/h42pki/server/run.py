"""``h42pki serve``: open the database, configure logging, run the launcher until a signal."""

import asyncio
import logging
import signal
from contextlib import suppress

from tortoise import Tortoise

from h42pki.config import Settings
from h42pki.db import ensure_sqlite_directory, tortoise_config
from h42pki.keystore import get_keystore
from h42pki.logs import configure_logging
from h42pki.main import create_app
from h42pki.server.launcher import Launcher
from h42pki.services.profiles import ProfileService
from h42pki.services.settings import SettingsService

log = logging.getLogger(__name__)


def install_signal_handlers(stop: asyncio.Event) -> None:
    """SIGINT / SIGTERM set ``stop`` (loop handlers on POSIX, signal.signal on Windows)."""
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # Windows
            signal.signal(sig, lambda *_: loop.call_soon_threadsafe(stop.set))


async def open_database(settings: Settings) -> None:
    """Schema and built-in profiles, as the lifespan does; ``database.pool_size`` applied."""
    ensure_sqlite_directory(settings.database_url)
    await Tortoise.init(config=tortoise_config(settings))
    # TODO(release): migrations instead of generate_schemas (ADR-0007).
    await Tortoise.generate_schemas(safe=True)
    await ProfileService().sync_builtin()
    pool_size = (await SettingsService().effective()).database.pool_size
    if pool_size is not None and not settings.database_url.startswith("sqlite://"):
        # Process level setting: read from the database, so reconnect with it.
        await Tortoise.close_connections()
        await Tortoise.init(config=tortoise_config(settings, pool_size=pool_size))


async def run_server(settings: Settings, stop: asyncio.Event | None = None) -> None:
    """Run the launcher until ``stop`` is set (by a signal when not given)."""
    stop = stop or asyncio.Event()
    install_signal_handlers(stop)
    await open_database(settings)
    try:
        runtime = await SettingsService().effective()
        configure_logging(runtime.logging.format, runtime.logging.level)
        app = create_app(settings, manage_database=False)
        launcher = Launcher(settings, app, get_keystore(settings))
        await launcher.run(stop)
    finally:
        with suppress(Exception):
            await Tortoise.close_connections()
