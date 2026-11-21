"""FastAPI application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from tortoise.contrib.fastapi import RegisterTortoise

from h42pki import __version__
from h42pki.api import admin, health
from h42pki.api.problems import exception_handlers
from h42pki.config import Settings, get_settings
from h42pki.db import ensure_sqlite_directory, tortoise_config
from h42pki.services.profiles import ProfileService


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application; ``settings`` defaults to :func:`get_settings`."""
    app_settings = settings if settings is not None else get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        ensure_sqlite_directory(app_settings.database_url)
        # TODO(release): migrations instead of generate_schemas (ADR-0007).
        async with RegisterTortoise(
            app,
            config=tortoise_config(app_settings),
            generate_schemas=True,
        ):
            await ProfileService().sync_builtin()
            yield

    app = FastAPI(
        title="h42-pki",
        version=__version__,
        lifespan=lifespan,
        exception_handlers=exception_handlers(),
    )
    app.state.settings = app_settings
    app.include_router(health.router)
    app.include_router(admin.router)
    return app
