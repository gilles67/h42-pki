"""FastAPI application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from tortoise.contrib.fastapi import RegisterTortoise, tortoise_exception_handlers

from h42pki import __version__
from h42pki.api import admin, health
from h42pki.config import Settings, get_settings
from h42pki.db import ensure_sqlite_directory, tortoise_config


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application; ``settings`` defaults to :func:`get_settings`."""
    app_settings = settings if settings is not None else get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        ensure_sqlite_directory(app_settings.database_url)
        # TODO(lot3): migrations instead of generate_schemas.
        async with RegisterTortoise(
            app,
            config=tortoise_config(app_settings),
            generate_schemas=True,
        ):
            yield

    app = FastAPI(
        title="h42-pki",
        version=__version__,
        lifespan=lifespan,
        exception_handlers=tortoise_exception_handlers(),
    )
    app.state.settings = app_settings
    app.include_router(health.router)
    app.include_router(admin.router)
    return app
