"""FastAPI application factory."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from tortoise.contrib.fastapi import RegisterTortoise

from h42pki import __version__
from h42pki.api import admin, federation, health, ocsp, public
from h42pki.api.listener import ListenerRoutesMiddleware
from h42pki.api.problems import exception_handlers, install_problem_schemas
from h42pki.config import Settings, get_settings
from h42pki.db import ensure_sqlite_directory, tortoise_config
from h42pki.keystore import KEY_OPERATIONS_REQUIREMENT
from h42pki.services.ocsp import OcspCache
from h42pki.services.profiles import ProfileService


def create_app(settings: Settings | None = None, *, manage_database: bool = True) -> FastAPI:
    """Build the application; ``settings`` defaults to :func:`get_settings`.

    ``manage_database``: the lifespan opens the database (tests, direct ASGI use). The launcher
    passes False: it opens the database itself and runs Uvicorn without lifespan, since two
    listeners would otherwise run it twice (ADR-0012).
    """
    app_settings = settings if settings is not None else get_settings()
    if app_settings.ca_passphrase is None:
        # Unchanged behaviour: the API generates and uses keys, it does not start without it.
        raise RuntimeError(f"cannot start the server: {KEY_OPERATIONS_REQUIREMENT}")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if not manage_database:
            yield
            return
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
    app.state.launcher = None  # LauncherStatus, set by the launcher
    # Answers without nonce, signed by the CA key; a revocation here drops its entries.
    app.state.ocsp_cache = OcspCache()
    app.state.revocation_listener = app.state.ocsp_cache.invalidate
    # Public routes only on the HTTP listener, everything on HTTPS (ADR-0012).
    app.add_middleware(ListenerRoutesMiddleware)
    app.include_router(health.router)
    app.include_router(admin.router)
    app.include_router(federation.router)
    app.include_router(public.router)
    app.include_router(ocsp.router)
    install_problem_schemas(app)
    return app
