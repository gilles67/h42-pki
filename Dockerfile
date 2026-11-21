# syntax=docker/dockerfile:1
#
# h42-pki: one container = one certificate authority.
#
# Required at run time: the CA key passphrase, through one of
#   -e H42_PKI_CA_PASSPHRASE=...                  (environment variable)
#   -e H42_PKI_CA_PASSPHRASE_FILE=/path/in/container
#   a Docker secret named h42_pki_ca_passphrase   (/run/secrets/h42_pki_ca_passphrase)
# The SQLite database lives in the /data volume.

ARG PYTHON_VERSION=3.12

FROM ghcr.io/astral-sh/uv:0.13.9 AS uv

# --- build: resolve and install the locked dependencies into /app/.venv -------------------------
FROM python:${PYTHON_VERSION}-slim AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0 \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /app
# Dependencies first (cached layer), then the project itself.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# --- runtime --------------------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim AS runtime
RUN groupadd --system --gid 10001 h42pki \
    && useradd --system --uid 10001 --gid 10001 --home-dir /app --no-create-home \
       --shell /usr/sbin/nologin h42pki \
    && mkdir -p /data \
    && chown 10001:10001 /data
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    H42_PKI_DATABASE_URL=sqlite:///data/h42pki.sqlite3
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8000
# slim images have no curl: probe /health with the standard library.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status == 200 else 1)"]
# A single worker: scheduled tasks run in the lifespan (docs/ARCHITECTURE.md section 9).
CMD ["granian", "--interface", "asgi", "--factory", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "1", "h42pki.main:create_app"]
