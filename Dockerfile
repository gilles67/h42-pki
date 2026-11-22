# syntax=docker/dockerfile:1
#
# h42-pki: one container = one certificate authority (ADR-0001).
#
# Required at run time:
#   - the CA key passphrase, through one of
#       -e H42_PKI_CA_PASSPHRASE=...                  (environment variable)
#       -e H42_PKI_CA_PASSPHRASE_FILE=/path/in/container
#       a Docker secret named h42_pki_ca_passphrase   (/run/secrets/h42_pki_ca_passphrase)
#   - -e H42_PKI_SERVER_HOSTNAME=pki.example.lan      (FQDN of the service, ADR-0011)
# Optional: H42_PKI_SERVER_ALT_NAMES, H42_PKI_HTTP_ENABLED|PORT, H42_PKI_HTTPS_ENABLED|PORT,
# H42_PKI_TRUSTED_PROXIES. Everything else is in the database (`h42pki config`).
#
# `h42pki serve` is the built-in launcher (ADR-0012): HTTP on 8080 (public routes: /, /health,
# /ca/*), HTTPS on 8443 (everything) as soon as the CA is active and has issued the certificate
# of its own server (ADR-0013). Publish them with -p 80:8080 -p 443:8443.
# The SQLite database (data and configuration) lives in the /data volume.

ARG PYTHON_VERSION=3.13

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
    H42_PKI_DATABASE_URL=sqlite:///data/h42pki.sqlite3 \
    H42_PKI_BIND_ADDRESS=0.0.0.0
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8080 8443
# Port independent: database and launcher heartbeat; also healthy in idle mode (no listener).
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD ["h42pki", "healthcheck"]
# One process: both listeners and the scheduled tasks (docs/ARCHITECTURE.md section 9).
CMD ["h42pki", "serve"]
