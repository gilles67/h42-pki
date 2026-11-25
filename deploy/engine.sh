# Container engine of the deploy scripts (sourced, ADR-0016): Podman by default, Docker with
# CONTAINER_ENGINE=docker. Script variable only: it is not a setting of h42-pki.
# shellcheck shell=bash

CONTAINER_ENGINE="${CONTAINER_ENGINE:-podman}"

need() { # need COMMAND HINT
  command -v "$1" >/dev/null 2>&1 || {
    printf 'error: %s not found: %s\n' "$1" "$2" >&2
    exit 2
  }
}

need_engine() {
  case "$CONTAINER_ENGINE" in
    podman)
      need podman "install Podman, or set CONTAINER_ENGINE=docker"
      # The OCI format, default of Podman, drops HEALTHCHECK. For podman-compose --build:
      export BUILDAH_FORMAT=docker
      BUILD_OPTIONS=(--format docker)
      ;;
    docker)
      need docker "install Docker, or unset CONTAINER_ENGINE to use Podman"
      BUILD_OPTIONS=()
      ;;
    *)
      printf 'error: CONTAINER_ENGINE must be podman or docker, not %s\n' "$CONTAINER_ENGINE" >&2
      exit 2
      ;;
  esac
}

need_compose() {
  need_engine
  if [ "$CONTAINER_ENGINE" = podman ]; then
    need podman-compose "install podman-compose 1.3 or later, or set CONTAINER_ENGINE=docker"
    COMPOSE=(podman-compose)
  else
    docker compose version >/dev/null 2>&1 || {
      echo "error: 'docker compose' not found: install Docker Compose v2" >&2
      exit 2
    }
    COMPOSE=(docker compose)
  fi
}
