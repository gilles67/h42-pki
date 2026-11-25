#!/usr/bin/env bash
# Smoke test of the image (phase 1.1): build, healthy with listeners, HTTPS opened by
# `authority init` without restart, healthy in idle mode (no listener at all).
#
# Usage: deploy/smoke-test.sh [IMAGE]
# Needs podman (or CONTAINER_ENGINE=docker), curl and openssl.
# Everything it creates (containers, volumes) is removed at the end; the image is kept.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=deploy/engine.sh
. "$ROOT_DIR/deploy/engine.sh"
need_engine
need curl "install curl"
need openssl "install openssl"

IMAGE="${1:-h42-pki:smoke}"
NAME="h42pki-smoke-$$"
HTTP_PORT="${HTTP_PORT:-18080}"
HTTPS_PORT="${HTTPS_PORT:-18443}"
WORK="$(mktemp -d)"
PASSPHRASE="$(openssl rand -hex 24)" # throwaway, for this run only

cleanup() {
  "$CONTAINER_ENGINE" rm -f "$NAME" "$NAME-idle" >/dev/null 2>&1 || true
  "$CONTAINER_ENGINE" volume rm -f "$NAME" "$NAME-idle" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
die() {
  printf 'FAILED: %s\n' "$*" >&2
  for container in "$NAME" "$NAME-idle"; do
    "$CONTAINER_ENGINE" logs "$container" 2>&1 | sed "s/^/$container: /" >&2 || true
  done
  exit 1
}

wait_healthy() {
  local status
  for _ in $(seq 1 60); do
    status="$("$CONTAINER_ENGINE" inspect --format '{{.State.Health.Status}}' "$1" 2>/dev/null || true)"
    [ "$status" = healthy ] && return 0
    sleep 2
  done
  die "$1 is not healthy (status ${status:-none: does the image have a HEALTHCHECK?})"
}

run() {
  local name="$1"
  shift
  H42_PKI_CA_PASSPHRASE="$PASSPHRASE" "$CONTAINER_ENGINE" run -d --name "$name" -v "$name:/data" \
    -e H42_PKI_CA_PASSPHRASE \
    -e H42_PKI_SERVER_HOSTNAME=pki.home42.test \
    -e H42_PKI_SERVER_ALT_NAMES=localhost,127.0.0.1 "$@" "$IMAGE" >/dev/null
}

step "build $IMAGE"
"$CONTAINER_ENGINE" build "${BUILD_OPTIONS[@]}" -t "$IMAGE" "$ROOT_DIR"

step "empty database: HTTP answers, HTTPS closed, container healthy"
run "$NAME" -p "127.0.0.1:$HTTP_PORT:8080" -p "127.0.0.1:$HTTPS_PORT:8443"
wait_healthy "$NAME"
curl -fsS "http://127.0.0.1:$HTTP_PORT/health" && echo
curl -ks --max-time 3 "https://127.0.0.1:$HTTPS_PORT/" >/dev/null && die "HTTPS is already open"

step "authority init opens HTTPS without restart"
"$CONTAINER_ENGINE" exec "$NAME" h42pki authority init --name home42-root --common-name "Home42 Root CA"
"$CONTAINER_ENGINE" exec "$NAME" h42pki authority export >"$WORK/root.pem"
for _ in $(seq 1 30); do
  curl -fs --cacert "$WORK/root.pem" "https://127.0.0.1:$HTTPS_PORT/health" >/dev/null && break
  sleep 1
done
curl -fsS --cacert "$WORK/root.pem" "https://127.0.0.1:$HTTPS_PORT/health" && echo

step "admin API: 404 over HTTP, 200 over HTTPS"
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$HTTP_PORT/api/v1/authority")"
[ "$code" = 404 ] || die "HTTP answered $code"
code="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$WORK/root.pem" \
  "https://127.0.0.1:$HTTPS_PORT/api/v1/authority")"
[ "$code" = 200 ] || die "HTTPS answered $code"

step "idle mode (no listener): healthy"
run "$NAME-idle" -e H42_PKI_HTTP_ENABLED=false -e H42_PKI_HTTPS_ENABLED=false
wait_healthy "$NAME-idle"

step "OK"
