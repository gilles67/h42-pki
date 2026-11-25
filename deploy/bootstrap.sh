#!/usr/bin/env bash
# Build the example hierarchy of compose.yaml (root -> intermediate -> issuing), issue a TLS server
# certificate with the issuing CA and verify it up to the root.
#
# Usage: deploy/bootstrap.sh [--fresh] [OUTPUT_DIRECTORY]
#   --fresh   remove the containers and VOLUMES of this compose project first (all its CAs!)
# Needs podman with podman-compose >= 1.3 (or CONTAINER_ENGINE=docker: docker with compose v2), curl
# and openssl. Invitation tokens only travel through pipes: they are neither printed, nor written to a
# file, nor visible in a process list.
set -euo pipefail

FRESH=false
if [ "${1:-}" = --fresh ]; then
  FRESH=true
  shift
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=deploy/engine.sh
. "$HERE/engine.sh"
need_compose
need curl "install curl"
need openssl "install openssl"
OUT="${1:-$HERE/out}"
ISSUING_HTTPS_PORT="${ISSUING_HTTPS_PORT:-18443}"
START_TIMEOUT="${START_TIMEOUT:-120}" # seconds, per container
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
cd "$HERE"

compose() { "${COMPOSE[@]}" -f compose.yaml "$@"; }
pki_stdin() { # pki_stdin SERVICE ARGS...: the CLI of one CA, reading standard input
  local service="$1"
  shift
  compose exec -T "$service" h42pki "$@"
}
# podman-compose always runs `exec --interactive`: do not let it swallow the input of the script.
pki() { pki_stdin "$@" </dev/null; }
step() { printf '\n== %s\n' "$*"; }

wait_healthy() { # portable replacement of `up --wait`, unknown to podman-compose 1.3
  local service="$1" deadline=$((SECONDS + START_TIMEOUT))
  until pki "$service" healthcheck >/dev/null 2>&1; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "$service is not healthy after $START_TIMEOUT s" >&2
      pki "$service" healthcheck >&2 || true
      compose logs "$service" >&2 || true
      return 1
    fi
    sleep 2
  done
}

wait_https() { # the launcher opens HTTPS by itself once the CA is active
  local service="$1"
  for _ in $(seq 1 60); do
    if pki "$service" authority status >/dev/null 2>&1 &&
      compose exec -T "$service" python -c \
        "import socket; socket.create_connection(('127.0.0.1', 8443), 2).close()" </dev/null 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "HTTPS of $service does not open" >&2
  compose logs "$service" >&2 || true
  return 1
}

enrol() { # enrol PARENT CHILD COMMON_NAME PATH_LENGTH
  local parent="$1" child="$2" common_name="$3" path_length="$4" fingerprint
  fingerprint="$(pki "$parent" authority export |
    openssl x509 -noout -fingerprint -sha256 | cut -d= -f2)"
  pki "$parent" federation invite --label "$child" --path-length "$path_length" \
    --auto-approve --expires-in-hours 1 |
    pki_stdin "$child" authority init --name "$child" --common-name "$common_name" \
      --parent-url "https://$parent:8443" --parent-fingerprint "$fingerprint" --token - \
      --public-base-url "http://$child.pki.test:8080"
}

# Readable by the container user, not writable by others (checked by h42-pki).
chmod 0644 secrets/EXAMPLE-*.txt

if "$FRESH"; then
  step "remove the previous hierarchy"
  compose down --volumes
fi

step "start the three containers"
compose up -d --build
for service in root intermediate issuing; do
  wait_healthy "$service"
done

step "root"
pki root authority init --name root --common-name "Home42 Example Root CA" --path-length 2 \
  --public-base-url http://root.pki.test:8080
wait_https root
pki root authority export >"$OUT/root.pem"

step "intermediate, invited by the root"
enrol root intermediate "Home42 Example Intermediate CA" 1
wait_https intermediate

step "issuing, invited by the intermediate"
enrol intermediate issuing "Home42 Example Issuing CA" 0
wait_https issuing

step "TLS server certificate issued by the issuing CA"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$OUT/leaf.key" -out "$OUT/leaf.csr" -subj "/CN=www.pki.test" \
  -addext "subjectAltName=DNS:www.pki.test" 2>/dev/null
API="https://127.0.0.1:$ISSUING_HTTPS_PORT"
csr="$(awk '{printf "%s\\n", $0}' "$OUT/leaf.csr")"
id="$(printf '{"csr_pem": "%s", "profile": "tls_server"}' "$csr" |
  curl -fsS --cacert "$OUT/root.pem" -H 'content-type: application/json' -d @- \
    "$API/api/v1/requests" | sed -n 's/.*"certificate_id":"\([^"]*\)".*/\1/p')"
curl -fsS --cacert "$OUT/root.pem" -o "$OUT/leaf.pem" "$API/api/v1/certificates/$id.pem"
curl -fsS --cacert "$OUT/root.pem" -o "$OUT/chain.pem" "$API/ca/chain.pem"

step "verify up to the root"
(cd "$OUT" && openssl verify -CAfile root.pem -untrusted chain.pem leaf.pem)
