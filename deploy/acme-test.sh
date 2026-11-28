#!/usr/bin/env bash
# ACME (RFC 8555, ADR-0020) on the issuing CA of the example hierarchy, after deploy/bootstrap.sh,
# with lego and certbot in containers on the network of the hierarchy (they trust the root):
#   1. every ACME route answers 404 until `h42pki config set acme.enabled true`;
#   2. http-01 with lego (the client answers on port 80 as www.pki.test);
#   3. http-01 with certbot --standalone (certbot.pki.test);
#   4. dns-01 and a wildcard with lego, through pebble-challtestsrv (acme.dns_resolvers);
#   5. an IP address in http-01 (RFC 8738) with lego;
#   6. manual approval (acme.manual_approval): lego waits, `h42pki request approve`, certificate;
#   7. `lego certificates revoke`, then `openssl ocsp` says revoked;
#   8. no private key, no challenge token, no unused nonce in the logs of the container.
#
# Usage: deploy/acme-test.sh [OUTPUT_DIRECTORY]   (the directory given to bootstrap.sh)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=deploy/engine.sh
. "$HERE/engine.sh"
need_compose
need curl "install curl"
need openssl "install openssl"
OUT="$(cd "${1:-$HERE/out}" && pwd)"
ISSUING_HTTP_PORT="${ISSUING_HTTP_PORT:-18083}"
ISSUING_HTTPS_PORT="${ISSUING_HTTPS_PORT:-18443}"
PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$HERE")}"
NETWORK="${PROJECT}_pki"
LEGO_IMAGE="${LEGO_IMAGE:-docker.io/goacme/lego:v5.8.1}"
CERTBOT_IMAGE="${CERTBOT_IMAGE:-docker.io/certbot/certbot:v5.10.0}"
CHALLTESTSRV_IMAGE="${CHALLTESTSRV_IMAGE:-ghcr.io/letsencrypt/pebble-challtestsrv:2.8.0}"
SERVER="https://issuing.pki.test:8443/acme"
OCSP="http://127.0.0.1:$ISSUING_HTTP_PORT/ocsp"
DNS="acme-dns-$PROJECT"
cd "$HERE"

compose() { "${COMPOSE[@]}" -f compose.yaml "$@"; }
pki() { compose exec -T issuing h42pki "$@" </dev/null; }
step() { printf '\n== %s\n' "$*"; }
fail() {
  printf 'FAILED: %s\n' "$*" >&2
  exit 1
}
expect() { # expect ACTUAL EXPECTED WHAT
  [ "$1" = "$2" ] || fail "$3: expected $2, got ${1:-nothing}"
  printf 'OK  %s: %s\n' "$3" "$1"
}

[ -s "$OUT/root.pem" ] || fail "$OUT/root.pem not found: run deploy/bootstrap.sh first"
WORK="$OUT/acme"
rm -rf "$WORK"
mkdir -p "$WORK"
cp "$OUT/root.pem" "$WORK/root.pem"

cleanup() {
  "$CONTAINER_ENGINE" rm -f -t 0 "$DNS" "acme-ip-$PROJECT" >/dev/null 2>&1 || true
  pki config unset acme.manual_approval >/dev/null 2>&1 || true
}
trap cleanup EXIT

lego() { # lego NAME ALIAS ARGS...: lego in a container answering as ALIAS on the network
  local name="$1" alias="$2"
  shift 2
  "$CONTAINER_ENGINE" run --rm --network "$NETWORK" --network-alias "$alias" \
    -v "$WORK:/work:Z" -e LEGO_CA_CERTIFICATES=/work/root.pem "$LEGO_IMAGE" \
    "$@" --path "/work/$name" --log.format text
}
lego_run() { # lego_run NAME ALIAS [PROFILE] ARGS...: obtain a certificate
  local name="$1" alias="$2"
  shift 2
  lego "$name" "$alias" run --server "$SERVER/directory" --accept-tos --email "admin@pki.test" \
    "$@"
}
check() { # check FILE: issued by the issuing CA, chained to the root, its SANs and dates
  openssl verify -CAfile "$WORK/root.pem" -untrusted "$OUT/chain.pem" "$1"
  openssl x509 -in "$1" -noout -issuer -dates -ext subjectAltName
}

step "ACME is disabled by default"
pki config unset acme.enabled >/dev/null
code="$(curl -sk -o /dev/null -w '%{http_code}' \
  "https://127.0.0.1:$ISSUING_HTTPS_PORT/acme/directory")"
expect "$code" 404 "directory before acme.enabled"
pki config set acme.enabled true
pki config set acme.retry_after_seconds 2 >/dev/null # the manual approval below polls quickly
curl -sk --cacert "$WORK/root.pem" "https://127.0.0.1:$ISSUING_HTTPS_PORT/acme/directory"
echo

step "http-01 with lego (www.pki.test)"
lego_run lego www.pki.test --domains www.pki.test --http 2>&1 | grep -E "validated|responded|ERROR"
check "$WORK/lego/certificates/www.pki.test.crt"
days="$(($(date -d "$(openssl x509 -in "$WORK/lego/certificates/www.pki.test.crt" -noout \
  -enddate | cut -d= -f2)" +%s) / 86400 - $(date +%s) / 86400))"
expect "$((days >= 46 && days <= 47))" 1 "tls_server validity of about 47 days ($days)"

step "http-01 with certbot --standalone (certbot.pki.test)"
"$CONTAINER_ENGINE" run --rm --network "$NETWORK" --network-alias certbot.pki.test \
  -v "$WORK:/work:Z" -e REQUESTS_CA_BUNDLE=/work/root.pem "$CERTBOT_IMAGE" certonly \
  --standalone --non-interactive --agree-tos -m admin@pki.test --server "$SERVER/directory" \
  -d certbot.pki.test --config-dir /work/certbot --work-dir /work/certbot/work \
  --logs-dir /work/certbot/logs 2>&1 | grep -E "Successfully|Certificate is saved|error" || true
check "$WORK/certbot/live/certbot.pki.test/cert.pem"

step "dns-01 and a wildcard with lego (pebble-challtestsrv)"
"$CONTAINER_ENGINE" rm -f "$DNS" >/dev/null 2>&1 || true
"$CONTAINER_ENGINE" run -d --name "$DNS" --network "$NETWORK" "$CHALLTESTSRV_IMAGE" \
  -http01 "" -https01 "" -tlsalpn01 "" -doh "" >/dev/null
dns_ip="$("$CONTAINER_ENGINE" inspect "$DNS" --format \
  '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
[ -n "$dns_ip" ] || fail "no address for the DNS test server"
pki config set acme.dns_resolvers "[\"$dns_ip:8053\"]"
# lego's exec provider: `hook present|cleanup FQDN VALUE` → the management API of challtestsrv.
cat >"$WORK/dns-hook.sh" <<EOF
#!/bin/sh
case "\$1" in
  present) wget -q -O - --post-data "{\"host\":\"\$2\",\"value\":\"\$3\"}" http://$DNS:8055/set-txt ;;
  cleanup) wget -q -O - --post-data "{\"host\":\"\$2\"}" http://$DNS:8055/clear-txt ;;
esac
EOF
chmod 0755 "$WORK/dns-hook.sh"
"$CONTAINER_ENGINE" run --rm --network "$NETWORK" -v "$WORK:/work:Z" \
  -e LEGO_CA_CERTIFICATES=/work/root.pem -e EXEC_PATH=/work/dns-hook.sh \
  -e EXEC_SEQUENCE_INTERVAL=1 "$LEGO_IMAGE" \
  run --server "$SERVER/directory" --accept-tos --email admin@pki.test \
  --domains '*.wild.pki.test' --domains wild.pki.test --dns exec \
  --dns.resolvers "$dns_ip:8053" --dns.propagation.wait 1s \
  --path /work/wild --log.format text 2>&1 | grep -E "validated|responded|ERROR"
check "$WORK/wild/certificates/_.wild.pki.test.crt"
openssl x509 -in "$WORK/wild/certificates/_.wild.pki.test.crt" -noout -ext subjectAltName |
  grep -q 'DNS:\*.wild.pki.test' || fail "no wildcard in the certificate"
printf 'OK  wildcard *.wild.pki.test issued through dns-01\n'

step "an IP address in http-01 (RFC 8738)"
"$CONTAINER_ENGINE" rm -f "acme-ip-$PROJECT" >/dev/null 2>&1 || true
"$CONTAINER_ENGINE" run -d --name "acme-ip-$PROJECT" --network "$NETWORK" -v "$WORK:/work:Z" \
  -e LEGO_CA_CERTIFICATES=/work/root.pem --entrypoint sleep "$LEGO_IMAGE" 300 >/dev/null
ip="$("$CONTAINER_ENGINE" inspect "acme-ip-$PROJECT" --format \
  '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
"$CONTAINER_ENGINE" exec "acme-ip-$PROJECT" /lego run --server "$SERVER/directory" --accept-tos \
  --email admin@pki.test --domains "$ip" --http --path /work/ip --log.format text 2>&1 |
  grep -E "validated|responded|ERROR"
"$CONTAINER_ENGINE" rm -f -t 0 "acme-ip-$PROJECT" >/dev/null
check "$WORK/ip/certificates/$ip.crt"
openssl x509 -in "$WORK/ip/certificates/$ip.crt" -noout -ext subjectAltName |
  grep -q "IP Address:$ip" || fail "no IP address in the certificate"
printf 'OK  IP address %s issued through http-01\n' "$ip"

step "manual approval (acme.manual_approval): lego waits for h42pki request approve"
pki config set acme.manual_approval true >/dev/null
lego_run manual manual.pki.test --domains manual.pki.test --http --cert.timeout 120 \
  >"$WORK/manual.log" 2>&1 &
lego_pid=$!
id=""
for _ in $(seq 1 60); do
  id="$(pki request list --status pending | awk '$4 == "acme" {print $1; exit}')"
  [ -n "$id" ] && break
  sleep 1
done
[ -n "$id" ] || fail "no pending ACME request"
pki request list --status pending
sleep 3 # lego is polling the processing order
pki request approve "$id" >/dev/null
wait "$lego_pid" || {
  cat "$WORK/manual.log"
  fail "lego did not get the approved certificate"
}
pki config unset acme.manual_approval >/dev/null
grep -E "validated|responded" "$WORK/manual.log"
check "$WORK/manual/certificates/manual.pki.test.crt"

step "lego certificates revoke, then openssl ocsp"
# The issuing CA: first certificate of the bundle lego wrote next to the certificate.
openssl x509 -in "$WORK/lego/certificates/www.pki.test.issuer.crt" -out "$WORK/issuing.pem"
ocsp_status() { # ocsp_status CERTIFICATE: good, revoked or unknown, verified answer
  local output
  output="$(openssl ocsp -issuer "$WORK/issuing.pem" -cert "$1" -url "$OCSP" \
    -CAfile "$WORK/root.pem" -verify_other "$OUT/chain.pem" -no_nonce 2>&1)" ||
    fail "openssl ocsp: $output"
  grep -q "Response verify OK" <<<"$output" || fail "OCSP answer not verified: $output"
  awk -F': ' '/\.crt: /{print $2; exit}' <<<"$output"
}
expect "$(ocsp_status "$WORK/lego/certificates/www.pki.test.crt")" good "OCSP before revocation"
lego lego www.pki.test certificates revoke --server "$SERVER/directory" --email admin@pki.test \
  --cert.name www.pki.test --reason 4 --keep 2>&1 | grep -iE "revok|ERROR"
expect "$(ocsp_status "$WORK/lego/certificates/www.pki.test.crt")" revoked "OCSP after revokeCert"

step "no private key, no token, no unused nonce in the logs of the container"
logs="$(compose logs issuing 2>&1)"
secrets="$(compose exec -T issuing python3 -c '
import sqlite3
db = sqlite3.connect("/data/h42pki.sqlite3")
for table, column in (("acme_challenge", "token"), ("acme_nonce", "value")):
    for (value,) in db.execute(f"SELECT {column} FROM {table}"):
        print(value)
' </dev/null)"
count=0
while read -r secret; do
  [ -n "$secret" ] || continue
  count=$((count + 1))
  if grep -qF -- "$secret" <<<"$logs"; then fail "a token or a nonce is in the logs"; fi
done <<<"$secrets"
if grep -q "PRIVATE KEY" <<<"$logs"; then fail "a private key is in the logs"; fi
printf 'OK  none of %d tokens and nonces, no private key in %d lines of logs\n' "$count" \
  "$(wc -l <<<"$logs")"
pki acme account list

printf '\nacme-test: all checks passed\n'
