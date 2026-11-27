#!/usr/bin/env bash
# EST (RFC 7030, ADR-0018) on the issuing CA of the example hierarchy, after deploy/bootstrap.sh:
#   1. every EST route answers 404 until `h42pki config set est.enabled true`;
#   2. cacerts, simpleenroll with HTTP Basic (tls_server), manual approval with a retry
#      (ocsp_signer: 202, `h42pki request approve`, 200);
#   3. simplereenroll with the client certificate obtained (tls_client), same subject and SANs;
#   4. serverkeygen: the key received matches the certificate, its copy can be deleted;
#   5. csrattrs; no password nor private key in the logs of the container.
# With ESTCLIENT=/path/to/estclient (github.com/globalsign/est), a real EST client runs cacerts,
# enroll, csrattrs, reenroll and serverkeygen too.
#
# Usage: deploy/est-test.sh [OUTPUT_DIRECTORY]   (the directory given to bootstrap.sh)
# Needs the engine of bootstrap.sh (podman by default, CONTAINER_ENGINE=docker), curl, openssl and
# python3 (to split the multipart answer of serverkeygen). The EST password only travels through
# pipes: it is never an argument of a command.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=deploy/engine.sh
. "$HERE/engine.sh"
need_compose
need curl "install curl"
need openssl "install openssl"
need python3 "install python3"
OUT="$(cd "${1:-$HERE/out}" && pwd)"
ISSUING_HTTPS_PORT="${ISSUING_HTTPS_PORT:-18443}"
BASE="https://127.0.0.1:$ISSUING_HTTPS_PORT"
EST="$BASE/.well-known/est"
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
WORK="$OUT/est"
rm -rf "$WORK"
mkdir -p "$WORK"
chmod 0700 "$WORK"

# curl with the EST account, the password read from a config on standard input.
basic_curl() { printf 'user = "alice:%s"\n' "$PASSWORD" | curl -K - "$@"; }

csr() { # csr NAME SUBJECT [SAN] [CURVE]: new key and CSR, base64 DER in NAME.b64
  local name="$1" subject="$2" san="${3:-}" curve="${4:-prime256v1}"
  local extra=()
  [ -n "$san" ] && extra=(-addext "subjectAltName=$san")
  openssl req -new -newkey ec -pkeyopt "ec_paramgen_curve:$curve" -nodes \
    -keyout "$WORK/$name.key" -outform DER -out "$WORK/$name.der" -subj "$subject" \
    "${extra[@]}" 2>/dev/null
  base64 "$WORK/$name.der" >"$WORK/$name.b64"
}

post() { # post OPERATION LABEL NAME [CURL OPTIONS]: body NAME.b64, answer NAME.out, prints the status
  local operation="$1" label="$2" name="$3"
  shift 3
  curl -sS --cacert "$OUT/root.pem" -H 'Content-Type: application/pkcs10' \
    --data-binary @"$WORK/$name.b64" -D "$WORK/$name.headers" -o "$WORK/$name.out" \
    -w '%{http_code}' "$@" "$EST/$label/$operation"
}

certificate() { # certificate NAME: NAME.out (base64 PKCS#7 certs-only, one certificate) to NAME.pem
  # Through `openssl x509`: plain PEM, without the subject lines of -print_certs.
  base64 -d "$WORK/$1.out" | openssl pkcs7 -inform DER -print_certs | openssl x509 -out "$WORK/$1.pem"
}

step "EST is disabled by default"
pki config unset est.enabled >/dev/null
for path in cacerts tls_server/cacerts tls_server/simpleenroll tls_server/csrattrs; do
  code="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$OUT/root.pem" "$EST/$path")"
  expect "$code" 404 "GET $path before est.enabled"
done

step "enable EST, create an account (generated password, kept in memory only)"
pki config set est.enabled true
pki est account delete alice >/dev/null 2>&1 || true
PASSWORD="$(pki est account create alice --description "est-test.sh" 2>/dev/null)"
[ "${#PASSWORD}" -eq 24 ] || fail "no generated password"
pki est account show alice

step "cacerts"
curl -fsS --cacert "$OUT/root.pem" -D "$WORK/cacerts.headers" "$EST/tls_server/cacerts" |
  base64 -d | openssl pkcs7 -inform DER -print_certs -out "$WORK/cacerts.pem"
grep -iE '^content-(type|transfer-encoding)' "$WORK/cacerts.headers"
grep '^subject' "$WORK/cacerts.pem"
[ "$(grep -c 'BEGIN CERTIFICATE' "$WORK/cacerts.pem")" -eq 3 ] || fail "cacerts: 3 CAs expected"

step "simpleenroll, HTTP Basic, tls_server (auto-approved)"
csr server "/CN=est.pki.test" "DNS:est.pki.test"
expect "$(basic_curl -sS --cacert "$OUT/root.pem" -H 'Content-Type: application/pkcs10' \
  --data-binary @"$WORK/server.b64" -o "$WORK/server.out" -w '%{http_code}' \
  "$EST/tls_server/simpleenroll")" 200 "simpleenroll"
certificate server
openssl x509 -in "$WORK/server.pem" -noout -subject -issuer -ext subjectAltName
openssl verify -CAfile "$OUT/root.pem" -untrusted "$WORK/cacerts.pem" "$WORK/server.pem"
expect "$(printf 'user = "alice:wrong-password"\n' | curl -K - -s -o /dev/null -w '%{http_code}' \
  --cacert "$OUT/root.pem" -H 'Content-Type: application/pkcs10' \
  --data-binary @"$WORK/server.b64" "$EST/tls_server/simpleenroll")" 401 "wrong password"

step "simpleenroll with manual approval (ocsp_signer)"
csr responder "/CN=EST OCSP Responder"
send_responder() {
  basic_curl -sS --cacert "$OUT/root.pem" -H 'Content-Type: application/pkcs10' \
    --data-binary @"$WORK/responder.b64" -D "$WORK/responder.headers" -o "$WORK/responder.out" \
    -w '%{http_code}' "$EST/ocsp_signer/simpleenroll"
}
expect "$(send_responder)" 202 "first request"
grep -i '^retry-after' "$WORK/responder.headers"
expect "$(send_responder)" 202 "same request again"
pki request list --status pending
id="$(pki request list --status pending | awk '$4 == "est" {print $1; exit}')"
[ -n "$id" ] || fail "no pending EST request"
pki request approve "$id" >/dev/null
expect "$(send_responder)" 200 "after the approval"
certificate responder
openssl x509 -in "$WORK/responder.pem" -noout -subject -ext extendedKeyUsage

step "simplereenroll with the client certificate (tls_client)"
csr device "/CN=device.pki.test" "DNS:device.pki.test"
expect "$(basic_curl -sS --cacert "$OUT/root.pem" -H 'Content-Type: application/pkcs10' \
  --data-binary @"$WORK/device.b64" -o "$WORK/device.out" -w '%{http_code}' \
  "$EST/tls_client/simpleenroll")" 200 "tls_client certificate"
certificate device
csr renewed "/CN=device.pki.test" "DNS:device.pki.test" secp384r1
expect "$(post simplereenroll tls_client renewed --cert "$WORK/device.pem" --key "$WORK/device.key")" \
  200 "simplereenroll (new key)"
certificate renewed
openssl x509 -in "$WORK/renewed.pem" -noout -subject -ext subjectAltName
old_serial="$(openssl x509 -in "$WORK/device.pem" -noout -serial)"
new_serial="$(openssl x509 -in "$WORK/renewed.pem" -noout -serial)"
[ "$old_serial" != "$new_serial" ] || fail "simplereenroll: same certificate"
csr other "/CN=other.pki.test" "DNS:other.pki.test"
expect "$(post simplereenroll tls_client other --cert "$WORK/device.pem" --key "$WORK/device.key")" \
  400 "simplereenroll with another subject"
expect "$(basic_curl -sS -o /dev/null -w '%{http_code}' --cacert "$OUT/root.pem" \
  -H 'Content-Type: application/pkcs10' --data-binary @"$WORK/renewed.b64" \
  "$EST/tls_client/simplereenroll")" 401 "simplereenroll with Basic only"

step "serverkeygen (tls_server)"
csr keygen "/CN=keygen.pki.test" "DNS:keygen.pki.test"
expect "$(basic_curl -sS --cacert "$OUT/root.pem" -H 'Content-Type: application/pkcs10' \
  --data-binary @"$WORK/keygen.b64" -D "$WORK/keygen.headers" -o "$WORK/keygen.out" \
  -w '%{http_code}' "$EST/tls_server/serverkeygen")" 200 "serverkeygen"
grep -i '^content-type' "$WORK/keygen.headers"
python3 -I - "$WORK/keygen.headers" "$WORK/keygen.out" "$WORK" <<'PY'
import sys
from email import message_from_bytes
from pathlib import Path

headers, body, work = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
content_type = next(
    line.split(":", 1)[1].strip()
    for line in headers.read_text().splitlines()
    if line.lower().startswith("content-type:")
)
message = message_from_bytes(f"Content-Type: {content_type}\r\n\r\n".encode() + body.read_bytes())
for part in message.get_payload():
    kind = part.get_content_type()
    target = work / ("keygen-key.der" if kind == "application/pkcs8" else "keygen-certs.der")
    target.write_bytes(part.get_payload(decode=True))
    target.chmod(0o600)
    print(f"part {kind}: {target.name}")
PY
openssl pkcs7 -inform DER -in "$WORK/keygen-certs.der" -print_certs | openssl x509 -out "$WORK/keygen.pem"
key_pub="$(openssl pkey -inform DER -in "$WORK/keygen-key.der" -pubout | openssl sha256)"
cert_pub="$(openssl x509 -in "$WORK/keygen.pem" -noout -pubkey | openssl sha256)"
expect "$key_pub" "$cert_pub" "key received matches the certificate"
own_pub="$(openssl pkey -in "$WORK/keygen.key" -pubout | openssl sha256)"
[ "$own_pub" != "$cert_pub" ] || fail "serverkeygen used the key of the CSR"
expect "$(basic_curl -sS -o /dev/null -w '%{http_code}' --cacert "$OUT/root.pem" \
  -H 'Content-Type: application/pkcs10' --data-binary @"$WORK/keygen.b64" \
  "$EST/tls_server/serverkeygen")" 409 "the key is delivered once"
keygen_id="$(pki certificate list --profile tls_server --limit 5 |
  awk '$3 == "CN=keygen.pki.test" {print $1; exit}')"
[ -n "$keygen_id" ] || fail "serverkeygen certificate not listed"
expect "$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$OUT/root.pem" -X DELETE \
  "$BASE/api/v1/certificates/$keygen_id/private-key")" 204 "stored copy deleted (API)"
if pki certificate delete-key "$keygen_id" >/dev/null 2>&1; then fail "deleted twice"; fi

step "csrattrs"
for label in tls_server tls_client; do
  printf '%s: ' "$label"
  curl -fsS --cacert "$OUT/root.pem" "$EST/$label/csrattrs" | base64 -d |
    openssl asn1parse -inform DER | sed -n 's/.*OBJECT *://p' | paste -sd, -
done

if [ -n "${ESTCLIENT:-}" ]; then
  step "real EST client: estclient (github.com/globalsign/est)"
  # The password goes in a private configuration file, never on the command line.
  (
    umask 077
    printf '{"server": "127.0.0.1:%s", "additional_path_segment": "%s", "username": "alice", "password": "%s"}\n' \
      "$ISSUING_HTTPS_PORT" tls_server "$PASSWORD" >"$WORK/estclient.json"
  )
  "$ESTCLIENT" cacerts -config "$WORK/estclient.json" -explicit "$OUT/root.pem" \
    -out "$WORK/estclient-cacerts.pem"
  printf 'cacerts: %s certificates\n' "$(grep -c 'BEGIN CERTIFICATE' "$WORK/estclient-cacerts.pem")"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 \
    -out "$WORK/estclient.key" 2>/dev/null
  "$ESTCLIENT" csr -key "$WORK/estclient.key" -cn estclient.pki.test \
    -dnsnames estclient.pki.test -out "$WORK/estclient.csr"
  "$ESTCLIENT" enroll -config "$WORK/estclient.json" -explicit "$OUT/root.pem" \
    -key "$WORK/estclient.key" -csr "$WORK/estclient.csr" -out "$WORK/estclient.pem"
  openssl x509 -in "$WORK/estclient.pem" -noout -subject -issuer
  "$ESTCLIENT" csrattrs -config "$WORK/estclient.json" -explicit "$OUT/root.pem"
  # Re-enrolment authenticates with a client certificate: the tls_client one obtained above.
  "$ESTCLIENT" reenroll -server "127.0.0.1:$ISSUING_HTTPS_PORT" -aps tls_client \
    -explicit "$OUT/root.pem" -key "$WORK/renewed.key" -certs "$WORK/renewed.pem" \
    -out "$WORK/estclient-renewed.pem"
  openssl x509 -in "$WORK/estclient-renewed.pem" -noout -subject -serial
  "$ESTCLIENT" serverkeygen -config "$WORK/estclient.json" -explicit "$OUT/root.pem" \
    -cn estclient-keygen.pki.test -dnsnames estclient-keygen.pki.test \
    -key "$WORK/estclient.key" -out "$WORK/estclient-keygen.pem" \
    -keyout "$WORK/estclient-keygen.key"
  openssl x509 -in "$WORK/estclient-keygen.pem" -noout -subject
  expect "$(openssl x509 -in "$WORK/estclient-keygen.pem" -noout -pubkey | openssl sha256)" \
    "$(openssl pkey -in "$WORK/estclient-keygen.key" -pubout | openssl sha256)" \
    "estclient serverkeygen: key and certificate match"
  rm -f "$WORK/estclient.json"
fi

step "no secret in the logs of the container"
logs="$(compose logs issuing 2>&1)"
if grep -qF "$PASSWORD" <<<"$logs"; then fail "the EST password is in the logs"; fi
if grep -q "PRIVATE KEY" <<<"$logs"; then fail "a private key is in the logs"; fi
key_b64="$(base64 -w0 "$WORK/keygen-key.der" | cut -c1-40)"
if grep -qF "$key_b64" <<<"$logs"; then fail "the generated key is in the logs"; fi
printf 'OK  no password, no private key in %d lines of logs\n' "$(wc -l <<<"$logs")"

printf '\nest-test: all checks passed\n'
