#!/usr/bin/env bash
# Revocation on the example hierarchy (ADR-0017), after deploy/bootstrap.sh:
#   1. two TLS certificates from the issuing CA, one revoked through the API;
#   2. CRL: read by openssl, `openssl verify -crl_check` accepts the valid one, refuses the other;
#   3. OCSP: `openssl ocsp` says good then revoked, with and without nonce;
#   4. the intermediate revokes the issuing CA; `authority check-parent` on the issuing CA sees it,
#      which then refuses to issue, while its CRL and OCSP are still served.
# The hierarchy ends with a revoked issuing CA: run `deploy/bootstrap.sh --fresh` before reuse.
#
# Usage: deploy/revocation-test.sh [OUTPUT_DIRECTORY]   (the directory given to bootstrap.sh)
# Needs the engine of bootstrap.sh (podman by default, CONTAINER_ENGINE=docker), curl, openssl.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=deploy/engine.sh
. "$HERE/engine.sh"
need_compose
need curl "install curl"
need openssl "install openssl"
OUT="$(cd "${1:-$HERE/out}" && pwd)"
ROOT_HTTP_PORT="${ROOT_HTTP_PORT:-18081}"
INTERMEDIATE_HTTP_PORT="${INTERMEDIATE_HTTP_PORT:-18082}"
ISSUING_HTTP_PORT="${ISSUING_HTTP_PORT:-18083}"
ISSUING_HTTPS_PORT="${ISSUING_HTTPS_PORT:-18443}"
API="https://127.0.0.1:$ISSUING_HTTPS_PORT"
OCSP="http://127.0.0.1:$ISSUING_HTTP_PORT/ocsp"
cd "$HERE"

compose() { "${COMPOSE[@]}" -f compose.yaml "$@"; }
pki() { compose exec -T "$1" h42pki "${@:2}" </dev/null; }
step() { printf '\n== %s\n' "$*"; }
fail() {
  printf 'FAILED: %s\n' "$*" >&2
  exit 1
}

[ -s "$OUT/root.pem" ] || fail "$OUT/root.pem not found: run deploy/bootstrap.sh first"

request() { # request NAME: JSON request of a TLS server certificate (new key and CSR)
  local name="$1" csr
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$OUT/$name.key" -out "$OUT/$name.csr" -subj "/CN=$name.pki.test" \
    -addext "subjectAltName=DNS:$name.pki.test" 2>/dev/null
  csr="$(awk '{printf "%s\\n", $0}' "$OUT/$name.csr")"
  printf '{"csr_pem": "%s", "profile": "tls_server"}' "$csr"
}

submit() { # submit NAME [CURL OPTIONS]: POST the request to the issuing CA
  local name="$1"
  shift
  request "$name" | curl -sS --cacert "$OUT/root.pem" -H 'content-type: application/json' \
    -d @- "$@" "$API/api/v1/requests"
}

issue() { # issue NAME: a TLS server certificate from the issuing CA; prints its id
  submit "$1" -f | sed -n 's/.*"certificate_id":"\([^"]*\)".*/\1/p'
}

crls() { # the three CRLs, DER and PEM
  local name port
  for name in root intermediate issuing; do
    case "$name" in
      root) port="$ROOT_HTTP_PORT" ;;
      intermediate) port="$INTERMEDIATE_HTTP_PORT" ;;
      issuing) port="$ISSUING_HTTP_PORT" ;;
    esac
    curl -fsS -o "$OUT/$name.crl" "http://127.0.0.1:$port/crl/$name.crl"
    openssl crl -inform DER -in "$OUT/$name.crl" -out "$OUT/$name.crl.pem"
  done
  cat "$OUT/root.crl.pem" "$OUT/intermediate.crl.pem" "$OUT/issuing.crl.pem" >"$OUT/crls.pem"
}

ocsp_status() { # ocsp_status NAME [-no_nonce]: good, revoked or unknown, from `openssl ocsp`
  local name="$1" output
  shift
  output="$(openssl ocsp -issuer "$OUT/issuing.pem" -cert "$OUT/$name.pem" -url "$OCSP" \
    -CAfile "$OUT/root.pem" -verify_other "$OUT/chain.pem" "$@" 2>&1)" ||
    fail "openssl ocsp: $output"
  printf '%s\n' "$output" >&2
  grep -q "Response verify OK" <<<"$output" || fail "OCSP answer not verified"
  sed -n "s|^$OUT/$name.pem: \([a-z]*\)\$|\1|p" <<<"$output"
}

expect() { # expect ACTUAL EXPECTED WHAT
  [ "$1" = "$2" ] || fail "$3: expected $2, got ${1:-nothing}"
  printf 'OK  %s: %s\n' "$3" "$1"
}

step "two certificates from the issuing CA"
pki issuing authority export >"$OUT/issuing.pem"
valid_id="$(issue valid)"
revoked_id="$(issue revoked)"
[ -n "$valid_id" ] && [ -n "$revoked_id" ] || fail "issuance"
for name in valid revoked; do
  id="$valid_id"
  [ "$name" = revoked ] && id="$revoked_id"
  curl -fsS --cacert "$OUT/root.pem" -o "$OUT/$name.pem" "$API/api/v1/certificates/$id.pem"
done
openssl x509 -in "$OUT/valid.pem" -noout -ext crlDistributionPoints,authorityInfoAccess

step "OCSP before the revocation"
expect "$(ocsp_status revoked)" good "OCSP with nonce"
expect "$(ocsp_status revoked -no_nonce)" good "OCSP without nonce"

step "revoke one of them (key_compromise)"
curl -fsS --cacert "$OUT/root.pem" -H 'content-type: application/json' \
  -d '{"reason": "key_compromise"}' "$API/api/v1/certificates/$revoked_id/revoke" >/dev/null

step "CRL of the issuing CA"
crls
openssl crl -inform DER -in "$OUT/issuing.crl" -noout -text
serial="$(openssl x509 -in "$OUT/revoked.pem" -noout -serial | cut -d= -f2)"
openssl crl -inform DER -in "$OUT/issuing.crl" -noout -text | grep -q "Serial Number: $serial" ||
  fail "the revoked serial is not in the CRL"
verify() { # verify NAME [OPTIONS]: openssl verify with the CRLs
  local name="$1"
  shift
  openssl verify -CAfile "$OUT/root.pem" -untrusted "$OUT/chain.pem" -CRLfile "$OUT/crls.pem" \
    "$@" "$OUT/$name.pem" 2>&1
}
verify valid -crl_check || fail "the valid certificate is refused"
if output="$(verify revoked -crl_check)"; then fail "the revoked certificate is accepted"; fi
printf '%s\n' "$output"
grep -q "certificate revoked" <<<"$output" || fail "unexpected verify error"
verify valid -crl_check_all || fail "the valid certificate is refused with every CRL"

step "OCSP after the revocation"
expect "$(ocsp_status revoked)" revoked "OCSP with nonce"
expect "$(ocsp_status revoked -no_nonce)" revoked "OCSP without nonce"
expect "$(ocsp_status valid -no_nonce)" good "OCSP of the valid certificate"

step "the intermediate revokes the issuing CA"
pki issuing authority check-parent
pki intermediate federation revoke-child issuing --reason key_compromise
if pki issuing authority check-parent; then fail "check-parent does not see the revocation"; fi
pki issuing authority status | grep -E '^(Status|Parent check)'
code="$(submit late -o /dev/null -w '%{http_code}')"
expect "$code" 503 "issuance by the revoked issuing CA"
crls
if verify valid -crl_check_all >/dev/null; then fail "a revoked issuing CA is still trusted"; fi
printf 'OK  the valid certificate is now refused with every CRL (issuing CA revoked)\n'
expect "$(ocsp_status valid -no_nonce)" good "OCSP still answered by the revoked issuing CA"

printf '\nrevocation-test: all checks passed\n'
