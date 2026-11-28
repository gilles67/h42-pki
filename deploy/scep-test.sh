#!/usr/bin/env bash
# SCEP (RFC 8894, ADR-0019) on the issuing CA of the example hierarchy, after deploy/bootstrap.sh,
# with sscep (built from its sources by deploy/sscep/Containerfile, in a container on the network
# of the hierarchy, over plain HTTP as SCEP devices do):
#   1. every SCEP route answers 404 until `h42pki config set scep.enabled true`, then the RA;
#   2. getcaps, getca;
#   3. enroll with a single-use challenge, then the same challenge refused;
#   4. enroll twice with a reusable challenge;
#   5. a profile with manual approval: PENDING, `h42pki request approve`, SUCCESS by polling;
#   6. renewal (sscep sends a PKCSReq signed by the certificate obtained, no challenge); getcrl (GetCert is covered by the tests:
#      sscep cannot pass a 159-bit serial number);
#   7. no challenge nor private key in the logs of the container.
#
# Usage: deploy/scep-test.sh [OUTPUT_DIRECTORY]   (the directory given to bootstrap.sh)
# Challenges never appear on a command line: they go into a private openssl configuration file.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=deploy/engine.sh
. "$HERE/engine.sh"
need_compose
need curl "install curl"
need openssl "install openssl"
OUT="$(cd "${1:-$HERE/out}" && pwd)"
ISSUING_HTTP_PORT="${ISSUING_HTTP_PORT:-18083}"
PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$HERE")}"
NETWORK="${PROJECT}_pki"
SSCEP_IMAGE="${SSCEP_IMAGE:-localhost/h42-sscep:0.10.0}"
URL="http://issuing:8080/scep"
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

WORK="$OUT/scep"
rm -rf "$WORK"
mkdir -p "$WORK"
chmod 0700 "$WORK"

sscep() { # sscep ARGS...: in a container on the network of the hierarchy, files in /work
  "$CONTAINER_ENGINE" run --rm --network "$NETWORK" -v "$WORK:/work:Z" -w /work "$SSCEP_IMAGE" "$@"
}

request() { # request NAME CN [CHALLENGE]: RSA key NAME.key, CSR NAME.csr (challenge in a 0600 file)
  local name="$1" cn="$2" secret="${3:-}"
  (
    umask 077
    {
      printf '[req]\nprompt = no\ndistinguished_name = dn\n'
      [ -n "$secret" ] && printf 'attributes = attributes\n[attributes]\nchallengePassword = %s\n' "$secret"
      printf '[dn]\nCN = %s\n' "$cn"
    } >"$WORK/$name.cnf"
  )
  openssl req -new -newkey rsa:2048 -nodes -keyout "$WORK/$name.key" -out "$WORK/$name.csr" \
    -config "$WORK/$name.cnf" 2>/dev/null
  rm -f "$WORK/$name.cnf"
}

challenge() { # challenge [create options]: a new challenge, printed (kept in shell variables only)
  pki scep challenge create "$@" 2>/dev/null
}

enroll() { # enroll NAME PROFILE [sscep options]: exit status of sscep enroll
  local name="$1" profile="$2"
  shift 2
  sscep enroll -u "$URL/$profile" -c ra.crt -e ra.crt -k "$name.key" -r "$name.csr" \
    -l "$name.crt" -E aes256 -S sha256 "$@"
}

if [ -z "$("$CONTAINER_ENGINE" images -q "$SSCEP_IMAGE" 2>/dev/null)" ]; then
  step "build sscep (deploy/sscep/Containerfile)"
  "$CONTAINER_ENGINE" build "${BUILD_OPTIONS[@]}" -t "$SSCEP_IMAGE" sscep
fi

step "SCEP is disabled by default"
pki config unset scep.enabled >/dev/null
code="$(curl -s -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:$ISSUING_HTTP_PORT/scep/tls_client?operation=GetCACaps")"
expect "$code" 404 "GetCACaps before scep.enabled"

step "enable SCEP: the server issues its RA certificate"
pki config set scep.enabled true
for _ in $(seq 1 60); do
  code="$(curl -s -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:$ISSUING_HTTP_PORT/scep/tls_client?operation=GetCACert")"
  [ "$code" = 200 ] && break
  sleep 1
done
expect "$code" 200 "GetCACert once the RA exists"

step "getcaps, getca"
sscep getcaps -u "$URL/tls_client"
sscep getca -u "$URL/tls_client" -c ca.crt
# getca writes ca.crt-0, ca.crt-1...: the issuing CA and the RA (keyEncipherment, no keyCertSign).
for file in "$WORK"/ca.crt-*; do
  subject="$(openssl x509 -in "$file" -noout -subject)"
  case "$subject" in
    *"Issuing CA"*) cp "$file" "$WORK/ca.crt" ;;
    *"SCEP RA"*) cp "$file" "$WORK/ra.crt" ;;
  esac
done
[ -s "$WORK/ca.crt" ] && [ -s "$WORK/ra.crt" ] || fail "CA or RA certificate not found by getca"
openssl x509 -in "$WORK/ra.crt" -noout -subject -ext keyUsage

step "enroll with a single-use challenge"
single="$(challenge)"
request single "scep-single.pki.test" "$single"
enroll single tls_client
openssl x509 -in "$WORK/single.crt" -noout -subject -issuer
openssl verify -CAfile "$OUT/root.pem" -untrusted "$OUT/chain.pem" "$WORK/single.crt"
request reuse "scep-reuse.pki.test" "$single"
if enroll reuse tls_client; then fail "a used challenge was accepted again"; fi
printf 'OK  the single-use challenge is refused the second time\n'

step "enroll twice with a reusable challenge"
fleet="$(challenge --reusable --description "scep-test.sh fleet")"
for name in fleet-a fleet-b; do
  request "$name" "scep-$name.pki.test" "$fleet"
  enroll "$name" tls_client
  openssl x509 -in "$WORK/$name.crt" -noout -subject
done

step "manual approval (ocsp_signer): PENDING, approve, SUCCESS by polling"
manual="$(challenge)"
request manual "SCEP OCSP Responder" "$manual"
enroll manual ocsp_signer -t 2 -T 120 >"$WORK/manual.log" 2>&1 &
sscep_pid=$!
id=""
for _ in $(seq 1 60); do
  id="$(pki request list --status pending | awk '$4 == "scep" {print $1; exit}')"
  [ -n "$id" ] && break
  sleep 1
done
[ -n "$id" ] || fail "no pending SCEP request"
pki request list --status pending
pki request approve "$id" >/dev/null
wait "$sscep_pid" || {
  cat "$WORK/manual.log"
  fail "sscep did not get the approved certificate"
}
grep -iE "pending|issued|status" "$WORK/manual.log" | head -5 || true
openssl x509 -in "$WORK/manual.crt" -noout -subject -ext extendedKeyUsage

step "renewal signed by the certificate obtained (no challenge)"
request renewed "scep-single.pki.test"
enroll renewed tls_client -K single.key -O single.crt
old_serial="$(openssl x509 -in "$WORK/single.crt" -noout -serial)"
new_serial="$(openssl x509 -in "$WORK/renewed.crt" -noout -serial)"
[ "$old_serial" != "$new_serial" ] || fail "renewal: same certificate"
openssl x509 -in "$WORK/renewed.crt" -noout -subject -serial

step "getcrl"
sscep getcrl -u "$URL/tls_client" -c ra.crt -e ra.crt -k single.key -l single.crt -w crl.der
openssl crl -in "$WORK/crl.der" -noout -issuer -lastupdate 2>/dev/null ||
  openssl crl -inform DER -in "$WORK/crl.der" -noout -issuer -lastupdate

step "no challenge nor private key in the logs of the container"
logs="$(compose logs issuing 2>&1)"
for secret in "$single" "$fleet" "$manual"; do
  if grep -qF "${secret#*-}" <<<"$logs"; then fail "a challenge is in the logs"; fi
done
if grep -q "PRIVATE KEY" <<<"$logs"; then fail "a private key is in the logs"; fi
printf 'OK  no challenge, no private key in %d lines of logs\n' "$(wc -l <<<"$logs")"
pki scep challenge list

printf '\nscep-test: all checks passed\n'
