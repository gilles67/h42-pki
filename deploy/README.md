# Example deployment

Three containers of the same image form a hierarchy: `root` → `intermediate` → `issuing`.
There is no reverse proxy: each container serves HTTP and HTTPS by itself, and its CA issues the
certificate of its own HTTPS server.

> [!WARNING]
> Example only. The admin API has **no authentication** yet
> ([ADR-0008](../docs/adr/0008-api-admin-sans-authentification.md)): anyone who reaches the HTTPS
> port can create an invitation, hence a CA. Ports are published on `127.0.0.1` only; keep it so.
> The passphrases in `secrets/EXAMPLE-*.txt` are public.

## Run it

Needs **Podman** (rootless is fine) with **podman-compose ≥ 1.3**, `curl` and `openssl`. Podman is the reference
container engine of the project ([ADR-0016](../docs/adr/0016-podman-moteur-de-reference.md)); Docker with Compose
v2 works too.

```bash
deploy/bootstrap.sh                          # add --fresh to delete a previous run, volumes included
CONTAINER_ENGINE=docker deploy/bootstrap.sh  # same with Docker and Docker Compose v2
```

The script:

1. starts the three containers and creates the root CA (`--path-length 2`);
2. for each child, creates a single-use invitation on the parent and enrols the child with it;
3. issues a `tls_server` certificate with the issuing CA;
4. runs `openssl verify -CAfile root.pem -untrusted chain.pem leaf.pem`.

Every CA is created with `--crl --ocsp` and a public base URL `http://<service>.pki.test:8080`
([ADR-0017](../docs/adr/0017-revocation.md)); `compose.yaml` gives each container that name as a network alias, so
that a child reaches the OCSP of its parent.

## EST

```bash
deploy/est-test.sh                 # after bootstrap.sh, on the issuing CA
ESTCLIENT=/path/to/estclient deploy/est-test.sh   # also with estclient (github.com/globalsign/est)
```

EST is disabled by default (ADR-0018): the script checks that every EST route answers 404, runs
`h42pki config set est.enabled true`, creates an account (the generated password stays in memory, curl reads it on
standard input), then `cacerts`, `simpleenroll` (Basic, then a manual approval with a retry), `simplereenroll` with
the client certificate obtained, `serverkeygen` (the key received matches the certificate, delivered once, stored
copy deleted) and `csrattrs`, and checks that the container logs hold no password nor private key.

`estclient` v1.0.6 builds in a container (its PKCS#11 dependency needs cgo):

```bash
podman run --rm -e CGO_ENABLED=1 -e GOBIN=/out -v "$PWD":/out:Z docker.io/library/golang:1.23 \
  go install github.com/globalsign/est/cmd/estclient@v1.0.6
```

## SCEP

```bash
deploy/scep-test.sh                # after bootstrap.sh, on the issuing CA
```

SCEP is disabled by default ([ADR-0019](../docs/adr/0019-scep.md)): the script checks that the SCEP routes answer 404,
runs `h42pki config set scep.enabled true`, waits for the RA certificate, then runs `sscep` in a container on the
network of the hierarchy, over plain HTTP: `getcaps`, `getca`, `enroll` with a single-use challenge (then the same
challenge refused), a reusable challenge twice, the manual `ocsp_signer` profile (PENDING, `h42pki request approve`,
SUCCESS by polling), renewal signed by the certificate obtained, `getcert` and `getcrl`; it checks that the container
logs hold no challenge nor private key. Challenges only go into private openssl configuration files, never on a
command line.

sscep is no longer packaged by Debian: the script builds `localhost/h42-sscep:0.10.0` from
[`sscep/Containerfile`](sscep/Containerfile) (a pinned release of github.com/certnanny/sscep) when the image is
missing; `SSCEP_IMAGE=…` selects another one. With sscep, `-c` must be the RA certificate (sscep verifies the answer
with it): `sscep enroll -c ra.crt -e ra.crt …`.

Run `est-test.sh` and `scep-test.sh` before `revocation-test.sh`, which revokes the issuing CA.

## Revocation

```bash
deploy/revocation-test.sh          # after bootstrap.sh, same output directory (deploy/out by default)
```

It issues two certificates from the issuing CA, revokes one, and checks with `openssl`: the CRL (`openssl crl
-text`, `openssl verify -crl_check` and `-crl_check_all`), OCSP (`openssl ocsp`, good then revoked, with and without
`-no_nonce`). Then the intermediate revokes the issuing CA: `h42pki authority check-parent` on the issuing CA sees
it, issuance is refused (503), the chain fails with every CRL, and the issuing CA still answers OCSP. The hierarchy
ends with a revoked issuing CA: run `deploy/bootstrap.sh --fresh` before using it again.

Results are in `deploy/out/` (ignored by git). `podman-compose -f deploy/compose.yaml down
--volumes` removes everything, CA keys included.

| Service | HTTP | HTTPS |
|---|---|---|
| `root` | 127.0.0.1:18081 | 127.0.0.1:18441 |
| `intermediate` | 127.0.0.1:18082 | 127.0.0.1:18442 |
| `issuing` | 127.0.0.1:18083 | 127.0.0.1:18443 |

Ports can be changed with `ROOT_HTTP_PORT`, `ROOT_HTTPS_PORT`, and so on.

## Enrol a child by hand

With manual approval (the default). Run the commands from `deploy/`, where `compose.yaml` is; `CHILD` stands for the
service of a container that has no CA yet:

```bash
# On the parent: the token is on standard output, shown this one time.
podman-compose exec root h42pki federation invite --label lab --path-length 0

# On the child: paste the token on standard input (it stays out of the shell history).
podman-compose exec CHILD h42pki authority init --name lab --common-name "Lab CA" \
  --parent-url https://root:8443 --parent-fingerprint <sha256> --token -

# On the parent, meanwhile:
podman-compose exec root h42pki request list --status pending
podman-compose exec root h42pki request approve <id>
```

If the child stopped waiting: `h42pki authority init --resume --token -`. To give up:
`h42pki authority abandon`.

The host of `--parent-url` must be in `H42_PKI_SERVER_HOSTNAME` or `H42_PKI_SERVER_ALT_NAMES` of
the parent.

## With Podman

- Build the image in the **Docker format**: `podman build --format docker`, or `BUILDAH_FORMAT=docker` for
  podman-compose (the scripts set it). In the default OCI format, Podman drops the `HEALTHCHECK` and containers never
  report `healthy`.
- Rootless containers: run `loginctl enable-linger $USER` once, so that containers and their health checks survive
  the end of your session.
- Rootless Podman cannot publish host ports below 1024 by default; the examples use 18081-18083 / 18441-18443.
- podman-compose has no `up --wait`: `bootstrap.sh` waits for each container with `h42pki healthcheck` (120 s at
  most, `START_TIMEOUT` to change it), and shows its logs on failure.
- podman-compose always keeps standard input open in `exec`: in a script, add `</dev/null` to the commands that must
  not read it.
- Containers reach each other by service name (`https://root:8443`) through the network DNS (netavark and
  aardvark-dns, installed with Podman on Debian).
- Validated on 2026-11-25 with Debian 13, Podman 5.4.2 (rootless) and podman-compose 1.3.0; revocation scenario
  validated on 2026-11-26 with the same versions (network aliases included).

## Other files

- `smoke-test.sh`: builds the image and checks one container alone (health, HTTPS, idle mode). Podman by default,
  `CONTAINER_ENGINE=docker` for Docker.
- `engine.sh`: choice of the engine, sourced by both scripts.

