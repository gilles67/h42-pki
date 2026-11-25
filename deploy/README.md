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

Results are in `deploy/out/` (ignored by git). `podman-compose -f deploy/compose.yaml down
--volumes` removes everything, CA keys included.

| Service | HTTP | HTTPS |
|---|---|---|
| `root` | 127.0.0.1:18081 | 127.0.0.1:18441 |
| `intermediate` | 127.0.0.1:18082 | 127.0.0.1:18442 |
| `issuing` | 127.0.0.1:18083 | 127.0.0.1:18443 |

Ports can be changed with `ROOT_HTTP_PORT`, `ROOT_HTTPS_PORT`, and so on.

## Enrol a child by hand

With manual approval (the default):

```bash
# On the parent: the token is on standard output, shown this one time.
podman-compose exec root h42pki federation invite --label lab --path-length 0

# On the child: paste the token on standard input (it stays out of the shell history).
podman-compose exec child h42pki authority init --name lab --common-name "Lab CA" \
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
- podman-compose has no `up --wait`: the scripts wait for each container with `h42pki healthcheck`.
- Containers reach each other by service name (`https://root:8443`) through the network DNS (netavark and
  aardvark-dns, installed with Podman on Debian).
- Validated on 2026-11-25 with Debian 13, Podman 5.4.2 (rootless) and podman-compose 1.3.0.

## Other files

- `smoke-test.sh`: builds the image and checks one container alone (health, HTTPS, idle mode). Podman by default,
  `CONTAINER_ENGINE=docker` for Docker.
