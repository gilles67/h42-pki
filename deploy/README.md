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

Needs Docker with compose v2, `curl` and `openssl`.

```bash
deploy/bootstrap.sh            # add --fresh to delete a previous run, volumes included
```

The script:

1. starts the three containers and creates the root CA (`--path-length 2`);
2. for each child, creates a single-use invitation on the parent and enrols the child with it;
3. issues a `tls_server` certificate with the issuing CA;
4. runs `openssl verify -CAfile root.pem -untrusted chain.pem leaf.pem`.

Results are in `deploy/out/` (ignored by git). `docker compose -f deploy/compose.yaml down
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
docker compose exec root h42pki federation invite --label lab --path-length 0

# On the child: paste the token on standard input (it stays out of the shell history).
docker compose exec -it child h42pki authority init --name lab --common-name "Lab CA" \
  --parent-url https://root:8443 --parent-fingerprint <sha256> --token -

# On the parent, meanwhile:
docker compose exec root h42pki request list --status pending
docker compose exec root h42pki request approve <id>
```

If the child stopped waiting: `h42pki authority init --resume --token -`. To give up:
`h42pki authority abandon`.

The host of `--parent-url` must be in `H42_PKI_SERVER_HOSTNAME` or `H42_PKI_SERVER_ALT_NAMES` of
the parent.

## Other files

- `smoke-test.sh`: builds the image and checks one container alone (health, HTTPS, idle mode).
