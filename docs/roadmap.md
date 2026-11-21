# Feuille de route

Chaque phase se termine par : tests verts, `ruff`/`mypy` propres, documentation mise à jour.
Les numéros `B…` renvoient à `docs/etat-des-lieux.md`.

## Phase 0 — Assainissement (prérequis à tout le reste)

- ✅ Suppression des expérimentations `certold.py`, `certdb.py`, `certapp.py`, `main.py`, `cli.py` et de la
  dépendance `requests` (2026-11-21) ; `uv.lock` régénéré.
- ✅ `.gitattributes` (fins de ligne LF) et renormalisation du dépôt.
- ✅ Layout paquet `src/h42pki/` installable (hatchling), script `h42pki` (Typer : `version`, `serve`) déclaré dans
  `pyproject.toml` (B20). Code legacy déplacé dans `h42pki/ca/` et `h42pki/api/admin.py`, logique inchangée.
- ✅ `pyproject.toml` seule source de dépendances ; `src/requirements.txt` supprimé ; extra `pkcs11` (B19).
  `src/Makefile` (paquets apt OpenSC/pcscd/libccid) supprimé aussi : ces paquets reviendront avec l'image
  `-pkcs11` en phase 7.
- ✅ Groupe `dev`, configuration pytest / ruff / mypy (`docs/testing.md` §2) ; `tests/conftest.py` de base
  (fixtures `settings`, `client` avec lifespan), tests `/health`, config et fumée du parcours legacy.
- ✅ Supprimer `src/test.py` (B5).
- ✅ `config.py` avec `pydantic-settings` + `*_FILE` + secrets Docker (B4 partiel, B23) ; `create_app()` + lifespan
  Tortoise (B22 partiel : migrations avant la première release, ADR-0007) ; `GET /health`.
- ✅ Nouveau `Dockerfile` (`python:3.12-slim`, uv, non-root, healthcheck, Granian) et `Makefile` cohérent (B16).
- ✅ CI GitHub Actions (lint + tests, Python 3.12 / 3.13).

**Fait quand** : `uv run pytest` passe (même avec peu de tests), l'image se construit et `/health` répond.

> État au lot 1 (2026-11-21) : `pytest`, `ruff`, `mypy` verts et `/health` vérifié sous uvicorn et Granian.
> **La construction de l'image Docker et son état `healthy` restent à valider** (Docker indisponible sur le poste
> de développement) : `docker build -t h42-pki:dev .` puis `docker run -e H42_PKI_CA_PASSPHRASE=… h42-pki:dev`.

## Phase 1 — Noyau d'AC

- `core/` : noms (sujet RFC 4514 ↔ JSON, champs optionnels — B11), extensions (B9, B10), profils, numéros de série (B1),
  construction de certificat avec AKI/SKI/CDP/AIA (B12), validation de CSR, algorithmes RSA/EC/Ed25519 (B8).
  Renommage de tous les champs en snake_case (ADR-0006).
- `keystore/software.py` : PKCS#8 chiffré (B18), interface `KeyBackend` complète.
- Modèles Tortoise cibles (ARCHITECTURE §4) avec `ForeignKeyField` (B13, B14, B21), sans migration (ADR-0007).
- `IssuanceService` (chemin d'émission unique, sans recopie d'extensions du CSR — B2), `AuditLog`.
- Profils par défaut fournis : `sub_ca`, `tls_server`, `tls_client`, `ocsp_signer`, `device`.
- API admin `/api/v1` : clés, profils, demandes (approve/reject), certificats (liste, détail, PEM/DER), **sans authentification** (ADR-0008) (B6, B7).
- CLI : `h42pki authority init|status|export`, `h42pki profile list`.
- AIA public : `/ca/{name}.crt|.pem`, `/ca/chain.pem`.

**Fait quand** : une AC racine s'initialise par CLI, émet un certificat serveur via l'API, vérifiable par
`openssl verify` ; couverture `core/` ≥ 90 %.

## Phase 2 — Hiérarchie (fédération)

- `docs/protocols/federation.md` complet : invitations, `enroll`, approbation, validation de chaîne côté fille,
  vérification périodique du statut de l'AC fille.
- `deploy/compose.yaml` racine + intermédiaire + émettrice.

**Fait quand** : la hiérarchie à trois niveaux se monte par `docker compose up` + deux invitations, et un certificat
de l'émettrice se vérifie jusqu'à la racine.

## Phase 3 — Révocation : CRL + OCSP

- `RevocationService`, raisons RFC 5280, suspension/levée.
- `core/crl.py`, `CrlService`, tâche périodique, endpoints `/crl/*` avec cache HTTP.
- `core/ocsp.py`, répondeur délégué auto-renouvelé, endpoints POST/GET, nonce, cache.

**Fait quand** : scénarios interop CRL/OCSP de `docs/testing.md` §5 passent.

## Phase 4 — EST

- Endpoints `cacerts`, `simpleenroll`, `simplereenroll`, `csrattrs` ; `serverkeygen` en option.
- Authentification Basic + certificat client via proxy de confiance ; Traefik mTLS dans le compose.

## Phase 5 — SCEP

- Spike `core/cms.py` (asn1crypto + cryptography) avec aller-retour testé **avant** les endpoints.
- Certificat RA, `GetCACaps`, `GetCACert`, `PKIOperation` (PKCSReq, RenewalReq, CertPoll, GetCert, GetCRL), challenges.

**Fait quand** : `sscep enroll` obtient un certificat dans le compose d'interop.

## Phase 6 — ACME

- 6a : choix lib JWS, nonces, comptes, commandes, autorisations, http-01, dns-01, finalize, certificat, revokeCert.
- 6b : tls-alpn-01, keyChange, EAB, ARI (RFC 9773).

**Fait quand** : `lego` obtient puis révoque un certificat en http-01 et en dns-01.

## Phase 7 — Durcissement

- Spike puis backend **PKCS#11** (carte à puce / HSM via OpenSC) — cf. ADR-0004 ; image `-pkcs11` (paquets apt
  `opensc`, `opensc-pkcs11`, `pcscd`, `libccid` de l'ancien `src/Makefile`, `PYKCS11LIB`, extra `pkcs11`).
- PostgreSQL validé en CI ; `/metrics` Prometheus ; logs JSON structurés.
- Rollover de clé d'AC (`GetNextCACert`, coexistence des générations).
- Runbook d'exploitation : sauvegarde/restauration, perte de passphrase, compromission de clé.

## Jalon « Première release »

Prérequis bloquants avant de taguer une version déployable avec des données à conserver :

- Migrations de base en place (ADR-0007) : choix de l'outil, migration initiale, `generate_schemas` réservé aux
  tests, test de migration en CI.
- Authentification de l'API d'administration (ADR-0008) : jetons Bearer hachés en base, portées
  `admin` / `operator` / `read`, `h42pki token create`, identité réelle dans l'`AuditLog`.
- Runbook de sauvegarde/restauration (cf. phase 7).

## Décisions ouvertes (à trancher par le mainteneur)

1. Publication CRL/certificat d'une racine arrêtée (miroir sur les filles ?) — federation.md §6.
2. ~~Nom du paquet Python~~ → `h42pki` (adopté au lot 1).
3. Base de production visée : SQLite suffit-elle, ou PostgreSQL dès la phase 1 ?
4. Approbation manuelle par défaut pour les AC filles, ou auto-approbation avec invitation ?
5. Interface web d'administration : hors périmètre v1 confirmé ?
6. ~~Casse des champs JSON~~ → **snake_case** (ADR-0006, 2026-11-21).
7. ~~Migrations~~ → aucune avant la première release (ADR-0007, 2026-11-21).
8. ~~Authentification de l'API admin~~ → aucune avant la première release (ADR-0008, 2026-11-21).
