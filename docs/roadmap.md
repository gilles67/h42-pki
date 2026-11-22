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

## Phase 1 — Noyau d'AC — ✅ terminée (2026-11-22)

Réalisée en cinq lots (1 à 5b) :
- ✅ `core/` pur et testé : clés RSA/EC/Ed25519 et PKCS#8 DER chiffré (B8, B18), noms (B11, B28), extensions (B9, B10),
  profils, CSR (signature vérifiée, RSA < 2048 et SHA-1 / MD5 refusés — B36), émission avec AKI/SKI, validité bornée
  et ramenée à l'émetteur, `pathLen` décroissant (B12, B17), numéros de série (B1), AIA caIssuers.
- ✅ `keystore/software.py` (protocole `KeyStore`, ADR-0004) ; la passphrase n'est exigée qu'à l'usage d'une clé (B32).
- ✅ Modèles `PrivateKey`, `Authority`, `Profile`, `Certificate`, `CertificateRequest`, `AuditLog` (FK sans cycle,
  stockage DER), sans migration (ADR-0007).
- ✅ `IssuanceService`, seul chemin d'émission (`submit` → `auto_approve` ou `approve` / `reject`), refus audités
  (B35) ; AC racine par `h42pki authority init` (ADR-0010).
- ✅ Profils intégrés en lecture seule : `sub_ca`, `tls_server` (90 / 200 jours, SC-081v3), `tls_client`,
  `ocsp_signer`, `device` (ADR-0009) ; ST et L autorisés sauf pour `ocsp_signer` (B33).
- ✅ API `/api/v1` sans authentification (ADR-0008) : clés, AC locale, profils, demandes, certificats (liste filtrée et
  paginée, détail avec statut effectif — B34, `.pem` / `.crt` / `chain.pem`) ; erreurs `problem+json` déclarées dans
  l'OpenAPI (B29, B30).
- ✅ Publication HTTP `/ca/{name}.crt|.pem` et `/ca/chain.pem` (cache, 304) et AIA caIssuers dans les certificats
  émis quand `public_base_url` est renseignée (lot 5b).
- ✅ CLI : `h42pki authority init|status|export|update`, `h42pki profile list|show`,
  `h42pki certificate list|export`.

**Critère atteint** : une AC racine s'initialise par CLI, émet un certificat serveur via l'API depuis un CSR
`openssl req`, vérifiable par `openssl verify` (avec `root.pem` ou la chaîne de `/ca/chain.pem`) ; couverture de `core/`
≥ 94 % par module.

**Reporté** :
- édition des profils et profils non intégrés (avec l'authentification) ;
- statut `expired` **persistant** (aujourd'hui calculé à la lecture, B34) et CDP / OCSP dans les certificats →
  phase 3 ;
- authentification de l'API d'administration → jalon « Première release » (ADR-0008) ;
- ascendants dans `/ca/chain.pem` → phase 2 (fédération).

## Phase 2 — Hiérarchie (fédération)

- `docs/protocols/federation.md` complet : invitations, `enroll`, approbation, validation de chaîne côté fille,
  vérification périodique du statut de l'AC fille.
- `deploy/compose.yaml` racine + intermédiaire + émettrice.

**Fait quand** : la hiérarchie à trois niveaux se monte par `docker compose up` + deux invitations, et un certificat
de l'émettrice se vérifie jusqu'à la racine.

## Phase 3 — Révocation : CRL + OCSP

- `RevocationService`, raisons RFC 5280, suspension/levée.
- CDP et AIA OCSP ajoutés aux certificats émis (absents jusque-là, lot 5a).
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
- Validité de `tls_server` alignée sur la suite de SC-081v3 : **47 jours par défaut et 100 au maximum**, puis **47 au
  maximum au 15 mars 2029** (aujourd'hui 90 / 200, lot 5a).

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
