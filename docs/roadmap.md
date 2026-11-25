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
> Image et état `healthy` validés le 2026-11-25 sur Debian 13 / Podman 5.4.2 rootless (`deploy/smoke-test.sh`).

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

## Phase 1.1 — Socle d'exploitation — ✅ terminée (2026-11-22)

Décisions du 2026-11-22 (ADR-0011 à 0014, complément de l'ADR-0009), réalisées en deux étapes. La fédération
s'appuiera sur ce socle : la fille joint la mère en HTTPS intégré.

- ✅ **Python 3.13** (ADR-0014) : `requires-python`, `.python-version`, ruff et mypy, image `python:3.13-slim`, CI
  (lint en 3.13, tests en 3.13 et 3.14), `uv.lock` régénéré. Granian retiré, Uvicorn épinglé `>=0.54,<0.55`.
- ✅ **Variables d'environnement** (ADR-0011) : liste fermée, validée par `core/hostnames.py` (FQDN, noms
  supplémentaires DNS ou IP, CIDR) et par `Settings` (ports, listeners) ; `H42_PKI_SERVER_HOSTNAME` exigé par
  `h42pki serve` seulement.
- ✅ **Configuration en base** (ADR-0011) : tables `Setting` et `SettingsRevision`, schéma `RuntimeSettings`
  (13 réglages de la phase 1.1, niveau `hot` / `listener` / `process` déclaré pour chacun), `h42pki config
  show|get|set|unset` (audit `config.set` / `config.unset`, message d'effet), `GET /api/v1/config` (405 en
  écriture). Le serveur relit la révision toutes les 5 s.
- ✅ **Profils désactivables** (ADR-0009) : `issuance.disabled_profiles`, `h42pki profile disable|enable`, champ
  `enabled` ; soumission refusée (422), approbation refusée (409), rejet possible.
- ✅ **Lanceur maison** (ADR-0012) : `server/` (listeners Uvicorn HTTP et HTTPS, protocole qui pose
  `h42pki.listener` et l'extension ASGI `tls`, `SSLContext` TLS 1.2+ et mTLS facultatif, démarrage différé,
  rechargement à chaud, redémarrage d'un seul listener, mode « à vide »), routes publiques seules en HTTP (404
  `problem+json` sinon), `Client-Cert` seulement depuis `H42_PKI_TRUSTED_PROXIES`, avertissements au démarrage.
- ✅ **Certificat HTTPS intégré** (ADR-0013) : profil interne `service_tls`, `PrivateKey.purpose`, canal `system`,
  émission par `IssuanceService` dès que l'AC est active, réémission si les noms changent, tâche
  `tasks/tls_service.py` (renouvellement à J-15, nouvelle tentative le lendemain, rechargement à chaud).
- ✅ **Santé** : `h42pki healthcheck` (base + battement du lanceur, sans port) utilisé par le `HEALTHCHECK` Docker ;
  `GET /health` enrichi (base, battement, AC, listeners, état du HTTPS, expiration et renouvellement du certificat).
- ✅ **Tests** : scénarios U1 à U14 de `docs/spikes/2026-11-tls-launcher.md` sur le vrai lanceur
  (`tests/integration/server/`, vrais sockets), en plus des tests des réglages, de la CLI et de l'API.

**Fait quand** : dans un conteneur, avec une base vide et `H42_PKI_SERVER_HOSTNAME` défini, `h42pki authority init`
ouvre le HTTPS sans redémarrage ; `curl --cacert root.pem https://<hostname>:8443/health` répond ; l'API
d'administration ne répond plus en HTTP ; un certificat client présenté est visible de l'application ; le
renouvellement forcé du certificat HTTPS est pris à chaud ; le conteneur est `healthy` avec HTTP et HTTPS
désactivés.

> État au 2026-11-22 : tous ces points sont vérifiés par les tests et par un scénario manuel **hors conteneur**
> (Windows). **Validé en conteneur le 2026-11-25** sur Debian 13 / Podman 5.4.2 rootless : image, état `healthy`
> avec et sans listener, HTTPS ouvert par `authority init` (`deploy/smoke-test.sh`).

**Reporté** :
- passage à chaud du mTLS facultatif à obligatoire et ajout d'une ancre de confiance client **sans** redémarrer le
  listener (aujourd'hui `server.client_trust_anchors` est de niveau `listener`) ;
- vérification de la chaîne d'un certificat client reçu par `Client-Cert` → phase 4 (EST, B45) ;
- purge des anciennes clés et anciens certificats `service_tls` → tâches de purge, phase 3 (B44) ;
- CDP / OCSP dans les certificats, attendus par les clients Windows (B41) → phase 3.

## Phase 2 — Hiérarchie (fédération) — ✅ terminée (2026-11-25)

- ✅ **Mère** : invitations à usage unique (`FederationInvitation`), `enroll` par demande `sub_ca` sur le canal
  `federation`, approbation par invitation, AC filles et leur révocation, par l'API et la CLI
  (`h42pki federation …`, `h42pki request …`). ADR-0015.
- ✅ **Fille** : `h42pki authority init --parent-url … --parent-fingerprint … --token -`, épinglage, contrôle de la
  chaîne et du certificat reçu, `--resume`, `h42pki authority abandon` ; jeton jamais stocké.
- ✅ Chaîne complète dans `/ca/chain.pem` et `chain.pem` des certificats ; mode et mère dans `GET /api/v1/authority`.
- ✅ `deploy/compose.yaml`, `deploy/bootstrap.sh`, `deploy/smoke-test.sh`.
- ✅ Nom d'AC contrôlé à toute création (B37).

**Fait quand** : la hiérarchie à trois niveaux se monte par `podman-compose up` + deux invitations, et un certificat
de l'émettrice se vérifie jusqu'à la racine.

> État au 2026-11-25 : vérifié par les tests (mères réelles en sous-processus, HTTPS) et en exécutant `bootstrap.sh` avec
> un substitut de `docker` qui lance des `h42pki serve` locaux. **Validé en conteneur le 2026-11-25** sur
> Debian 13 / Podman 5.4.2 / podman-compose 1.3.0 : `deploy/bootstrap.sh --fresh` aboutit (`leaf.pem: OK`), une fois
> `up --wait` remplacé par une attente explicite (correctif de script à faire, ADR-0016).

**Reporté en phase 3** : contrôle par la fille de son propre statut (OCSP de la mère), effet visible de la révocation
d'une AC fille, publication d'une racine arrêtée (décision ouverte n° 1). **Non planifié** : NameConstraints, mode
`external`, renouvellement d'une AC fille.

## Phase 3 — Révocation : CRL + OCSP

- `RevocationService`, raisons RFC 5280, suspension/levée.
- Contrôle quotidien par une AC fille de son propre statut auprès de sa mère (reporté de la phase 2).
- CDP et AIA OCSP ajoutés aux certificats émis (absents jusque-là, lot 5a).
- `core/crl.py`, `CrlService`, tâche périodique, endpoints `/crl/*` avec cache HTTP.
- `core/ocsp.py`, répondeur délégué auto-renouvelé, endpoints POST/GET, nonce, cache.

**Fait quand** : scénarios interop CRL/OCSP de `docs/testing.md` §5 passent.

## Phase 4 — EST

- Endpoints `cacerts`, `simpleenroll`, `simplereenroll`, `csrattrs` ; `serverkeygen` en option.
- Authentification Basic ou certificat client lu dans la connexion TLS du lanceur (mTLS facultatif, ADR-0012) ;
  certificat via proxy de confiance (`Client-Cert`) en option.

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
4. ~~Approbation des AC filles~~ → choisie par invitation, manuelle par défaut (ADR-0015, 2026-11-25).
5. Interface web d'administration : hors périmètre v1, mais **prévue** : `GET /health` et `GET /api/v1/config`
   sont pensés pour elle (2026-11-22).
6. ~~Casse des champs JSON~~ → **snake_case** (ADR-0006, 2026-11-21).
7. ~~Migrations~~ → aucune avant la première release (ADR-0007, 2026-11-21).
8. ~~Authentification de l'API admin~~ → aucune avant la première release (ADR-0008, 2026-11-21).
9. ~~Fichier de configuration~~ → configuration en base, liste fermée de variables d'environnement (ADR-0011,
   2026-11-22).
10. ~~Reverse-proxy obligatoire~~ → HTTP et HTTPS intégrés, proxy facultatif (ADR-0012, remplace ADR-0005,
    2026-11-22).
11. ~~Certificat du serveur HTTPS~~ → émis par l'AC locale, 47 jours, renouvelé à J-15, y compris pour une racine
    ou une intermédiaire (ADR-0013, 2026-11-22).
12. ~~Rôle des AC~~ → aucun profil réservé à un rang ; profils désactivables par AC (ADR-0009, 2026-11-22).
13. ~~Version de Python~~ → 3.13 (ADR-0014, 2026-11-22).
