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
- ✅ statut `expired` **persistant** (B34) et CDP / OCSP dans les certificats → faits en phase 3 ;
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
- ✅ purge des anciennes clés et anciens certificats `service_tls` (B44) → faite en phase 3 ;
- ✅ CDP / OCSP dans les certificats, attendus par les clients Windows (B41) → faits en phase 3.

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

**Reporté en phase 3** (✅ fait) : contrôle par la fille de son propre statut (OCSP de la mère), effet visible de la
révocation d'une AC fille, publication d'une racine arrêtée (décision ouverte n° 1, close par l'ADR-0017). **Non
planifié** : NameConstraints, mode `external`, renouvellement d'une AC fille.

## Phase 3 — Révocation : CRL + OCSP — ✅ terminée (2026-11-26)

Décisions : ADR-0017. Réalisée en deux étapes.

- ✅ **Options de l'AC** : `h42pki authority init --crl --ocsp` (racine et subordonnée), désactivées par défaut,
  immuables (`Authority.crl_enabled`, `ocsp_enabled`) ; une AC avec révocation refuse le mode « à vide » (au démarrage
  et à `authority init`), ce qui clôt la décision ouverte n° 1.
- ✅ **Extensions** : CDP `{public_base_url}/crl/{name}.crl` et AIA OCSP `{public_base_url}/ocsp`, non critiques, dans
  tous les certificats émis (AC filles et `service_tls` compris), jamais sur la racine (B41).
- ✅ **`RevocationService`** : motifs RFC 5280 sans suspension, 409 (déjà révoqué, AC locale, `service_tls`, non émis
  ici), audit, CRL régénérée, cache OCSP invalidé ; révocation d'une AC fille par le même chemin. API
  `POST /api/v1/certificates/{id}/revoke`, CLI `h42pki certificate revoke`.
- ✅ **CRL** : `core/crl.py`, `CrlService`, table `Crl`, une CRL complète par AC (pas de delta), `GET /crl/{name}.crl`
  (HTTP et HTTPS, cache, jamais de signature à la demande), `GET /api/v1/crl`, `h42pki crl show|generate`, réglages
  `crl.validity_hours` / `crl.regenerate_before_hours`, première CRL dès l'activation.
- ✅ **Tâches** : CRL (15 min), statut `expired` en base (1 h, B34), purge `service_tls` (1 jour, B44), contrôle
  auprès de la mère (1 jour) ; toutes au démarrage et en mode « à vide ».
- ✅ **OCSP** : `core/ocsp.py`, `OcspService` / `OcspCache`, `POST /ocsp` et `GET /ocsp/{requête}`, signature par l'AC,
  nonce, cache des réponses sans nonce, en-têtes RFC 5019, `ocsp.response_validity_hours`.
- ✅ **Fille** : contrôle de son statut auprès de l'OCSP de sa mère (`h42pki authority check-parent`), `revoked` →
  plus aucune émission (B50).
- ✅ **`/health`** : CRL, OCSP, dernier contrôle auprès de la mère.
- ✅ Tests de processus sous Linux réel (B42), `uv` fonctionnel (B43).

**Fait quand** : scénarios interop CRL/OCSP de `docs/testing.md` §5 passent.

> État au 2026-11-26 : vérifié par les tests (1026, plus 10 d'interop) et sur Debian 13 / Podman 5.4.2 rootless /
> podman-compose 1.3.0 : `deploy/bootstrap.sh --fresh` puis `deploy/revocation-test.sh` (CRL et OCSP vérifiés par
> `openssl`, émettrice révoquée par l'intermédiaire puis émission refusée) ; mode « à vide » accepté sans révocation et
> refusé avec, en conteneur.

**Non retenu** (ADR-0017) : CRL delta, répondeur OCSP délégué, suspension, miroir de la CRL d'une racine arrêtée.
**Reporté** : OCSP stapling ; répondeur délégué si la clé passe sur PKCS#11 (phase 7) ; limitation des requêtes OCSP
avec nonce (B54).

## Phase 4 — EST — ✅ terminée (2026-11-27)

Décisions : ADR-0018. Réalisée en deux étapes.

- ✅ **Désactivé par défaut** : `est.enabled` (404 sur toutes les routes), `est.default_profile`,
  `est.retry_after_seconds` (niveau `hot`). Même principe à venir pour SCEP et ACME.
- ✅ **Comptes** `EnrollmentCredential` (HTTP Basic, scrypt, sans restriction de profil) : API
  `/api/v1/est/accounts` et `h42pki est account …`.
- ✅ **`cacerts`, `simpleenroll`** : label = profil ; approbation du profil, `202` + `Retry-After`, relance retrouvée
  par (identité, CSR, opération), idempotence ; erreurs en texte brut.
- ✅ **Certificat client** lu dans TLS ou via un proxy de confiance, revérifié par l'application (B45).
- ✅ **`simplereenroll`** (certificat seul, même sujet et SAN), **`csrattrs`**, **`serverkeygen`** (clé générée à
  l'émission, remise une fois, copie chiffrée supprimable : `DELETE /api/v1/certificates/{id}/private-key`,
  `h42pki certificate delete-key`).
- ✅ `deploy/est-test.sh` (curl, openssl, et `estclient` de `github.com/globalsign/est`).

**Fait quand** : `deploy/bootstrap.sh --fresh` puis `deploy/est-test.sh` réussissent.

> État au 2026-11-27 : vérifié par les tests (1142, plus 10 d'interop) et sur Debian 13 / Podman 5.4.2 rootless /
> podman-compose 1.3.0, `estclient` v1.0.6 compris (`cacerts`, `enroll`, `csrattrs`, `reenroll` en mTLS,
> `serverkeygen`) ; aucun mot de passe ni clé privée dans les journaux du conteneur.

**Hors périmètre** : `fullcmc` (501), *channel binding* `tls-unique`, `ChangeSubjectName`, restriction des profils par
compte, relecture des clés conservées, révocation automatique au réenrôlement. **Reporté** : limitation des essais
de mot de passe (B56).

## Phase 5 — SCEP

- **Désactivé par défaut** (`scep.enabled`, 404 sur toutes les routes), comme EST (ADR-0018).
- Spike `core/cms.py` (asn1crypto + cryptography) avec aller-retour testé **avant** les endpoints.
- Certificat RA, `GetCACaps`, `GetCACert`, `PKIOperation` (PKCSReq, RenewalReq, CertPoll, GetCert, GetCRL), challenges.

**Fait quand** : `sscep enroll` obtient un certificat dans le compose d'interop.

## Phase 6 — ACME

- **Désactivé par défaut** (`acme.enabled`, 404 sur toutes les routes), comme EST (ADR-0018).
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

1. ~~Publication CRL/certificat d'une racine arrêtée~~ → une AC avec CRL ou OCSP ne tourne pas à vide ; une racine
   hors ligne se crée sans révocation (ADR-0017, 2026-11-26).
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
