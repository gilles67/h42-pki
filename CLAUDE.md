# CLAUDE.md — h42-pki (Home42 PKI)

Guide de travail pour Claude Code sur ce dépôt. À lire en entier avant toute modification.
La conception détaillée est dans `docs/` — ce fichier donne les règles et les repères.

## 1. Le projet en bref

h42-pki est un **serveur d'autorité de certification (AC) conteneurisé**. Un conteneur = **une AC = un niveau**
de hiérarchie. Plusieurs conteneurs identiques se connectent entre eux pour former une hiérarchie
(racine → intermédiaire(s) → AC émettrice(s)).

Chaque niveau fournit :

| Service | Rôle | RFC de référence | Doc |
|---|---|---|---|
| API d'administration | gestion clés, profils, certificats, révocation | — | `docs/ARCHITECTURE.md` §6 |
| Fédération inter-AC | inscription d'une AC fille auprès de son AC mère | — | `docs/protocols/federation.md` |
| AIA | publication du certificat de l'AC et de la chaîne | RFC 5280 §4.2.2.1 | `docs/protocols/crl.md` |
| CRL | listes de révocation (complète + delta optionnelle) | RFC 5280 | `docs/protocols/crl.md` |
| OCSP | statut de révocation en ligne | RFC 6960, RFC 5019, RFC 8954 | `docs/protocols/ocsp.md` |
| EST | enrôlement sur TLS | RFC 7030 | `docs/protocols/est.md` |
| SCEP | enrôlement équipements réseau / MDM | RFC 8894 | `docs/protocols/scep.md` |
| ACME | enrôlement automatisé (type Let's Encrypt) | RFC 8555 (+ RFC 8737, RFC 9773) | `docs/protocols/acme.md` |

Stack : **Python ≥ 3.13 (ADR-0014), FastAPI, Tortoise ORM (async), `cryptography`, Pydantic v2, Typer (CLI), uv**.
Serveur : **Uvicorn 0.54** (épinglé) piloté par un **lanceur maison** (HTTP + HTTPS intégrés, ADR-0012) ; plus de
Granian.

## 2. État actuel du code (important)

**Phases 1 et 1.1 terminées** : outillage, sécurité, modèle de données, API `/api/v1`, AC racine par CLI, profils,
demandes, émission depuis un CSR, publication `/ca/*` et AIA caIssuers, liste des certificats (phase 1) ; Python 3.13,
configuration en base, profils désactivables, lanceur HTTP/HTTPS intégré, certificat HTTPS émis par l'AC locale, santé
(phase 1.1). Le code suit la structure en couches cible ; ce qui n'existe pas encore est marqué « à venir » au §3.
**Prochaine étape : phase 2 (fédération).**

**Décisions du 2026-11-22, en place depuis la phase 1.1** — à respecter :
- **Configuration en base** (ADR-0011) : hors de la base, seulement une **liste fermée** de variables d'environnement
  (`H42_PKI_DATABASE_URL`, `H42_PKI_CA_PASSPHRASE`, `H42_PKI_SERVER_HOSTNAME`, `H42_PKI_SERVER_ALT_NAMES`,
  `H42_PKI_ENVIRONMENT`, `H42_PKI_BIND_ADDRESS`, `H42_PKI_HTTP_ENABLED|PORT`, `H42_PKI_HTTPS_ENABLED|PORT`,
  `H42_PKI_TRUSTED_PROXIES`), plus le mécanisme de livraison des secrets (`*_FILE`, `H42_PKI_SECRETS_DIR`). Le
  reste est dans la table `Setting` (schéma `RuntimeSettings`, `core/settings_schema.py`), écrite par la CLI
  seulement (`h42pki config …`), lue par `GET /api/v1/config`. Pas de fichier TOML.
- **HTTP et HTTPS intégrés** (ADR-0012, remplace ADR-0005) : `server/`, deux listeners Uvicorn dans un processus,
  mTLS facultatif, certificat client dans `scope["extensions"]["tls"]` (lu par `api/client_cert.py`), routes
  publiques seules en HTTP (`api/listener.py`), mode « à vide » admis, santé par `h42pki healthcheck` et
  `GET /health`.
- **Certificat HTTPS émis par l'AC locale** (ADR-0013) : profil interne `service_tls`, 47 jours, renouvelé quand il
  reste 15 jours (`tasks/tls_service.py`) ; toute AC, même racine ou intermédiaire, s'en émet un pour son propre
  serveur.
- **Profils désactivables** (`issuance.disabled_profiles`, complément de l'ADR-0009) : tous actifs par défaut, sur
  toute AC.
- **Python 3.13** (ADR-0014).

- **Socle** : `config.py` (`Settings`, variables `H42_PKI_*`, `H42_PKI_*_FILE`, secrets Docker dans `/run/secrets`
  ou `H42_PKI_SECRETS_DIR`, contrôle des permissions des fichiers de secrets), `db.py` (config Tortoise), `main.py`
  (`create_app()` + lifespan `RegisterTortoise` puis synchronisation des profils, `generate_schemas=True` jusqu'à la
  première release, ADR-0007 ; `manage_database=False` pour le lanceur), `errors.py` (erreurs métier typées, dont 503
  `NoActiveAuthority`), `logs.py` (format texte ou JSON, niveau à chaud), `heartbeat.py` (battement du lanceur).
- **`server/`** (lanceur, ADR-0012) : `launcher.py` (`Launcher` : listeners, démarrage différé du HTTPS, rechargement
  à chaud du certificat, redémarrage d'un seul listener, mode « à vide », battement), `protocol.py` (sous-classe de
  `H11Protocol` d'Uvicorn : extensions `h42pki.listener` et `tls`), `tls.py` (extension ASGI `tls`),
  `ssl_context.py` (`SSLContext`, clé chiffrée via un dossier temporaire privé), `run.py` (base, journaux, signaux).
- **`tasks/`** : `tls_service.py` (renouvellement quotidien du certificat HTTPS, nouvelle tentative le lendemain).
- **`core/`** (pur, synchrone, testé par `tests/unit/core/test_purity.py`) : `keys.py` (`KeyAlgorithm` RSA/EC/Ed25519,
  génération, PKCS#8 DER chiffré, hachage de signature), `names.py` (`NameAttributes`, `Subject`, `rfc4514`),
  `extensions.py` (`Extensions`, `validate_for_key`), `profiles.py` (`ProfileSpec`, `BUILTIN_PROFILES`, dont le profil
  interne `service_tls`), `csr.py` (`parse_csr`, `build_csr`), `issuance.py` (`build_self_signed` pour la racine, `plan_issuance` / `build_issued` pour le reste,
  AIA caIssuers), `publication.py` (`public_base_url`, noms d'AC, URL caIssuers), `inspection.py` (SAN et AIA relus
  depuis le DER), `hostnames.py` (FQDN, noms supplémentaires, CIDR), `settings_schema.py` (`RuntimeSettings`, niveaux
  d'application), `service_tls.py` (quand réémettre le certificat HTTPS), `validity.py`, `serial.py`, `errors.py`.
- **`keystore/`** : `KeyStore` (protocole : `generate`, `load`, `export_encrypted` pour la clé TLS), `SoftwareKeyStore` (seul détenteur de la
  passphrase), `get_keystore(settings)`. Seul `keystore` appelle les fonctions de (dé)chiffrement de `core.keys`.
- **`services/`** : `AuthorityService` (`init_root`, AC locale), `IssuanceService` (`submit` → `auto_approve` ou
  `approve` / `reject` → `_issue`, **seul chemin d'émission**, y compris `issue_service_certificate`), `ProfileService`
  (synchronisation des profils intégrés, lecture, activation), `SettingsService` / `SettingsWatcher` (réglages en
  base, relecture par révision), `TlsServiceManager` (certificat `service_tls`), `PublicationService` (certificats publiés, chaîne), `KeyService`, `CertificateService`
  (lecture, recherche paginée, chaîne, statut effectif). Transactions, audit, crypto via `asyncio.to_thread` ; le
  keystore est passé explicitement et n'est construit que pour les opérations sur une clé (passphrase facultative
  ailleurs, B32).
- **Modèles** `models/` (un fichier par agrégat : `private_key` (`purpose` `ca|tls`), `authority`, `profile`,
  `certificate`, `request` (canal `system`), `audit`, `setting` (`Setting`, `SettingsRevision`), base
  `TimestampedModel`) : FK sans cycle (B27), stockage DER, `AuditLog.record()`. Un certificat est
  toujours enregistré signé.
- **API** : `api/admin/` (`routes.py`, `schemas.py` écrits à la main, `extra="forbid"`, `deps.py` : keystore,
  services et `current_actor` = `"anonymous"`, ADR-0008), `api/problems.py` (toutes les erreurs en
  `application/problem+json`, schéma `Problem` déclaré dans l'OpenAPI), `api/public/` (`/ca/{name}.crt|.pem`,
  `/ca/chain.pem` en HTTP, cache `ETag` / 304, aucune clé touchée), `api/health.py` (`GET /`, `GET /health`),
  `api/listener.py` (routes publiques seules en HTTP), `api/client_cert.py` (certificat client d'une requête).
- **CLI** `cli/` : `version`, `serve` (lanceur, `--reload`), `healthcheck`, `authority init|status|export|update`,
  `profile list|show|enable|disable`, `certificate list|export`, `config show|get|set|unset` ; `_runtime.py` ouvre la même base que le serveur et transforme les erreurs en message
  lisible (code de sortie non nul).
- **Règles métier** : le seul certificat auto-signé est celui de l'AC racine, créé par `h42pki authority init`
  (ADR-0010) ; tout le reste passe par un profil intégré (lecture seule, ADR-0009) via `IssuanceService`. AIA
  caIssuers seulement si l'AC a une `public_base_url` ; pas de CDP ni d'OCSP dans les certificats avant la phase 3.
- mypy est `strict` sur tout `src/`, sans exemption.
- Les expérimentations précédentes (`certold.py`, `certdb.py`, `certapp.py`, `main.py`, `cli.py` : stockage en
  fichiers JSON + config TOML, routes `/api/pki/ca/*`) et `src/test.py` ont été **supprimées** le 2026-11-21. Ne pas
  les recréer ni s'en inspirer : la hiérarchie d'AC se fait via la fédération (`docs/protocols/federation.md`).

La liste des bogues connus et de la dette technique est dans `docs/etat-des-lieux.md`.
Le plan de travail par phases est dans `docs/roadmap.md` — **suivre l'ordre des phases**.

## 3. Structure cible

```
src/h42pki/
  main.py            # create_app() : factory FastAPI + lifespan (Tortoise, synchronisation des profils)
  config.py          # Settings (pydantic-settings) : variables H42_PKI_* (liste fermée, ADR-0011), *_FILE, secrets
  logs.py  heartbeat.py
  server/            # lanceur maison : launcher, protocol, tls, ssl_context, run — en place (phase 1.1)
  db.py              # configuration Tortoise (tortoise_config(settings))
  errors.py          # erreurs métier typées (NotFound, Conflict, Unprocessable, InvalidRequest)
  core/              # DOMAINE CRYPTO PUR : synchrone, sans I/O, sans ORM, sans FastAPI
    keys.py  names.py  extensions.py  profiles.py  csr.py  issuance.py  publication.py  inspection.py
    hostnames.py  settings_schema.py  service_tls.py  validity.py  serial.py  errors.py      — en place
    crl.py  ocsp.py  cms.py  chain.py                                           — à venir
  keystore/          # base.py (KeyStore), software.py — en place ; pkcs11.py en phase 7
  models/            # private_key, authority, profile, certificate, request, audit, setting — en place
  services/          # authority, issuance, profiles, publication, keys, certificates, settings, tls_service,
                     # x509_fields — en place ;
                     # revocation, crl, ocsp, federation à venir
  api/
    problems.py      # handlers application/problem+json (RFC 9457)        — en place
    listener.py  client_cert.py  health.py                                  — en place
    admin/           # /api/v1/... (routes, schemas, deps ; sans auth jusqu'à la release, ADR-0008) — en place
    public/          # /ca/* (HTTP public, AIA caIssuers, chaîne) — en place ; /crl/* en phase 3
    ocsp/  est/  scep/  acme/  federation/
  tasks/             # tâches périodiques : tls_service (certificat HTTPS) — en place ; CRL, purges, expirations à venir
  cli/               # Typer : authority, profile, certificate, config, healthcheck, serve — en place
tests/
  unit/  integration/  interop/  conftest.py
docs/
```

Règle de dépendance (stricte) : `server → api → services → (core, keystore, models)` ; `tasks` est lancé par
`server` et appelle `services`.
`core` n'importe **jamais** `models`, `services`, `api`, `fastapi` ni `tortoise`.

## 4. Commandes

Configuration des outils (ruff, mypy, pytest) dans `pyproject.toml`. Raccourcis équivalents dans le `Makefile`
(`make install|fmt|lint|typecheck|test|check|run|docker-build`), utilisable depuis Git Bash.

```bash
uv sync --all-groups                      # installer (prod + dev)
uv run pytest                             # tous les tests sauf interop
uv run pytest tests/unit -q               # tests unitaires seuls (rapides)
uv run pytest -m interop                  # interopérabilité (openssl, sscep, client ACME…) — nécessite les outils
uv run pytest --cov=h42pki --cov-report=term-missing
uv run ruff check . && uv run ruff format --check .
uv run mypy src
H42_PKI_CA_PASSPHRASE=... H42_PKI_SERVER_HOSTNAME=pki.home42.test H42_PKI_SERVER_ALT_NAMES=localhost,127.0.0.1 \
  uv run h42pki serve --reload            # lanceur de dev : HTTP :8080, HTTPS :8443 dès que l'AC existe
uv run h42pki healthcheck                 # base + battement du lanceur (code 0 / 1)
uv run h42pki config show                 # réglages en base ; `config set KEY VALUE`, `config unset KEY`
uv run h42pki --help                      # CLI
uv run h42pki authority init --name root --common-name "Test Root CA"   # AC racine locale (base data/)
docker build -t h42-pki:dev .            # image (non-root, /data, `h42pki serve`, ports 8080 et 8443)
docker compose -f deploy/compose.yaml up  # hiérarchie racine + intermédiaire + émettrice (phase 2)
```

Avant de déclarer une tâche terminée : `ruff check`, `ruff format --check`, `mypy src` et `pytest` passent.

## 5. Conventions de code

- **Langue** : identifiants, docstrings, commentaires, messages de log et de commit en **anglais** ;
  documentation dans `docs/` en **français**.
- **Champs JSON** (API, base, réglages) en **snake_case**, noms alignés sur `cryptography`
  (`common_name`, `path_length`, `key_cert_sign`…). Seules exceptions : les formats imposés par une RFC
  (ACME en camelCase, via `Field(alias=...)`). Voir ADR-0006.
- **Commits** : Conventional Commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`), comme l'historique.
- Typage complet (`mypy --strict` visé sur `core/` et `keystore/`). Pydantic v2 pour toutes les entrées/sorties d'API.
- **Ne pas** exposer directement les modèles Tortoise dans l'API : schémas Pydantic dédiés dans `api/*/schemas.py`.
- **Configuration** (ADR-0011) : ne pas ajouter de variable `H42_PKI_*` sans nouvel ADR ; tout nouveau réglage va
  dans `RuntimeSettings` (défaut dans le code, valeur modifiée en base) et déclare son niveau d'application
  (`hot`, `listener`, `process`).
- **Schéma de base** : aucune migration avant la première release (ADR-0007). Les modèles peuvent changer
  librement, sans code de compatibilité ; après un changement, supprimer `data/h42pki.sqlite3*`.
- **Dates** : toujours `datetime.now(timezone.utc)` (aware). `datetime.utcnow()` est interdit.
- **Opérations crypto coûteuses** (génération RSA, signature en masse) : `await asyncio.to_thread(...)`
  depuis le code async, pour ne pas bloquer la boucle.
- Références entre tables : `ForeignKeyField` / `OneToOneField`, jamais de `UUIDField` "manuel" (B14, corrigé au lot 3).
  Pas de cycle de FK : `generate_schemas` de Tortoise le refuse (B27).
- Erreurs métier : exceptions typées dans `h42pki/errors.py`, traduites en HTTP par des handlers
  (format `application/problem+json`, RFC 9457 ; ACME impose son propre format de problème).
- Pas de logique dans les routes : une route valide l'entrée, appelle un service, formate la sortie.
- Encodages : stocker les certificats/CSR/CRL en **DER** (`BinaryField`) ; convertir en PEM à la sortie.
- Numéros de série : 159 bits aléatoires (`x509.random_serial_number()`), stockés en **hex minuscule**
  (`CharField(max_length=40)`) — un entier SQLite 64 bits déborde. Unicité par AC émettrice.

## 6. Règles de sécurité (non négociables)

> **API d'administration sans authentification** jusqu'à la première release (ADR-0008) : ne pas en ajouter,
> mais ne jamais exposer le service hors de `127.0.0.1` / réseau Docker interne. Les mécanismes propres aux
> protocoles (JWS ACME, challenge SCEP, invitation de fédération, auth EST) sont, eux, implémentés normalement.

1. **Jamais** de clé privée, passphrase, mot de passe de challenge, secret EAB ou jeton dans les logs,
   les exceptions, les réponses d'API ou les tests imprimés.
2. Les clés privées ne sortent du `keystore` que chiffrées (PKCS#8 + `BestAvailableEncryption`),
   et uniquement pour EST `serverkeygen` si activé. Le format `TraditionalOpenSSL` n'est plus utilisé.
3. **Ne jamais recopier aveuglément les extensions d'un CSR.** Le profil décide de BasicConstraints,
   KeyUsage, EKU, NameConstraints, validité. Le CSR ne fournit que la clé publique, le sujet et les SAN,
   eux-mêmes filtrés par le profil (règle B2, appliquée par `core/csr.py` et `core/issuance.py`).
4. Toujours vérifier la signature du CSR (`csr.is_signature_valid`) et les contraintes de la clé
   (algorithme, taille minimale) avant émission.
5. Une AC fille ne peut pas recevoir un `pathLen` ≥ à celui de son AC mère ; validité d'un certificat
   émis ≤ validité restante de l'AC émettrice.
6. Toute émission, révocation, changement de profil, inscription d'AC fille → entrée `AuditLog`.
7. Secrets fournis par fichier (`*_FILE`, compatible Docker secrets) ou variable d'environnement,
   jamais en dur ni dans le dépôt. `config/pki.json`, `*.sqlite3`, `*.pem`, `*.key` sont ignorés par git.
8. Comparaisons de secrets en temps constant (`hmac.compare_digest`), mots de passe hachés (argon2 / scrypt).
9. CRL et AIA servis en **HTTP simple** (pas de redirection HTTPS) pour éviter les boucles de validation ;
   EST, ACME, la fédération et l'API d'admin uniquement en **HTTPS** (depuis la phase 1.1 : le listener HTTP ne sert
   que les routes publiques, ADR-0012).
10. Le certificat client se lit **uniquement** dans `scope["extensions"]["tls"]` (lanceur, ADR-0012) ; l'en-tête
    `Client-Cert` d'un reverse-proxy n'est pris en compte que si la requête vient de `H42_PKI_TRUSTED_PROXIES`.
11. La clé de l'AC ne sert jamais à TLS : le serveur HTTPS a sa propre clé (`purpose = tls`, ADR-0013).

## 7. Tests

Stratégie complète : `docs/testing.md`. L'essentiel :

- `pytest` + `pytest-asyncio` (mode `auto`), `httpx.AsyncClient` + `ASGITransport` pour l'API.
- Base Tortoise **en mémoire** (`sqlite://:memory:`) réinitialisée par test via fixture dans `tests/conftest.py`.
- Clés de test : générées **une fois par session** (fixtures `scope="session"`), RSA 2048 / EC P-256.
  Ne jamais générer de RSA 4096 dans un test unitaire.
- Temps : `time-machine` pour expiration, `nextUpdate` CRL, nonces ACME.
- Chaque bug corrigé ⇒ un test de non-régression. Chaque endpoint de protocole ⇒ au moins un test
  qui vérifie la sortie avec `cryptography` (parsing DER) **et** un test d'interop marqué `@pytest.mark.interop`.
- Lanceur : les scénarios U1 à U14 de `docs/spikes/2026-11-tls-launcher.md` sont repris comme tests de
  non-régression (vrais sockets, ports libres, PKI de test), car le protocole TLS hérite d'une classe interne
  d'Uvicorn (version épinglée).
- Couverture visée : `core/` ≥ 90 %, global ≥ 80 %.

## 8. Façon de travailler sur ce dépôt

- Lire la doc du protocole concerné dans `docs/protocols/` **avant** de coder un endpoint ; elle liste
  les endpoints, content-types, cas d'erreur et pièges connus.
- Travailler par petites étapes testées, une phase de `docs/roadmap.md` à la fois.
- Toute décision d'architecture nouvelle ou contraire à la doc ⇒ nouvel ADR dans `docs/adr/`
  (copier `docs/adr/0000-template.md`) et mise à jour de `docs/ARCHITECTURE.md`.
- Les points marqués **« À vérifier »** dans la doc (versions de bibliothèques, support d'une fonction
  par `cryptography`) doivent être confirmés par un petit spike/test avant d'en dépendre.
- Ne pas ajouter de dépendance sans la justifier dans le message de commit ; préférer `cryptography`
  à toute autre lib crypto, et n'ajouter `asn1crypto` que là où `cryptography` ne suffit pas (CMS/SCEP).

## 9. Index de la documentation

- `docs/ARCHITECTURE.md` — vue d'ensemble, composants, modèle de données, flux, déploiement
- `docs/etat-des-lieux.md` — analyse du code existant, bogues connus
- `docs/roadmap.md` — phases de développement et critères d'acceptation
- `docs/testing.md` — stratégie de test
- `docs/protocols/` — `federation.md`, `crl.md`, `ocsp.md`, `est.md`, `scep.md`, `acme.md`
- `docs/adr/` — décisions d'architecture
- `docs/spikes/` — comptes rendus d'expériences (ex. lanceur HTTP/HTTPS et certificat client)
