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

Stack : **Python ≥ 3.12, FastAPI, Tortoise ORM (async), `cryptography`, Pydantic v2, Typer (CLI), uv**.

## 2. État actuel du code (important)

Le dépôt est en transition. **Ne pas considérer le code existant comme la référence d'architecture.**

Phase 0 (lot 1) terminée ; lots 2 et 3 (sécurité, intégrité, modèle de données, API `/api/v1`) terminés.

- **Socle définitif** : `config.py` (`Settings`, variables `H42_PKI_*`, `H42_PKI_*_FILE`, secrets Docker dans
  `/run/secrets` ou `H42_PKI_SECRETS_DIR`, contrôle des permissions des fichiers de secrets), `db.py` (config
  Tortoise), `main.py` (`create_app()` + lifespan `RegisterTortoise`, `generate_schemas=True` jusqu'à la première
  release, cf. ADR-0007), `errors.py` (erreurs métier typées), `cli.py` (`version`, `serve`).
- **Modèles** `models/` (un fichier par agrégat : `private_key`, `authority`, `certificate`, `audit`, base
  `TimestampedModel`) : FK, stockage DER, `AuditLog.record()`. Le certificat propre d'une AC est
  `Certificate.authority` (OneToOne, inverse `authority.certificate`) : Tortoise ne sait pas créer un cycle de FK.
- **API** : `api/admin/` (`routes.py`, `schemas.py` écrits à la main, `extra="forbid"`, préfixe `/api/v1`),
  `api/problems.py` (handlers `application/problem+json`), `api/health.py` (`GET /`, `GET /health`).
  L'appelant est fourni par la dépendance `current_actor` (`"anonymous"`, ADR-0008).
- **Code legacy restant** (à réécrire au lot 4 dans `core/`, `keystore/`, `services/`) : `h42pki/ca/pki.py`
  (opérations sur clés et certificats, appelé directement par les routes en guise de service ; crypto inchangée :
  RSA seul, TraditionalOpenSSL, SHA-512, validité fixe) et `h42pki/ca/pki_models.py` (`Subject`, `Extensions`
  en snake_case). Seul `h42pki.ca.*` reste exempté de mypy (`ignore_errors`).
- Les expérimentations précédentes (`certold.py`, `certdb.py`, `certapp.py`, `main.py`, `cli.py` : stockage en
  fichiers JSON + config TOML, routes `/api/pki/ca/*`) et `src/test.py` ont été **supprimées** le 2026-11-21. Ne pas
  les recréer ni s'en inspirer : la hiérarchie d'AC se fait via la fédération (`docs/protocols/federation.md`).
- `cli.py` est un module unique pour l'instant ; il deviendra le paquet `cli/` de la structure cible.

La liste des bogues connus et de la dette technique est dans `docs/etat-des-lieux.md`.
Le plan de travail par phases est dans `docs/roadmap.md` — **suivre l'ordre des phases**.

## 3. Structure cible

```
src/h42pki/
  main.py            # create_app() : factory FastAPI + lifespan (Tortoise, tâches planifiées)
  config.py          # Settings (pydantic-settings) : variables H42_PKI_*, *_FILE, secrets (TOML à venir)
  db.py              # configuration Tortoise (tortoise_config(settings))
  core/              # DOMAINE CRYPTO PUR : synchrone, sans I/O, sans ORM, sans FastAPI
    names.py  extensions.py  profiles.py  serial.py  keys.py
    issuance.py  csr.py  crl.py  ocsp.py  cms.py  chain.py
  keystore/          # abstraction des clés privées : base.py, software.py, (pkcs11.py plus tard)
  errors.py          # erreurs métier typées (NotFound, Conflict, Unprocessable)
  models/            # modèles Tortoise (un fichier par agrégat)  — en place (lot 3)
  services/          # orchestration async : authority, issuance, revocation, crl, ocsp, federation
  api/
    deps.py          # dépendances FastAPI (auth, session, autorité courante)
    problems.py      # handlers application/problem+json (RFC 9457)        — en place
    admin/           # /api/v1/...        (JSON ; sans authentification jusqu'à la release, ADR-0008) — en place
    public/          # /ca/*, /crl/*      (HTTP public, AIA + CRL)
    ocsp/  est/  scep/  acme/  federation/
  tasks/             # tâches périodiques (CRL, purge nonces ACME, expirations)
  cli/               # commandes Typer : init, status, export, rotate...
  ca/                # LEGACY (pki.py, pki_models.py) : absorbé par core/, keystore/, services/ au lot 4
tests/
  unit/  integration/  interop/  conftest.py
docs/
```

Règle de dépendance (stricte) : `api → services → (core, keystore, models)`.
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
H42_PKI_CA_PASSPHRASE=... uv run h42pki serve --reload   # serveur de dev (uvicorn, rechargement auto)
uv run h42pki --help                      # CLI
docker build -t h42-pki:dev .            # image (Granian, non-root, /data)
docker compose -f deploy/compose.yaml up  # hiérarchie racine + intermédiaire + émettrice (phase 2)
```

Avant de déclarer une tâche terminée : `ruff check`, `ruff format --check`, `mypy src` et `pytest` passent.

## 5. Conventions de code

- **Langue** : identifiants, docstrings, commentaires, messages de log et de commit en **anglais** ;
  documentation dans `docs/` en **français**.
- **Champs JSON** (API, base, configuration TOML) en **snake_case**, noms alignés sur `cryptography`
  (`common_name`, `path_length`, `key_cert_sign`…). Seules exceptions : les formats imposés par une RFC
  (ACME en camelCase, via `Field(alias=...)`). Voir ADR-0006.
- **Commits** : Conventional Commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`), comme l'historique.
- Typage complet (`mypy --strict` visé sur `core/` et `keystore/`). Pydantic v2 pour toutes les entrées/sorties d'API.
- **Ne pas** exposer directement les modèles Tortoise dans l'API : schémas Pydantic dédiés dans `api/*/schemas.py`.
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
   eux-mêmes filtrés par le profil. (Le `SignRequest` actuel recopie tout : faille à corriger.)
4. Toujours vérifier la signature du CSR (`csr.is_signature_valid`) et les contraintes de la clé
   (algorithme, taille minimale) avant émission.
5. Une AC fille ne peut pas recevoir un `pathLen` ≥ à celui de son AC mère ; validité d'un certificat
   émis ≤ validité restante de l'AC émettrice.
6. Toute émission, révocation, changement de profil, inscription d'AC fille → entrée `AuditLog`.
7. Secrets fournis par fichier (`*_FILE`, compatible Docker secrets) ou variable d'environnement,
   jamais en dur ni dans le dépôt. `config/pki.json`, `*.sqlite3`, `*.pem`, `*.key` sont ignorés par git.
8. Comparaisons de secrets en temps constant (`hmac.compare_digest`), mots de passe hachés (argon2 / scrypt).
9. CRL et AIA servis en **HTTP simple** (pas de redirection HTTPS) pour éviter les boucles de validation ;
   EST et l'API d'admin uniquement en **HTTPS**.

## 7. Tests

Stratégie complète : `docs/testing.md`. L'essentiel :

- `pytest` + `pytest-asyncio` (mode `auto`), `httpx.AsyncClient` + `ASGITransport` pour l'API.
- Base Tortoise **en mémoire** (`sqlite://:memory:`) réinitialisée par test via fixture dans `tests/conftest.py`.
- Clés de test : générées **une fois par session** (fixtures `scope="session"`), RSA 2048 / EC P-256.
  Ne jamais générer de RSA 4096 dans un test unitaire.
- Temps : `time-machine` pour expiration, `nextUpdate` CRL, nonces ACME.
- Chaque bug corrigé ⇒ un test de non-régression. Chaque endpoint de protocole ⇒ au moins un test
  qui vérifie la sortie avec `cryptography` (parsing DER) **et** un test d'interop marqué `@pytest.mark.interop`.
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
