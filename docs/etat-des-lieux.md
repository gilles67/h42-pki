# État des lieux du code existant (2026-11)

Analyse du dépôt au commit `04118b4` (« feat: Create Key and self signed certificate »).
Objectif : savoir ce qui est conservé, porté ou supprimé, et lister les bogues à corriger **avec un test de non-régression**.

## 1. Inventaire

| Fichier | Génération | Rôle | Décision |
|---|---|---|---|
| `src/ca/certold.py` | 1 (fichiers bruts) | ancienne base de certificats | ✅ **Supprimé** (2026-11-21) |
| `src/ca/certdb.py` | 2 (JSON + TOML) | AC racine/intermédiaire, signature de CSR, config TOML | ✅ **Supprimé** (2026-11-21) — expérimentation, rien n'est porté |
| `src/ca/certapp.py`, `src/main.py` | 2 | routes `/api/pki/ca/request` et `/sign` | ✅ **Supprimés** (2026-11-21) — remplacés à terme par `api/federation/` |
| `src/cli.py` | 2 | CLI Typer `ca status/get/init` sur `certdb` | ✅ **Supprimé** (2026-11-21) — nouvelle CLI à écrire en phase 1 |
| `src/ca/models.py` | 3 (Tortoise) | `Certificate`, `Authority`, `PrivateKey` | ✅ **Remplacé** (lot 3) par le paquet `src/h42pki/models/` (un fichier par agrégat, FK, DER) |
| `src/ca/pki_models.py` | 3 | `Subject`, `Extension` Pydantic | **Faire évoluer** vers `core/names.py`, `core/extensions.py`, `core/profiles.py` — déplacé dans `src/h42pki/ca/pki_models.py` (lot 1), renommé en snake_case (lot 3, ADR-0006) |
| `src/ca/pki.py` | 3 | génération de clé, auto-signature | **Découper** : `keystore/software.py`, `core/issuance.py`, `services/` — déplacé dans `src/h42pki/ca/pki.py` (lot 1), passphrase lue dans `Settings` ; adapté au modèle du lot 3 (DER, audit, `asyncio.to_thread`) |
| `src/api.py` | 3 | routes FastAPI clés/certificats | ✅ **Remplacé** (lot 3) par `src/h42pki/api/admin/` (`/api/v1`, schémas explicites) ; anciennes routes supprimées |
| `src/test.py` | — | script de debug, **affiche la passphrase** | ✅ **Supprimé** (2026-11-21) |
| `Dockerfile`, `Makefile`, `src/Makefile`, `src/requirements.txt` | — | build | ✅ **Refaits** (lot 1) : `Dockerfile` et `Makefile` racine ; `src/Makefile` et `src/requirements.txt` supprimés |

## 2. Bogues et défauts identifiés

Gravité : 🔴 sécurité / perte de données · 🟠 fonctionnel · 🟡 qualité.

| # | Gravité | Emplacement | Problème | Correction attendue |
|---|---|---|---|---|
| B1 | ✅ | `models.Certificate.sn` | `default=x509.random_serial_number()` est **évalué une seule fois** à l'import : tous les certificats créés dans un même processus reçoivent le même numéro (échec d'unicité, ou pire collision si l'unicité est retirée). | Résolu (lot 2) : `serial_hex` (hex minuscule, 40 car.) avec défaut **fonction** `new_serial_hex()`, unicité `(issuer, serial_hex)` ; `test_regression_B1_unique_serials` (voir aussi B26) |
| B2 | ✅ | ~~`certdb.Certificate.SignRequest`~~ | Recopiait **toutes** les extensions du CSR. Code supprimé ; la règle reste : extensions imposées par le profil uniquement (CLAUDE.md §6.3) | — |
| B3 | ✅ | ~~`certdb` / `certapp`~~ | Routes `/api/pki/ca/*` sans authentification ni vérification de CSR. Code supprimé ; la fédération devra être authentifiée et vérifier `csr.is_signature_valid` | — |
| B4 | ✅ | `pki.PkiConfiguration.load` | `oct(st.st_mode) != 0o100600` compare une **chaîne** à un entier (toujours vrai) et l'`Exception(...)` n'est **pas levée** : le contrôle des permissions ne fait rien. | Résolu (lot 2) : `PkiConfiguration` supprimé (lot 1) ; sous POSIX, un fichier de secret (`*_FILE` ou dossier de secrets) modifiable par le groupe ou les autres est refusé en `production` (avertissement sinon), un fichier lisible par tous hors du dossier de secrets donne un avertissement, `0444` dans le dossier est accepté (secrets Docker). Tests `test_regression_B4_*` (exécutés sous Linux) |
| B5 | ✅ | `src/test.py` | Imprime la passphrase sur la sortie standard. | Résolu : fichier supprimé (2026-11-21) |
| B6 | ✅ | `api.py` → `delete_private_key` | Appelle `pki.PkiPrivateKey.delete`, qui n'existe pas (la méthode s'appelle `delete_key`) → `AttributeError`. | Résolu (lot 2) : `DELETE /api/v1/private-keys/{id}` appelle `delete_key` ; `test_regression_B6_B7_delete_private_key` |
| B7 | ✅ | `pki.PkiPrivateKey.delete_key` | `datakey.delete()` n'est pas `await` : la suppression n'a jamais lieu. | Résolu (lot 2) : `await key.delete()` ; 409 si un certificat ou une AC utilise la clé (FK `RESTRICT` en filet) ; `test_regression_B7_delete_used_private_key_conflicts` |
| B8 | 🟠 | `pki.PkiPrivateKey.generate` | Si le type n'est pas RSA, `key_data` n'est jamais défini → `UnboundLocalError`. | Dispatcher par algorithme (RSA, EC, Ed25519), erreur explicite sinon |
| B9 | 🟠 | `pki_models.Extension.append_extension` | `ExtendedKeyUsage` est modélisé mais **jamais ajouté** au certificat. | Ajouter l'EKU (et le rendre non critique) |
| B10 | 🟠 | `pki_models.X509BasicConstraints` | `PathLength=0` par défaut, y compris pour un certificat non-AC : `cryptography` lève une erreur si `ca=False` et `path_length` non nul… et `0` sur une AC racine interdit toute AC fille. | `basic_constraints.path_length: int | None = None` (snake_case, ADR-0006), validation croisée |
| B11 | 🟠 | `pki_models.Subject` | Tous les attributs sont obligatoires (impossible d'émettre un certificat avec seulement `CN`). | Champs optionnels + politique de sujet par profil |
| B12 | 🟠 | `pki.PkiCertificate.self_sign` | Pas d'`AuthorityKeyIdentifier`, validité fixe de 3653 jours, signature SHA-512 (moins compatible que SHA-256/384), pas de vérification que la clé n'est pas déjà utilisée. | Paramètres issus du profil/config |
| B13 | ✅ | `models.Certificate.key` | Le champ s'appelle `key` mais contient la **clé publique** → confusion dangereuse. | Résolu (lot 3) : `Certificate.public_key_der` ; le certificat lui-même est dans `der` |
| B14 | ✅ | `models` | Références par `UUIDField` (`privatekey`, `signed_by`, `certificate`) au lieu de `ForeignKeyField` : pas d'intégrité référentielle. | Résolu (lot 3) : `ForeignKeyField` (`issuer`, `private_key`, `parent`) et `OneToOneField` `Certificate.authority` (voir B27) |
| B15 | ✅ | ~~`cli.py`~~ | Imports manquants. Fichier supprimé ; nouvelle CLI en phase 1 | — |
| B16 | ✅ | `Dockerfile` | `COPY app /app` : le dossier `app` n'existe pas ; le `Makefile` racine construit avec le contexte `./src` alors que le Dockerfile est à la racine. | Résolu (lot 1) : `Dockerfile` racine `python:3.12-slim` + uv, non-root, healthcheck ; `Makefile` avec contexte `.` |
| B17 | 🟡 | partout | `datetime.utcnow()` (déprécié, naïf). | `datetime.now(timezone.utc)` |
| B18 | 🟡 | `pki.py` | Clés privées au format `TraditionalOpenSSL`. | PKCS#8 chiffré |
| B19 | ✅ | `src/requirements.txt` vs `pyproject.toml` | Deux listes de dépendances divergentes (`tortoise-orm` absent de l'une, `PyKCS11`/`granian` de l'autre). `requests` retiré des deux le 2026-11-21 (`uv.lock` à régénérer). | Résolu (lot 1) : `pyproject.toml` + `uv.lock` seule source, `src/requirements.txt` supprimé, extra `pkcs11` |
| B20 | ✅ | imports | `api.py` fait `from ca import …` : dépend du répertoire courant. | Résolu (lot 1) : paquet `h42pki` installable (layout `src/`, hatchling), imports `h42pki.*` |
| B21 | ✅ | `models.py` | `model_config = ConfigDict(...)` sur des modèles Tortoise : sans effet. | Résolu (lot 3) : retiré, ainsi que tous les `pydantic_model_creator` (schémas d'API écrits à la main) |
| B22 | 🟡 | `api.py` | `register_tortoise(..., generate_schemas=True)` en dur, base SQLite dans le répertoire courant. | Config + migrations — **Partiellement résolu** (lot 1) : URL de base dans `Settings` (`H42_PKI_DATABASE_URL`), `create_app()` + lifespan `RegisterTortoise` ; migrations reportées à la première release (ADR-0007), `generate_schemas=True` conservé d'ici là |
| B23 | ✅ | `PkiConfiguration` | `config/pki.json` relu à chaque appel. | Résolu (lot 1) : `Settings` (pydantic-settings) chargés une fois par `get_settings()` (cache) |
| B24 | 🔴 | `h42pki/api/admin/` | API d'administration sans aucune authentification : quiconque atteint le port peut générer des clés et auto-signer une AC. | **Accepté temporairement** (ADR-0008) : écoute locale uniquement, authentification avant la première release |
| B25 | ✅ | `api.py` → `GET /certificate/{id}` | Renvoyait le certificat **PEM** avec `Content-Type: application/pkix-cert` (type réservé au DER). | Résolu (lots 2-3, **avancé du lot 4**) : stockage DER, `GET /api/v1/certificates/{id}.pem` (`application/x-pem-file`) et `{id}.crt` (`application/pkix-cert`, DER), 409 tant que le certificat n'est pas signé |
| B26 | 🟡 | `models.Certificate` | L'unicité `(issuer, serial_hex)` ne protège pas les certificats **auto-signés** : `issuer` est NULL et SQL considère les NULL comme distincts. Le tirage aléatoire sur 159 bits rend la collision négligeable. | Au lot 4 : rattacher l'auto-signé à son `Authority` (issuer = l'AC elle-même) ou index unique partiel |
| B27 | 🟡 | `models` / Tortoise 1.1.7 | `generate_schemas` refuse un cycle de clés étrangères (`Certificate.issuer → Authority` + `Authority.certificate → Certificate`), même avec `db_constraint=False`. | **Contourné** (lot 3) : le certificat propre d'une AC est `Certificate.authority` (`OneToOneField`, inverse `authority.certificate`). Un renouvellement de certificat d'AC passe par une nouvelle `Authority` |
| B28 | 🟡 | `ca/pki.py` → `subject_dn` | `rfc4514_string()` écrit l'e-mail sous forme d'OID (`1.2.840.113549.1.9.1=…`) : correct mais peu lisible. | Lot 4 (`core/names.py`) : table de noms d'attributs (`emailAddress`) |
| B29 | 🟡 | `api` | Les erreurs de validation des requêtes (422 générés par FastAPI/Pydantic) gardent le format FastAPI `{"detail": [...]}`, pas `application/problem+json` comme les erreurs métier. | Lot 4 : handler `RequestValidationError` → problem+json avec la liste des erreurs en extension |

## 3. Ce qui est bon et à garder

- Le choix **Tortoise + FastAPI + Pydantic + `cryptography`**, cohérent et async de bout en bout.
- Le chiffrement systématique des clés privées par passphrase.
- La modélisation explicite des `KeyUsage` / `ExtendedKeyUsage` / `BasicConstraints` en Pydantic : bonne base pour
  les **profils**.
- L'idée, explorée dans l'expérimentation supprimée, d'une AC intermédiaire qui envoie son CSR à sa mère et
  d'ajouter CDP/AIA lors de la signature : reprise **uniquement au niveau conception** dans
  `docs/protocols/federation.md` et `docs/ARCHITECTURE.md` §5.1.
- La préparation PKCS#11 (OpenSC, `PyKCS11`) : conservée comme objectif de la phase 7.
