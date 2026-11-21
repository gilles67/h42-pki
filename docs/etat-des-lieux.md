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
| `src/ca/models.py` | 3 (Tortoise) | `Certificate`, `Authority`, `PrivateKey` | **Faire évoluer** vers `models/` (cf. ARCHITECTURE §4) — déplacé dans `src/h42pki/ca/models.py` (lot 1, logique inchangée) |
| `src/ca/pki_models.py` | 3 | `Subject`, `Extension` Pydantic | **Faire évoluer** vers `core/names.py`, `core/extensions.py`, `core/profiles.py` — déplacé dans `src/h42pki/ca/pki_models.py` (lot 1) |
| `src/ca/pki.py` | 3 | génération de clé, auto-signature | **Découper** : `keystore/software.py`, `core/issuance.py`, `services/` — déplacé dans `src/h42pki/ca/pki.py` (lot 1), passphrase lue dans `Settings` |
| `src/api.py` | 3 | routes FastAPI clés/certificats | ✅ **Déplacé** dans `src/h42pki/api/admin.py` (lot 1, `APIRouter`, mêmes routes) — réécriture en `api/admin/` au lot 4 |
| `src/test.py` | — | script de debug, **affiche la passphrase** | ✅ **Supprimé** (2026-11-21) |
| `Dockerfile`, `Makefile`, `src/Makefile`, `src/requirements.txt` | — | build | ✅ **Refaits** (lot 1) : `Dockerfile` et `Makefile` racine ; `src/Makefile` et `src/requirements.txt` supprimés |

## 2. Bogues et défauts identifiés

Gravité : 🔴 sécurité / perte de données · 🟠 fonctionnel · 🟡 qualité.

| # | Gravité | Emplacement | Problème | Correction attendue |
|---|---|---|---|---|
| B1 | 🔴 | `models.Certificate.sn` | `default=x509.random_serial_number()` est **évalué une seule fois** à l'import : tous les certificats créés dans un même processus reçoivent le même numéro (échec d'unicité, ou pire collision si l'unicité est retirée). | `default=lambda: format(x509.random_serial_number(), "x")`, colonne hex, unicité `(issuer, serial_hex)` |
| B2 | ✅ | ~~`certdb.Certificate.SignRequest`~~ | Recopiait **toutes** les extensions du CSR. Code supprimé ; la règle reste : extensions imposées par le profil uniquement (CLAUDE.md §6.3) | — |
| B3 | ✅ | ~~`certdb` / `certapp`~~ | Routes `/api/pki/ca/*` sans authentification ni vérification de CSR. Code supprimé ; la fédération devra être authentifiée et vérifier `csr.is_signature_valid` | — |
| B4 | 🔴 | `pki.PkiConfiguration.load` | `oct(st.st_mode) != 0o100600` compare une **chaîne** à un entier (toujours vrai) et l'`Exception(...)` n'est **pas levée** : le contrôle des permissions ne fait rien. | `stat.S_IMODE(st.st_mode) & 0o077` → `raise` ; remplacé à terme par `pydantic-settings` + `*_FILE` — **Partiellement résolu** (lot 1) : `PkiConfiguration` et `config/pki.json` supprimés, passphrase par `H42_PKI_CA_PASSPHRASE`, `*_FILE` ou secret Docker ; reste le contrôle des permissions du fichier secret au lot 2 |
| B5 | ✅ | `src/test.py` | Imprime la passphrase sur la sortie standard. | Résolu : fichier supprimé (2026-11-21) |
| B6 | 🟠 | `api.py` → `delete_private_key` | Appelle `pki.PkiPrivateKey.delete`, qui n'existe pas (la méthode s'appelle `delete_key`) → `AttributeError`. | Renommer / tester |
| B7 | 🟠 | `pki.PkiPrivateKey.delete_key` | `datakey.delete()` n'est pas `await` : la suppression n'a jamais lieu. | `await datakey.delete()` (et interdire la suppression d'une clé utilisée par une AC) |
| B8 | 🟠 | `pki.PkiPrivateKey.generate` | Si le type n'est pas RSA, `key_data` n'est jamais défini → `UnboundLocalError`. | Dispatcher par algorithme (RSA, EC, Ed25519), erreur explicite sinon |
| B9 | 🟠 | `pki_models.Extension.append_extension` | `ExtendedKeyUsage` est modélisé mais **jamais ajouté** au certificat. | Ajouter l'EKU (et le rendre non critique) |
| B10 | 🟠 | `pki_models.X509BasicConstraints` | `PathLength=0` par défaut, y compris pour un certificat non-AC : `cryptography` lève une erreur si `ca=False` et `path_length` non nul… et `0` sur une AC racine interdit toute AC fille. | `basic_constraints.path_length: int | None = None` (snake_case, ADR-0006), validation croisée |
| B11 | 🟠 | `pki_models.Subject` | Tous les attributs sont obligatoires (impossible d'émettre un certificat avec seulement `CN`). | Champs optionnels + politique de sujet par profil |
| B12 | 🟠 | `pki.PkiCertificate.self_sign` | Pas d'`AuthorityKeyIdentifier`, validité fixe de 3653 jours, signature SHA-512 (moins compatible que SHA-256/384), pas de vérification que la clé n'est pas déjà utilisée. | Paramètres issus du profil/config |
| B13 | 🟠 | `models.Certificate.key` | Le champ s'appelle `key` mais contient la **clé publique** → confusion dangereuse. | `public_key_der` |
| B14 | 🟠 | `models` | Références par `UUIDField` (`privatekey`, `signed_by`, `certificate`) au lieu de `ForeignKeyField` : pas d'intégrité référentielle. | `ForeignKeyField` |
| B15 | ✅ | ~~`cli.py`~~ | Imports manquants. Fichier supprimé ; nouvelle CLI en phase 1 | — |
| B16 | ✅ | `Dockerfile` | `COPY app /app` : le dossier `app` n'existe pas ; le `Makefile` racine construit avec le contexte `./src` alors que le Dockerfile est à la racine. | Résolu (lot 1) : `Dockerfile` racine `python:3.12-slim` + uv, non-root, healthcheck ; `Makefile` avec contexte `.` |
| B17 | 🟡 | partout | `datetime.utcnow()` (déprécié, naïf). | `datetime.now(timezone.utc)` |
| B18 | 🟡 | `pki.py` | Clés privées au format `TraditionalOpenSSL`. | PKCS#8 chiffré |
| B19 | ✅ | `src/requirements.txt` vs `pyproject.toml` | Deux listes de dépendances divergentes (`tortoise-orm` absent de l'une, `PyKCS11`/`granian` de l'autre). `requests` retiré des deux le 2026-11-21 (`uv.lock` à régénérer). | Résolu (lot 1) : `pyproject.toml` + `uv.lock` seule source, `src/requirements.txt` supprimé, extra `pkcs11` |
| B20 | ✅ | imports | `api.py` fait `from ca import …` : dépend du répertoire courant. | Résolu (lot 1) : paquet `h42pki` installable (layout `src/`, hatchling), imports `h42pki.*` |
| B21 | 🟡 | `models.py` | `model_config = ConfigDict(...)` sur des modèles Tortoise : sans effet. | Retirer |
| B22 | 🟡 | `api.py` | `register_tortoise(..., generate_schemas=True)` en dur, base SQLite dans le répertoire courant. | Config + migrations — **Partiellement résolu** (lot 1) : URL de base dans `Settings` (`H42_PKI_DATABASE_URL`), `create_app()` + lifespan `RegisterTortoise` ; migrations reportées à la première release (ADR-0007), `generate_schemas=True` conservé d'ici là |
| B23 | ✅ | `PkiConfiguration` | `config/pki.json` relu à chaque appel. | Résolu (lot 1) : `Settings` (pydantic-settings) chargés une fois par `get_settings()` (cache) |

## 3. Ce qui est bon et à garder

- Le choix **Tortoise + FastAPI + Pydantic + `cryptography`**, cohérent et async de bout en bout.
- Le chiffrement systématique des clés privées par passphrase.
- La modélisation explicite des `KeyUsage` / `ExtendedKeyUsage` / `BasicConstraints` en Pydantic : bonne base pour
  les **profils**.
- L'idée, explorée dans l'expérimentation supprimée, d'une AC intermédiaire qui envoie son CSR à sa mère et
  d'ajouter CDP/AIA lors de la signature : reprise **uniquement au niveau conception** dans
  `docs/protocols/federation.md` et `docs/ARCHITECTURE.md` §5.1.
- La préparation PKCS#11 (OpenSC, `PyKCS11`) : conservée comme objectif de la phase 7.
