# Stratégie de test

## 1. Pyramide

| Niveau | Dossier | Marqueur | Portée | Exécution |
|---|---|---|---|---|
| Unitaire | `tests/unit/` | — | `core/`, `keystore/`, schémas, fonctions pures ; pas de DB ni réseau | chaque commit, < 30 s |
| Intégration | `tests/integration/` | — | services + API via `httpx.ASGITransport`, Tortoise SQLite en mémoire | chaque commit |
| Interopérabilité | `tests/interop/` | `@pytest.mark.interop` | vrais clients : `openssl`, `sscep`, `curl`, `lego`/`certbot` | manuel / CI nocturne, nécessite Docker |

`pytest` sans option exclut `interop` (`addopts = "-m 'not interop'"`).

## 2. Dépendances de dev (en place depuis la phase 0, cf. `pyproject.toml`)

```toml
[dependency-groups]
dev = [
  "pytest", "pytest-asyncio", "pytest-cov", "time-machine",
  "ruff", "mypy", "asgi-lifespan",  # asgi-lifespan : exécute le lifespan de l'app en test
]
# asn1crypto : ajouté (prod) avec la phase SCEP.

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "session"
asyncio_default_test_loop_scope = "session"   # même boucle que les fixtures (connexions Tortoise)
addopts = "-m 'not interop' --strict-markers"
markers = ["interop: requires external tools / docker", "slow: long-running"]
```

## 3. Fixtures de base (`tests/conftest.py`)

- `settings` : `Settings` de test (passphrase fixe, `environment = "test"`, URLs `http://testserver`).
- `db` (function scope) : `Tortoise.init(db_url="sqlite://:memory:", modules=…)` + `generate_schemas()`, fermeture
  après le test. **À vérifier** : utilitaires de test fournis par Tortoise 1.x (`tortoise.contrib.test`) — les utiliser
  s'ils sont compatibles avec pytest-asyncio.
- Clés `scope="session"` : `rsa2048_key`, `ec_p256_key`, `ec_p384_key`, `ed25519_key`.
- Fabriques : `root_ca` (AC racine active), `issuing_ca` (fille signée par `root_ca`), `make_csr(**subject, sans=…)`,
  `issued_cert(profile=…)`, `revoked_cert(reason=…)`.
- `client` : `httpx.AsyncClient(transport=ASGITransport(app=create_app(settings)), base_url="http://testserver")`
  avec lifespan géré (tâches planifiées **désactivées** en test, appelées explicitement).
- `admin_headers` : jeton d'admin créé en base.
- `proxy_client_cert(cert)` : en-têtes simulant le reverse-proxy mTLS (pour EST/fédération).

## 4. Règles

1. Chaque module de `core/` a son fichier de test miroir (`core/crl.py` → `tests/unit/core/test_crl.py`).
2. Vérifier les sorties **en les relisant** : parser le DER produit avec `cryptography` et contrôler extensions,
   criticité, validité, signature (`cert.verify_directly_issued_by(issuer)`).
3. Tester les refus autant que les succès (profils, authentification, CSR malformés, rejeu).
4. Temps figé avec `time_machine.travel(...)` pour : expirations, `next_update` CRL/OCSP, nonces et commandes ACME.
5. Aucun secret réel, aucun appel réseau sortant hors `interop` (le validateur ACME est injecté).
6. Bug corrigé ⇒ test de non-régression nommé `test_regression_<id>` (ex. `test_regression_B1_unique_serials`).
7. Pas de RSA 4096 hors `@pytest.mark.slow`.

## 4 bis. Lanceur HTTP/HTTPS (phase 1.1)

Le protocole TLS du lanceur hérite d'une classe **interne** d'Uvicorn (ADR-0012) : ses tests vérifient le
comportement réel, avec de vrais sockets, et protègent les mises à jour d'Uvicorn (version épinglée).

- `tests/integration/server/` : PKI de test, ports libres, lanceur démarré dans la boucle de test ou en
  sous-processus.
- Reprendre les scénarios **U1 à U14** de `docs/spikes/2026-11-tls-launcher.md` :
  - démarrage différé du HTTPS ;
  - routes réparties entre HTTP et HTTPS (l'API d'administration absente en HTTP) ;
  - mTLS facultatif, certificat client et chaîne visibles dans `scope["extensions"]["tls"]`, refus d'une AC
    inconnue ;
  - rechargement à chaud, y compris pour une connexion déjà ouverte ;
  - un seul processus, arrêt propre.
- Ajouter :
  - mode « à vide » (aucun listener) avec `h42pki healthcheck` au vert ;
  - contrôles des variables d'environnement (FQDN invalide, ports identiques, CIDR invalide) ;
  - en-tête `Client-Cert` ignoré sans `H42_PKI_TRUSTED_PROXIES` ou depuis une IP non listée ;
  - renouvellement de `service_tls` à J-15 avec `time_machine`, réémission si les noms changent.
- À vérifier à l'implémentation (non couverts par l'expérience) : modification à chaud de la version TLS minimale,
  ajout à chaud d'une ancre de confiance, passage à chaud du mTLS facultatif à obligatoire.

## 5. Interopérabilité (`deploy/compose.interop.yaml`)

Services : `root`, `intermediate`, `issuing` (h42-pki, HTTP et HTTPS intégrés, sans reverse-proxy, ADR-0012),
`web` (cible http-01),
`dns` (cible dns-01), `tools` (openssl, sscep, curl, lego). Les tests `interop` pilotent `docker compose exec tools …`
et vérifient les codes de retour. Scénarios minimum :

| Scénario | Outil |
|---|---|
| Chaîne racine → intermédiaire → émettrice valide | `openssl verify` |
| Révocation visible dans la CRL et en OCSP | `openssl crl`, `openssl ocsp` |
| Enrôlement / réenrôlement EST | `curl` + `openssl pkcs7` |
| Enrôlement SCEP | `sscep getca`, `sscep enroll` |
| Émission ACME http-01 et dns-01, révocation | `lego` |

## 6. Couverture et qualité

- `core/` ≥ 90 %, `keystore/` ≥ 90 %, global ≥ 80 % (`--cov-fail-under=80` en CI une fois la phase 1 terminée).
- `ruff check`, `ruff format --check`, `mypy src` bloquants en CI (GitHub Actions : job `lint`, job `test`
  matrice Python 3.13/3.14 à partir de la phase 1.1, ADR-0014, job `interop` nocturne).
