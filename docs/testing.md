# Stratégie de test

## 1. Pyramide

| Niveau | Dossier | Marqueur | Portée | Exécution |
|---|---|---|---|---|
| Unitaire | `tests/unit/` | — | `core/`, `keystore/`, schémas, fonctions pures ; pas de DB ni réseau | chaque commit, < 30 s |
| Intégration | `tests/integration/` | — | services + API via `httpx.ASGITransport`, Tortoise SQLite en mémoire | chaque commit |
| Interopérabilité | `tests/interop/` | `@pytest.mark.interop` | vrais clients : `openssl`, `sscep`, `curl`, `lego`/`certbot` | manuel / CI nocturne, nécessite Podman (ou Docker) |

`pytest` sans option exclut `interop` (`addopts = "-m 'not interop'"`).

## 2. Dépendances de dev (en place depuis la phase 0, cf. `pyproject.toml`)

```toml
[dependency-groups]
dev = [
  "pytest", "pytest-asyncio", "pytest-cov", "time-machine",
  "ruff", "mypy", "asgi-lifespan",  # asgi-lifespan : exécute le lifespan de l'app en test
]
# asn1crypto : dépendance de production depuis la phase 5 (CMS de SCEP, core/cms.py).

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "session"
asyncio_default_test_loop_scope = "session"   # même boucle que les fixtures (connexions Tortoise)
addopts = "-m 'not interop' --strict-markers"
markers = ["interop: requires external tools / a container engine", "slow: long-running"]
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
- `proxy_client_cert(cert)` : en-têtes simulant le reverse-proxy mTLS (pour EST).

## 4. Règles

1. Chaque module de `core/` a son fichier de test miroir (`core/crl.py` → `tests/unit/core/test_crl.py`).
2. Vérifier les sorties **en les relisant** : parser le DER produit avec `cryptography` et contrôler extensions,
   criticité, validité, signature (`cert.verify_directly_issued_by(issuer)`).
3. Tester les refus autant que les succès (profils, authentification, CSR malformés, rejeu).
4. Temps figé avec `time_machine.travel(...)` pour : expirations, `next_update` CRL/OCSP, nonces et commandes ACME.
5. Aucun secret réel, aucun appel réseau sortant hors `interop` (le validateur ACME est injecté).
6. Bug corrigé ⇒ test de non-régression nommé `test_regression_<id>` (ex. `test_regression_B1_unique_serials`).
7. Pas de RSA 4096 hors `@pytest.mark.slow`.

## 4 bis. Lanceur HTTP/HTTPS

Le protocole TLS du lanceur hérite d'une classe **interne** d'Uvicorn (ADR-0012) : ses tests vérifient le
comportement réel, avec de vrais sockets, et protègent les mises à jour d'Uvicorn (version épinglée).

`tests/integration/server/` (PKI de test EC P-256, ports libres, base en mémoire de la fixture `client`) :

- `test_launcher.py`, lanceur démarré dans la boucle de test :
  - **U1, U2** : HTTP seul avant tout certificat, port HTTPS fermé, `/health` à `"https": "waiting"` ;
  - **U3** : HTTPS ouvert tout seul après la création de l'AC ;
  - **U4** : en HTTP, schéma `http`, extension `h42pki.listener` = `http`, pas d'extension `tls` ;
  - **U5, U6** : répartition des routes (`/api/v1/*`, `/docs`, `/openapi.json` absents en HTTP avec un 404
    `problem+json` sans redirection, présents en HTTPS ; `/`, `/health`, `/ca/*` sur les deux) ;
  - **U7 à U10** : HTTPS sans certificat client, certificat client et chaîne vérifiée (feuille + AC) dans
    `scope["extensions"]["tls"]`, certificat d'une AC inconnue refusé à la poignée de main ;
  - **U11, U12** : renouvellement forcé par les réglages `tls_service.*`, nouveau numéro de série pour les nouvelles
    connexions, connexion ouverte avant le renouvellement toujours servie avec l'ancien certificat ;
  - **U13** : les deux listeners servis par le même processus ;
  - redémarrage du seul listener HTTPS après `server.tls_min_version = tls1.3` (TLS 1.2 refusé ensuite, HTTP
    intact), redémarrage des deux listeners pour une limite Uvicorn, ancien listener conservé si le nouveau contexte
    TLS échoue, niveau des journaux appliqué à chaud ;
  - mode « à vide » (aucun port, battement écrit puis supprimé à l'arrêt), HTTPS désactivé sans émission de
    certificat, avertissements au démarrage, port HTTP occupé.
- `test_process.py`, `h42pki serve` dans un autre processus :
  - HTTPS ouvert après `h42pki authority init` lancée dans un troisième processus, API d'administration 404 en HTTP
    et 200 en HTTPS, certificat de 47 jours, puis **U14** (arrêt propre sur SIGTERM, POSIX seulement) ;
  - **U14** en mode « à vide » ;
  - `h42pki healthcheck` rouge avant le démarrage, vert en mode « à vide », rouge après l'arrêt ;
  - `serve` sans `H42_PKI_SERVER_HOSTNAME` ou sans passphrase : code 2 ; plus d'options `--host` / `--port`.
- `test_components.py` : `Client-Cert` ignoré sans `H42_PKI_TRUSTED_PROXIES` et depuis une IP non listée, accepté
  depuis une IP listée, en-tête invalide ignoré, connexion TLS prioritaire ; tâche de renouvellement (échec puis
  nouvelle tentative, renouvellement à J-15 avec `time_machine`, réveil sur demande) ; `/health` avec un
  renouvellement en échec ; battement et `healthcheck` (absent, récent, périmé, base injoignable) ; `SSLContext`
  (aucun fichier laissé dans le dossier temporaire, ancres) ; réglages qui redémarrent un listener ;
  `database.pool_size`.

Ailleurs : `tests/integration/test_service_tls.py` (émission, réémission si les noms changent, renouvellement à J-15,
expiration, matériel chargé avec la clé chiffrée), `tests/unit/core/test_service_tls.py`,
`tests/unit/core/test_hostnames.py`, `tests/unit/core/test_settings_schema.py`, `tests/integration/test_settings.py`
(dont la relecture d'une écriture faite « par un autre processus »), `test_cli_config.py`, `test_config_api.py`,
`test_disabled_profiles.py`.

Limites connues :
- sous **Windows**, SIGTERM ne peut pas être envoyé à un processus : les assertions de U14 ne tournent que sous
  POSIX ;
- les tests qui lancent la CLI pendant que le serveur tourne demandent un Linux réel, WSL2, Windows ou un conteneur
  (B42, clos : WSL1 n'est plus un environnement de développement) ;
- non couverts (non implémentés) : ajout à chaud d'une ancre de confiance et passage à chaud du mTLS facultatif à
  obligatoire, sans redémarrer le listener.

## 4 ter. Fédération

Détail dans `docs/protocols/federation.md` §7. Tortoise étant global au processus, la mère tourne dans un
**sous-processus** (`tests/integration/server/instance.py`) et se pilote par son API HTTPS, jamais par sa CLI pendant
qu'elle tourne. Le contrôle du statut d'une fille auprès de sa mère (`test_parent_check.py`, phase 3) suit le même
modèle. Sorties de la CLI : toujours par `tests/cli_helpers.plain`.

## 4 quater. Révocation (phase 3)

`docs/protocols/crl.md` §5 et `ocsp.md` §6. Unitaires `test_crl.py`, `test_ocsp.py` (fixture
`tests/fixtures/ocsp-two-certids.der`, produite par `openssl`, `cryptography` ne sachant pas construire deux CertID) ;
intégration `test_revocation.py`, `test_cli_revocation.py`, `test_revocation_options.py`, `test_ocsp.py`,
`test_tasks.py` (`time_machine`), `test_health_revocation.py`, `server/test_parent_check.py`,
`server/test_process.py` (mode « à vide » refusé avec révocation). Non-régression : B34, B41, B44.

## 4 quinquies. EST (phase 4)

`docs/protocols/est.md` §8. Unitaires `test_passwords.py` (les tests abaissent le coût de scrypt par la fixture
`fast_password_hashing`, les vrais paramètres sont testés une fois), `test_est.py` ; intégration `test_est.py`,
`test_est_accounts.py`, `test_est_reenroll.py`, `test_est_serverkeygen.py`, `server/test_est_tls.py` (vrai
certificat client en TLS). Le certificat client d'un proxy de confiance se simule par l'en-tête `Client-Cert` avec
`H42_PKI_TRUSTED_PROXIES` couvrant le client de test. Non-régression : B45, B55.

## 5. Interopérabilité (`-m interop`)

Outils de l'hôte (`openssl`, `curl`, `bash`) et moteur de conteneurs (Podman par défaut, ADR-0016) ; pas de conteneur
`tools` dédié :

- `tests/interop/test_openssl.py`, sans conteneur : certificats lus et vérifiés par `openssl` ; CRL (`openssl crl
  -inform DER -text`, `openssl verify -crl_check`) ; OCSP (`openssl ocsp -reqout` puis `-reqin -respin`, avec et sans
  nonce) ;
- `tests/interop/test_compose.py` : `deploy/bootstrap.sh` (hiérarchie `root`, `intermediate`, `issuing` de
  `deploy/compose.yaml`, toutes avec `--crl --ocsp`), `deploy/est-test.sh` (avec `estclient` si `ESTCLIENT` est
  défini), `deploy/scep-test.sh` (`sscep` construit depuis ses sources par `deploy/sscep/Containerfile`),
  `deploy/acme-test.sh` (lego, certbot, pebble-challtestsrv en conteneurs) puis `deploy/revocation-test.sh`.
- Client ACME des tests d'intégration : `tests/acme_client.py` et `tests/acme_jws.py` (sur `cryptography`) ; le
  validateur réseau est remplacé par `app.state.acme_validation.checker` ; http-01 et dns-01 réels sont testés contre
  un serveur HTTP et un serveur DNS locaux.
- Client SCEP des tests d'intégration : `tests/scep_client.py` (asn1crypto + `cryptography`), qui construit
  `PKCSReq`, `RenewalReq`, `CertPoll`, `GetCert`, `GetCRL` et lit les `CertRep`.

| Scénario | Outil | État |
|---|---|---|
| Chaîne racine → intermédiaire → émettrice valide | `openssl verify` | ✅ phase 2 |
| Révocation visible dans la CRL et en OCSP, émettrice révoquée par l'intermédiaire | `openssl crl`, `openssl verify -crl_check[_all]`, `openssl ocsp` | ✅ phase 3 |
| EST : `cacerts`, `simpleenroll`, approbation manuelle, `simplereenroll` (mTLS), `serverkeygen`, `csrattrs` | `curl` + `openssl`, `estclient` (`ESTCLIENT=…`) | ✅ phase 4 |
| SCEP : `getcaps`, `getca`, `enroll` (challenge à usage unique puis refusé, réutilisable), `PENDING` → `SUCCESS` par interrogation, renouvellement, `getcert`, `getcrl` | `sscep` 0.10.0 | ✅ phase 5 |
| ACME : http-01 (lego, certbot), dns-01 avec joker, adresse IP, approbation manuelle, `revokeCert` puis OCSP | lego 5.8.1, certbot 5.10.0, pebble-challtestsrv 2.8.0, `openssl ocsp` | ✅ phase 6 (6a) |

## 6. Couverture et qualité

- `core/` ≥ 90 %, `keystore/` ≥ 90 %, global ≥ 80 % (`--cov-fail-under=80` en CI une fois la phase 1 terminée).
- `ruff check`, `ruff format --check`, `mypy src` bloquants en CI (GitHub Actions : job `lint`, job `test`
  matrice Python 3.13/3.14 à partir de la phase 1.1, ADR-0014, job `interop` nocturne).
