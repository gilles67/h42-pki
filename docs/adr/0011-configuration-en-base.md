# ADR-0011 — Configuration en base, variables d'environnement limitées au démarrage

- **Statut** : accepté
- **Date** : 2026-11-22

## Contexte

Le projet doit tenir dans **un seul fichier de données** : la sauvegarde d'une AC = la base + la passphrase. Une
configuration éparpillée entre un fichier TOML, des variables d'environnement et la base compliquerait la sauvegarde,
la restauration et la future interface web d'administration.

Certains réglages doivent pourtant être connus **avant** d'ouvrir la base, ou concernent l'environnement d'exécution
du conteneur (ports publiés par le moteur de conteneurs, nom d'hôte) plutôt que l'AC elle-même.

## Décision

### Variables d'environnement (liste fermée, lues au démarrage)

| Variable | Défaut | Obligatoire | Rôle |
|---|---|---|---|
| `H42_PKI_DATABASE_URL` | `sqlite:///data/h42pki.sqlite3` | non | Connexion à la base |
| `H42_PKI_CA_PASSPHRASE` (ou `_FILE`, ou secret de conteneur) | — | **oui**, pour le serveur et les commandes qui utilisent une clé | Chiffrement des clés privées |
| `H42_PKI_SERVER_HOSTNAME` | — | **oui**, pour le serveur | FQDN du service : CN et premier SAN du certificat HTTPS intégré (ADR-0013) |
| `H42_PKI_SERVER_ALT_NAMES` | vide | non | Noms supplémentaires du certificat HTTPS : DNS (noms courts admis) et IP, séparés par des virgules |
| `H42_PKI_ENVIRONMENT` | `production` | non | `dev`, `test` ou `production` |
| `H42_PKI_BIND_ADDRESS` | `0.0.0.0` dans l'image | non | Adresse d'écoute des deux listeners |
| `H42_PKI_HTTP_ENABLED` / `H42_PKI_HTTP_PORT` | `true` / `8080` | non | Listener HTTP (ADR-0012) |
| `H42_PKI_HTTPS_ENABLED` / `H42_PKI_HTTPS_PORT` | `true` / `8443` | non | Listener HTTPS (ADR-0012) |
| `H42_PKI_TRUSTED_PROXIES` | vide | non | Réseaux (CIDR) des reverse-proxys de confiance ; vide = aucun proxy pris en compte |

Contrôles au démarrage, avec arrêt et message clair en cas d'échec :
- variables obligatoires présentes ;
- `H42_PKI_SERVER_HOSTNAME` est un vrai FQDN : au moins deux étiquettes, chacune de 1 à 63 caractères
  `a-z0-9-` sans tiret au début ni à la fin, 253 caractères au plus, dernière étiquette non numérique, ni IP, ni
  joker ; mis en minuscules, point final retiré ;
- `H42_PKI_SERVER_ALT_NAMES` : DNS valides ou IP, sans joker, doublons retirés ;
- ports entre 1 et 65535, distincts si les deux listeners sont actifs ;
- `H42_PKI_TRUSTED_PROXIES` : CIDR valides.

Les commandes de la CLI qui n'utilisent ni clé ni serveur ne demandent ni passphrase ni nom d'hôte (cf. B32).

### Tout le reste est en base

- Table `Setting` : une ligne par réglage **modifié** (clé, valeur JSON, date, auteur). Les **valeurs par défaut
  restent dans le code**, ce qui fait profiter de tout nouveau défaut les instances qui ne l'ont pas surchargé.
- Le schéma `RuntimeSettings` (Pydantic, snake_case, `extra="forbid"`) valide chaque écriture. Il est découpé en
  sections : `server` (limites TLS et HTTP), `tls_service` (certificat intégré), `issuance`, `crl`, `ocsp`, `est`,
  `scep`, `acme`, `tasks`.
- Chaque champ déclare son **niveau d'application** :

  | Niveau | Signification | Exemples |
  |---|---|---|
  | `hot` | pris en compte immédiatement (cache invalidé à l'écriture) | `issuance.disabled_profiles`, durées des CRL et de l'OCSP, `tls_service.validity_days`, niveau des journaux |
  | `listener` | le lanceur redémarre seulement le listener concerné (coupure brève de ce port) | version TLS minimale, suites de chiffrement, retrait d'une ancre de confiance client, limites Uvicorn (keep-alive, concurrence, backlog, taille des en-têtes) |
  | `process` | effet au prochain redémarrage du conteneur | backend du keystore, pool de connexions, format des journaux |

- **Écriture par la CLI seulement** jusqu'à l'authentification de l'API (ADR-0008) : `h42pki config
  show|get|set|unset`. La CLI affiche le niveau d'application de chaque modification. **Lecture** par
  `GET /api/v1/config` ; toute écriture par l'API renvoie `405`.
- Toute modification produit une entrée `AuditLog` `config.set` / `config.unset` (ancienne et nouvelle valeur,
  jamais de secret).
- Les secrets qui doivent être relus (clé HMAC d'EAB pour ACME, par exemple) sont chiffrés en base avec une clé
  dérivée de la passphrase ; les autres sont seulement hachés (`EnrollmentCredential`).
- Les paramètres d'inscription d'une AC fille (URL de la mère, invitation, empreinte) sont passés à la commande
  `h42pki authority init` ; l'invitation n'est jamais stockée.

## Alternatives considérées

- **Fichier TOML** (prévu dans la v1 de l'architecture) : lisible, mais un second fichier à sauvegarder et à garder
  cohérent avec la base, et non modifiable par une future interface web.
- **Tout en variables d'environnement** : simple dans un conteneur, mais chaque changement impose de recréer le conteneur,
  et les réglages de l'AC ne voyagent pas avec sa sauvegarde.

## Conséquences

- Sauvegarde et restauration d'une AC = un fichier (SQLite) + la passphrase.
- Le §7 de l'architecture est réécrit ; `H42_PKI_CONFIG` et le fichier TOML disparaissent.
- Changer un port ou un nom d'hôte impose de recréer le conteneur, ce qui va de pair avec la publication des ports
  par le moteur de conteneurs.
- Comme le schéma de base (ADR-0007), le schéma des réglages évolue sans migration jusqu'à la première release.

## Mise en œuvre (phase 1.1, 2026-11-22)

Décisions inchangées ; précisions apportées par l'implémentation :

- **Variables de livraison des secrets** : `H42_PKI_<NOM>_FILE` et `H42_PKI_SECRETS_DIR` (existantes depuis le lot 1,
  B4) restent en plus de la liste fermée : elles disent *où* lire un secret, elles ne configurent pas l'instance.
- **Défauts hors image** : `H42_PKI_DATABASE_URL` vaut `sqlite://data/h42pki.sqlite3` (chemin relatif, pour le
  développement local) et `H42_PKI_BIND_ADDRESS` `127.0.0.1` ; l'image fixe `sqlite:///data/h42pki.sqlite3` et
  `0.0.0.0`. Un défaut `/data` absolu ne fonctionnerait pas hors conteneur (Windows notamment).
- **Contrôles** : règles de noms et de réseaux dans `core/hostnames.py` (pur), cohérence des ports dans `Settings`.
  `H42_PKI_SERVER_HOSTNAME` et la passphrase ne sont exigés que par `h42pki serve` (code de sortie 2) ; `config`,
  `profile`, `certificate`, `healthcheck` et `authority status|export` fonctionnent sans.
- **Stockage** : `Setting.value` est du texte JSON (un `JSONField` de Tortoise gère mal une valeur qui est une simple
  chaîne). Une table `SettingsRevision` (une ligne, compteur) est incrémentée dans la même transaction que chaque
  écriture.
- **Prise en compte** : les services relisent les réglages en base à chaque usage (aucun cache : `hot` est donc
  immédiat pour eux) ; le lanceur relit la révision toutes les 5 secondes pour ce qu'il applique lui-même (niveau
  des journaux, redémarrage d'un listener, vérification du certificat HTTPS). Une valeur stockée qui ne passe plus la
  validation est ignorée avec un avertissement, au lieu de bloquer l'instance (pas de migration, ADR-0007).
- **Niveaux** : `server.client_trust_anchors` est `listener` pour tout changement, ajout compris (l'ajout à chaud
  d'une ancre n'a pas été validé) ; `server.tls_ciphers` est vérifié par OpenSSL dès l'écriture ;
  `database.pool_size` n'a d'effet qu'avec PostgreSQL / MySQL (lu après une première connexion, puis reconnexion).
- **CLI** : `h42pki config set KEY VALUE` lit la valeur en JSON, ou la prend comme texte si ce n'est pas du JSON ;
  `set` d'une valeur déjà stockée n'écrit rien. Les 404 et 405 de l'API sont en `problem+json` (B46).
