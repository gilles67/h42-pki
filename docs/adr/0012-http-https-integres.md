# ADR-0012 — HTTP et HTTPS intégrés au conteneur (lanceur maison Uvicorn)

- **Statut** : accepté
- **Date** : 2026-11-22
- **Remplace** : ADR-0005 (TLS et mTLS terminés par un reverse-proxy)

## Contexte

Un conteneur doit pouvoir fonctionner **seul**, sans reverse-proxy :
- en HTTP, pour les services qui doivent rester accessibles sans TLS (AIA, CRL, OCSP, SCEP) ;
- en HTTPS, pour l'API d'administration, la fédération, EST et ACME ;
- avec **mTLS facultatif** : EST doit voir le certificat client quand il y en a un (réenrôlement) et accepter
  l'authentification HTTP Basic quand il n'y en a pas, sur le même port.

L'ADR-0005 confiait TLS à un reverse-proxy, faute de savoir si un serveur ASGI pouvait transmettre le certificat
client à l'application. Une expérience autonome a tranché la question (`docs/spikes/2026-11-tls-launcher.md`) :

| Question | Uvicorn 0.54 + lanceur maison | Granian 2.8.9 |
|---|---|---|
| Certificat client visible par l'application | **oui** (protocole personnalisé), chaîne complète en Python 3.13 | **non**, avec ou sans vérification |
| mTLS facultatif (client sans certificat accepté) | **oui** (`CERT_OPTIONAL`) | **non** : `--ssl-client-verify` rend le certificat obligatoire |
| Certificat d'une AC inconnue refusé | oui | oui |
| HTTP + HTTPS dans un seul processus | **oui** | oui (mode embarqué) |
| HTTPS démarré après coup, certificat rechargé à chaud | **oui** | non testé (sans objet) |

## Décision

- **Un lanceur maison** (`h42pki serve`) exécute, dans un seul processus et une seule boucle asyncio, jusqu'à deux
  serveurs Uvicorn servant la même application : HTTP (`H42_PKI_HTTP_*`) et HTTPS (`H42_PKI_HTTPS_*`), cf. ADR-0011.
  Granian n'est plus utilisé.
- **Protocole HTTP personnalisé** (sous-classe du protocole `h11` d'Uvicorn) : après la poignée de main TLS, il lit le
  certificat client et la chaîne vérifiée, et les place dans `scope["extensions"]["tls"]`, au format de l'extension
  ASGI standard. L'application ne lit le certificat client **que** là.
- **`SSLContext` construit par l'application** (`ssl_context_factory` d'Uvicorn) : TLS 1.2 minimum, mTLS facultatif
  (`CERT_OPTIONAL`) avec la chaîne de l'AC locale comme ancre de confiance (complétable par réglage).
- **Démarrage différé** : le listener HTTPS ne démarre que lorsque le certificat du serveur existe (ADR-0013). Avant,
  seul HTTP répond.
- **Rechargement à chaud** : un certificat renouvelé est rechargé dans le même `SSLContext`. Les nouvelles connexions
  reçoivent le nouveau certificat, celles déjà ouvertes continuent. Le certificat et la clé, lus depuis la base,
  passent par un dossier temporaire privé (`0700`, clé en `0600`) supprimé aussitôt chargé : le module `ssl` de
  Python ne lit que des fichiers.
- **Répartition des routes** (décidée par l'application à chaque requête) :
  - **HTTP** : `/`, `/health`, `/ca/*`, `/crl/*`, `/ocsp`, `/scep` ;
  - **HTTPS** : tout, y compris les routes HTTP ci-dessus ; `/api/v1/*`, la fédération, EST et ACME y sont
    **exclusivement**.
- **Mode « à vide »** : HTTP et HTTPS peuvent être désactivés tous les deux. Le lanceur tourne alors sans listener,
  les tâches planifiées continuent et la CLI reste utilisable par `podman exec` (cas d'une racine hors ligne). Un
  message l'indique au démarrage.
- **Santé du service** :
  - `h42pki healthcheck`, indépendant de tout port, utilisé par le `HEALTHCHECK` de l'image. Il vérifie la base et le
    battement du lanceur (mis à jour régulièrement par le lanceur) ;
  - `GET /health` sur chaque listener actif, pour la future interface web : base, battement, statut de l'AC,
    listeners actifs, expiration du certificat HTTPS. Statuts seulement, jamais de secret ni de détail interne.
- **Reverse-proxy facultatif** : si `H42_PKI_TRUSTED_PROXIES` est renseigné, un certificat client transmis par un
  proxy (en-tête `Client-Cert`, RFC 9440) est accepté **seulement** depuis ces réseaux, et le proxy doit supprimer tout
  en-tête entrant du même nom. Vide (par défaut) : l'en-tête est ignoré.
- **Avertissements au démarrage** : HTTP désactivé alors que les URL publiques (AIA, puis CRL et OCSP) sont en
  `http://` ; HTTP désactivé mais HTTPS actif (risque de boucle de validation chez les clients qui vérifient la
  révocation).

## Alternatives considérées

- **Reverse-proxy obligatoire** (ADR-0005) : un composant de plus à déployer et à configurer pour chaque AC, et un
  second certificat à gérer.
- **Granian** : rapide et capable de mTLS, mais sans transmission du certificat client à l'application et sans mTLS
  facultatif ; les deux sont indispensables à EST.
- **Serveur TLS écrit à la main** : inutile, Uvicorn fait l'essentiel.

## Conséquences

- Le protocole personnalisé hérite d'une classe **interne** d'Uvicorn : la version d'Uvicorn est épinglée, et les
  scénarios de l'expérience deviennent des tests de non-régression du lanceur (`docs/testing.md`).
- HTTP/1.1 seulement (protocole `h11`).
- Le *channel binding* `tls-unique` d'EST reste non supporté.
- Un seul processus et pas de workers multiples : cohérent avec l'ADR-0001 et les tâches planifiées.

## Mise en œuvre (phase 1.1, 2026-11-22)

Décisions inchangées ; précisions apportées par l'implémentation (`src/h42pki/server/`) :

- **Uvicorn** épinglé `>=0.54,<0.55` ; Granian retiré des dépendances et de l'image.
- **Clé sur disque** : pour rester dans la règle « une clé ne sort du keystore que chiffrée » (CLAUDE.md §6.2), le
  fichier temporaire contient la clé en **PKCS#8 chiffré** par un mot de passe à usage unique gardé en mémoire
  (`KeyStore.export_encrypted`), et `load_cert_chain(..., password=…)` la déchiffre. Le dossier reste `0700`, les
  fichiers `0600`, supprimés aussitôt.
- **Base et lifespan** : le lanceur ouvre la base lui-même et lance Uvicorn avec `lifespan="off"` (deux listeners
  exécuteraient sinon deux fois le lifespan) ; `create_app(manage_database=False)`.
- **Adresse du client** : Uvicorn tourne avec `proxy_headers=False`, sinon `X-Forwarded-For` aurait pu faire passer
  un client pour un proxy de `H42_PKI_TRUSTED_PROXIES`.
- **Répartition des routes** : le protocole pose `scope["extensions"]["h42pki.listener"]` sur les deux listeners, et
  un middleware ASGI unique (`api/listener.py`) applique la règle, `/docs` et `/openapi.json` compris (HTTPS
  seulement). Sans l'extension, tout répond : mode réservé aux tests.
- **Redémarrage d'un listener** : le nouveau contexte TLS est construit avant l'arrêt de l'ancien listener (s'il
  échoue, l'ancien reste) ; les connexions ouvertes ont 5 secondes pour se terminer.
- **Santé** : le battement est un fichier du dossier temporaire nommé d'après l'URL de la base, écrit toutes les
  10 secondes et supprimé à l'arrêt, plutôt qu'une ligne en base (pas d'écriture permanente dans SQLite) ;
  `h42pki healthcheck` exige un battement de moins de 60 secondes.
- **Signaux** : SIGINT et SIGTERM par `loop.add_signal_handler`, `signal.signal` sous Windows ; Uvicorn n'installe
  pas ses propres gestionnaires.
- **Développement** : `h42pki serve --reload` relance tout le processus lanceur avec `watchfiles.run_process` (le
  rechargement d'Uvicorn ne sait relancer qu'une application, pas le lanceur).
- **Environnement** : sous WSL1, SQLite en mode WAL ne se partage pas entre deux processus (B42) ; WSL2, Docker et
  Windows ne sont pas concernés.
