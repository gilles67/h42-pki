# Expérience : lanceur HTTP + HTTPS et certificat client (2026-11-22)

Expérience **autonome**, menée hors du dépôt (dossier `h42-tls-spike`, non versionné ici), pour valider deux
hypothèses avant l'ADR-0012 :

1. un lanceur maison peut exécuter, dans **un seul processus**, un listener HTTP et un listener HTTPS sur la même
   application ASGI, démarrer le HTTPS après coup et **recharger le certificat à chaud** ;
2. le **certificat client** (mTLS, indispensable pour EST) peut arriver jusqu'à l'application, avec Uvicorn ou avec
   Granian.

## Montage

- PKI jetable générée avec `cryptography` : AC de confiance, certificat serveur (SAN `localhost`, `127.0.0.1`),
  certificat client, et un client signé par une **AC inconnue**.
- Application ASGI minimale sans framework : `GET /whoami` renvoie ce que l'application voit de la connexion, en
  particulier `scope["extensions"]["tls"]` ; `GET /admin` n'est servi qu'en HTTPS.
- **Uvicorn** : deux `uvicorn.Server` dans une boucle asyncio, `SSLContext` fourni par `ssl_context_factory`
  (TLS 1.2 minimum, `CERT_OPTIONAL`), et sous-classe de `H11Protocol` qui, après la poignée de main, enveloppe
  l'application pour ajouter l'extension ASGI `tls` (certificat client, chaîne vérifiée par
  `SSLObject.get_verified_chain()`, version TLS). Certificat et clé chargés depuis la mémoire via un dossier
  temporaire privé supprimé aussitôt.
- **Granian** : CLI avec `--ssl-certificate`, `--ssl-keyfile`, `--ssl-ca`, `--ssl-client-verify`, et sonde du mode
  embarqué (`granian.server.embed.Server`).

## Résultats (exécution Docker du 2026-11-22, Python 3.13.18, uvicorn 0.54.0, granian 2.8.9, cryptography 50.0.2)

| # | Scénario | Résultat |
|---|---|---|
| U1 | HTTP démarre seul, avant tout certificat serveur | PASS |
| U2 | HTTPS fermé tant qu'il n'y a pas de certificat | PASS |
| U3 | HTTPS démarre dès que le certificat existe (sans redémarrage) | PASS |
| U4 | HTTP : schéma `http`, pas d'extension `tls` | PASS |
| U5 | Séparation des routes : `/admin` refusé en HTTP | PASS |
| U6 | Séparation des routes : `/admin` servi en HTTPS | PASS |
| U7 | HTTPS sans certificat client accepté (mTLS facultatif) | PASS |
| U8 | Certificat client de confiance visible dans `scope["extensions"]["tls"]` (`CN=spike-client`) | PASS |
| U9 | Chaîne vérifiée du client transmise (feuille + AC, Python ≥ 3.13) | PASS |
| U10 | Certificat client d'une AC inconnue refusé | PASS |
| U11 | Renouvellement à chaud : les nouvelles connexions reçoivent le nouveau certificat | PASS |
| U12 | Une connexion ouverte avant le renouvellement continue de fonctionner | PASS |
| U13 | Les deux ports sont servis par un seul processus | PASS |
| U14 | Arrêt propre des deux serveurs sur SIGTERM | PASS |
| G1 | Granian `--ssl-client-verify` : client **sans** certificat | **refusé** (`certificate required`) : mTLS obligatoire |
| G2 | Granian : certificat client visible par l'application ? | **NON** (extensions : `http.response.pathsend`, `websocket.http.response` ; pas de `tls`) |
| G3 | Granian : certificat d'une AC inconnue refusé | PASS |
| G4 | Granian sans `--ssl-client-verify`, certificat présenté : visible ? | **NON** |
| G5 | Granian mode embarqué : HTTP + HTTPS dans un seul processus | OUI |

Un contrôle croisé avec `openssl s_client` (certificat client présenté) a donné la même réponse que le scénario U8.

## Conclusions

- **Uvicorn + lanceur maison** répond à tous les besoins : deux listeners dans un processus, démarrage différé,
  rechargement à chaud, mTLS facultatif, certificat client et chaîne transmis à l'application.
- **Granian** est écarté : il ne transmet pas le certificat client à l'application et ne sait faire que du mTLS
  obligatoire. Les deux sont indispensables à EST (réenrôlement par certificat, enrôlement par Basic sur le même
  port).
- Points d'attention repris dans l'ADR-0012 :
  - le protocole personnalisé hérite d'une classe **interne** d'Uvicorn : version épinglée, scénarios U1 à U14
    repris comme tests de non-régression ;
  - `get_verified_chain()` n'existe qu'à partir de Python 3.13 (en 3.12, seul le certificat feuille), d'où
    l'ADR-0014 ;
  - le module `ssl` ne charge un certificat que depuis des fichiers : passage par un dossier temporaire `0700`
    (clé `0600`) supprimé juste après le chargement ;
  - HTTP/1.1 seulement (protocole `h11`).
- Non testé, à vérifier lors de l'implémentation (niveau `listener` par prudence dans l'ADR-0011) : modification à
  chaud de la version TLS minimale, ajout à chaud d'une ancre de confiance client, passage à chaud du mTLS
  facultatif à obligatoire.
