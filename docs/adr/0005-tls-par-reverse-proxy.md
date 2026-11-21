# ADR-0005 — TLS et mTLS terminés par un reverse-proxy

- **Statut** : proposé
- **Date** : 2026-11-21

## Contexte

EST et la fédération exigent HTTPS, et EST a besoin du certificat client (mTLS). CRL, AIA, OCSP et SCEP doivent
rester accessibles en HTTP. L'accès au certificat client depuis une application ASGI dépend du serveur
(Uvicorn ne l'expose pas de façon standard ; Granian : à vérifier).

## Décision

En v1, un reverse-proxy (Traefik dans le compose fourni ; Caddy/nginx documentés) termine TLS et mTLS, et transmet
le certificat client à l'application dans l'en-tête `X-Client-Cert` (PEM URL-encodé). L'application **ignore** cet
en-tête si l'adresse source n'appartient pas à `server.trusted_proxies`, et le proxy doit **supprimer** tout en-tête
`X-Client-Cert` entrant.

## Alternatives considérées

- TLS direct dans le serveur ASGI : moins de composants, mais dépendance à un serveur précis et gestion des
  certificats TLS du serveur dans l'application.

## Conséquences

- Pas de *channel binding* `tls-unique` pour EST (documenté comme non supporté).
- Le certificat TLS du proxy peut lui-même être obtenu par ACME auprès de l'AC émettrice.
- Test d'intégration obligatoire : en-tête forgé depuis une IP non fiable → refusé.
