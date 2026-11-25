# ADR-0016 — Podman, moteur de conteneurs de référence

- **Statut** : accepté
- **Date** : 2026-11-25

## Contexte

Le projet a été conçu et documenté avec Docker (image, `docker compose`, `docker exec`). Le 2026-11-25, l'image et
la hiérarchie d'exemple ont été validées sur Debian 13 avec **Podman 5.4.2 rootless** et podman-compose 1.3.0
(`deploy/smoke-test.sh` et `deploy/bootstrap.sh`), à deux écarts près : `docker compose up --wait` n'existe pas dans
podman-compose, et Podman ignore `HEALTHCHECK` dans une image au format OCI. Le mainteneur choisit de privilégier
Podman pour la suite du projet.

## Décision

- **Podman rootless est le moteur de conteneurs de référence** : documentation, exemples, scripts de `deploy/`,
  tests d'interopérabilité et environnement de test multi-instances.
- **Docker reste compatible** : l'image est une image standard, et les scripts acceptent Docker sans modification de
  code (choix du moteur par une variable de script, pas par une variable `H42_PKI_*`).
- **Format de l'image** : construite avec `podman build --format docker` (ou `BUILDAH_FORMAT=docker` pour
  podman-compose), sinon `HEALTHCHECK` est perdu. Le fichier reste nommé `Dockerfile`, que Podman lit sans
  difficulté.
- **Compose** : `podman-compose` (≥ 1.3) sur `deploy/compose.yaml`, sans fonctionnalité propre à Docker Compose v2
  (pas de `up --wait` : attente explicite dans les scripts). Docker Compose v2 reste utilisable.
- **Rootless** :
  - publier des ports ≥ 1024 côté hôte dans les exemples (`-p 127.0.0.1:8080:8080 -p 127.0.0.1:8443:8443`) ; pour
    80 et 443, abaisser `net.ipv4.ip_unprivileged_port_start` ou placer un redirecteur devant, au choix de
    l'exploitant ;
  - `loginctl enable-linger <utilisateur>` pour que les conteneurs et leurs vérifications de santé survivent à la
    fin de la session.
- **Secrets** : secrets de conteneur (`podman secret` ou `secrets:` de compose), montés dans `/run/secrets/` ; le
  mécanisme `*_FILE` de l'ADR-0011 est inchangé.

## Alternatives considérées

- **Rester sur Docker** : plus répandu, mais démon root et environnement de test du projet sous Podman.
- **Podman seul, sans compatibilité Docker** : inutilement restrictif, l'image et compose.yaml sont standards.

## Conséquences

- Scripts `deploy/*.sh` et `Makefile` à adapter (moteur par défaut `podman`, `docker` en option).
- Les exemples de la documentation utilisent `podman run` / `podman exec` / `podman-compose`.
- Déploiement durable sous Podman : unités systemd **Quadlet** (`.container`) à documenter avec le runbook
  d'exploitation (phase 7).
- Les mentions historiques de Docker (expérience TLS du 2026-11-22, lots 0 et 1) sont conservées telles quelles.
