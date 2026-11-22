# ADR-0001 — Un conteneur = une AC = un niveau

- **Statut** : proposé
- **Date** : 2026-11-21

## Contexte

Le projet vise une hiérarchie d'AC construite en assemblant des conteneurs identiques. Une alternative serait un
serveur multi-AC unique hébergeant toute la hiérarchie.

## Décision

Chaque conteneur porte **une seule AC active** (plus ses générations précédentes pendant un rollover). La hiérarchie
se construit en reliant des conteneurs par le protocole de fédération. Tous exécutent la même image ; le rôle vient
de la configuration (`authority.mode`).

> **Précision (2026-11-22)** : le rôle n'est pas un réglage. Il est choisi une fois pour toutes par
> `h42pki authority init` (racine au lot 5a ; fille et externe en phase 2). La configuration est en base (ADR-0011).

## Alternatives considérées

- **Serveur multi-AC** : plus simple à déployer, mais la clé racine vit dans le même processus et la même base que les
  AC émettrices exposées sur Internet/LAN ; impossible d'arrêter la racine seule.

## Conséquences

- Isolation forte : la racine peut être arrêtée ou placée sur un hôte séparé.
- Le modèle de données garde une table `Authority` (locale, mère, filles) mais une seule `local` active.
- Il faut un protocole inter-conteneurs (ADR-0003) et gérer la publication de la CRL d'une racine arrêtée.
- Un seul processus/worker par conteneur en v1 (tâches planifiées dans le lifespan).
