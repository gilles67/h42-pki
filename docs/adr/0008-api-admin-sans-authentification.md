# ADR-0008 — API d'administration sans authentification jusqu'à la première release

- **Statut** : accepté
- **Date** : 2026-11-21

## Contexte

L'architecture prévoit des jetons Bearer hachés en base, avec des portées, pour l'API d'administration (ARCHITECTURE
§8.4). Pendant le développement, cette couche ralentirait les tests et les essais manuels sans protéger de données
réelles : aucune AC de production n'existe avant la première release (ADR-0007).

## Décision

- L'**API d'administration** (`/api/v1/...` et les routes legacy de `h42pki/api/admin.py`) n'a **aucune
  authentification** jusqu'à la première release. On n'ajoute ni jeton statique, ni dépendance `require_admin`
  provisoire.
- Les mécanismes d'authentification **propres aux protocoles** ne sont pas concernés et s'implémentent avec leur
  protocole, parce qu'ils en font partie : JWS des comptes ACME, challenge password SCEP, invitation de la
  fédération, Basic ou certificat client pour EST.
- Les routes d'administration sont écrites de façon à pouvoir recevoir une dépendance d'authentification
  sans être réécrites : toutes sur un même `APIRouter`, et l'identité de l'appelant passée explicitement aux services
  (`actor="anonymous"` pour l'`AuditLog` d'ici là).
- Implémenter l'authentification de l'API d'administration est un **prérequis bloquant de la première release**.

## Mesures compensatoires (obligatoires tant que la décision est en vigueur)

- `h42pki serve` écoute par défaut sur `127.0.0.1`.
- Le port du conteneur n'est publié qu'en local (`-p 127.0.0.1:8000:8000`) ou sur un réseau Docker interne, jamais sur
  une interface accessible depuis le LAN ou Internet.
- Aucune vraie AC (clé racine de production) n'est créée avec une version sans authentification.

## Conséquences

- Développement et tests plus simples.
- Risque assumé : toute personne qui atteint le port peut générer des clés et émettre des certificats d'AC.
- Claude Code ne doit pas ajouter d'authentification sur l'API d'administration avant ce jalon.
