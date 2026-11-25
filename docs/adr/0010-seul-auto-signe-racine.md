# ADR-0010 — Le seul certificat auto-signé est celui de l'AC racine

- **Statut** : accepté
- **Date** : 2026-11-21

## Contexte

Jusqu'au lot 4, l'API permettait de préparer un certificat (`POST /api/v1/certificates`) puis de l'auto-signer
(`POST /api/v1/certificates/{id}/self-sign`), avec une durée de validité paramétrable. Ce chemin servait à fabriquer
une AC racine faute de mieux. Avec l'AC locale (`Authority`) et l'émission depuis un CSR, il devient un second chemin
de création de certificats, hors profils et hors `Authority`.

## Décision

- Une AC racine **naît uniquement** par `h42pki authority init` (`AuthorityService.init_root`) : nouvelle clé (une clé
  = une AC), certificat de la racine construit par `core.issuance.build_self_signed`, `Authority(kind=local,
  status=active)`, le tout dans une transaction avec audit.
- La durée de validité de la racine se règle par **`--validity-days`** (3650 jours par défaut, de 1 à 10950), avec les
  constantes de `core/validity.py`. Le `path_length` est optionnel (absent = pas de limite).
- Tout autre certificat est signé par l'AC via **`IssuanceService`** (demande + profil). C'est le seul chemin
  d'émission.
- `POST /api/v1/certificates` et `POST /api/v1/certificates/{id}/self-sign` sont **supprimés** (404/405), ainsi que le
  statut de certificat `pending` : un certificat est toujours enregistré déjà signé.

## Alternatives considérées

- **Garder l'auto-signature par API** pour les tests ou des usages ponctuels : un certificat d'entité finale
  auto-signé n'a pas d'usage dans ce projet, et une racine créée hors `Authority` ne pourrait rien émettre.
- **Initialiser la racine par API** : sans authentification (ADR-0008), n'importe qui pourrait créer l'AC d'un
  conteneur vierge. La CLI (`podman exec` ou `docker exec`) suppose un accès à l'hôte.

## Conséquences

- Il n'existe plus que deux producteurs de certificats : `init_root` et `IssuanceService`.
- Les tests de racine passent par `AuthorityService.init_root` et la CLI.
- Les modes `subordinate` et `external` (phase 2) ajouteront leurs propres sous-commandes d'`authority init`.
