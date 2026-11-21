# ADR-0009 — Profils intégrés en lecture seule, approbation par profil

- **Statut** : accepté
- **Date** : 2026-11-21

## Contexte

L'émission depuis un CSR (lot 5a) a besoin de profils : ce sont eux, et non le CSR, qui décident des extensions, de
la validité, des algorithmes admis et des parties du sujet et des SAN acceptées (CLAUDE.md §6.3). Il faut aussi
décider quelles demandes sont émises immédiatement et lesquelles attendent une décision humaine.

Pendant le développement, le schéma de base change librement (ADR-0007) et l'API d'administration n'a pas
d'authentification (ADR-0008) : ouvrir l'édition des profils par API permettrait à quiconque atteint le port
d'élargir ce que l'AC accepte de signer.

## Décision

- Les profils **intégrés** sont définis dans le code (`core/profiles.py`, `BUILTIN_PROFILES`) : `sub_ca`,
  `tls_server`, `tls_client`, `ocsp_signer`, `device`.
- Ils sont **écrits en base au démarrage** (lifespan, et chaque commande CLI) : créés s'ils manquent, **réalignés sur
  le code** s'ils ont été modifiés en base (entrées d'audit `profile.create` / `profile.realign`). Pas de migration.
- L'API (`GET /api/v1/profiles[/{name}]`) et la CLI (`h42pki profile list|show`) permettent seulement de les
  **consulter**. L'édition viendra plus tard (avec l'authentification et des profils non intégrés).
- Chaque profil porte **`auto_approve`** : vrai → la demande est émise à la soumission ; faux → elle reste `pending`
  jusqu'à `approve` / `reject`. `sub_ca` et `ocsp_signer` exigent une approbation manuelle ; `tls_server`,
  `tls_client` et `device` sont émis automatiquement.
- **`tls_server` suit le vote CA/Browser Forum SC-081v3** : 200 jours au plus depuis le 15 mars 2026, 90 jours par
  défaut. La baisse suivante (100 puis 47 jours) arrive avec ACME en phase 6.

## Alternatives considérées

- **Édition par API** : utile à terme, mais dangereuse sans authentification (ADR-0008) et source de divergence entre
  conteneurs d'une même hiérarchie.
- **Profils dans un fichier TOML** : configurables sans recompiler, mais il faudrait valider, versionner et
  documenter un format de plus, pour un bénéfice faible tant que les cinq profils couvrent les besoins.

## Conséquences

- Une modification de profil passe par le code et une revue ; le redémarrage suffit à l'appliquer.
- Le mécanisme d'approbation est en place pour les canaux à venir (EST, SCEP, ACME, fédération).
- Un profil intégré supprimé du code reste en base (il n'est plus réaligné) : à traiter quand l'édition existera.
