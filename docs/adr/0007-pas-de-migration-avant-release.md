# ADR-0007 — Pas de migration de base avant la première release

- **Statut** : accepté
- **Date** : 2026-11-21

## Contexte

Les modèles Tortoise vont beaucoup changer pendant les phases 1 à 6 : renommages snake_case (ADR-0006), clés
étrangères, nouvelles tables pour les protocoles. Maintenir une chaîne de migrations pendant cette période coûterait
cher pour un bénéfice nul, puisque aucune donnée réelle n'existe encore.

## Décision

- **Jusqu'à la première release** (premier tag de version destiné à être déployé avec des données à conserver), le
  schéma est créé par `generate_schemas=True` au démarrage. Aucune migration n'est écrite.
- Toute modification de modèle est autorisée sans compatibilité ascendante. Après un changement de schéma, il suffit
  de supprimer la base locale (`data/h42pki.sqlite3*`).
- La mise en place des migrations est un **prérequis bloquant de la première release** (jalon « Release » de
  `docs/roadmap.md`) : choix de l'outil (Aerich ou mécanisme natif de Tortoise 1.x, à vérifier), migration initiale
  générée depuis le schéma final, `generate_schemas` réservé aux tests ensuite, test de migration en CI.

## Alternatives considérées

- Migrations dès le lot 3 : des dizaines de migrations intermédiaires sans valeur, et un frein aux refactorings.

## Conséquences

- Les bases créées avant la release sont jetables : ne pas y stocker de vraie AC.
- Claude Code ne doit pas créer de fichiers de migration ni de code de compatibilité de schéma avant ce jalon.
