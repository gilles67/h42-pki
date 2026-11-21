# ADR-0002 — Tortoise ORM et découpage en couches core / services / api

- **Statut** : proposé
- **Date** : 2026-11-21

## Contexte

Le code a connu trois générations de persistance (fichiers bruts, JSON + TOML, Tortoise). La logique crypto est mêlée
aux accès base et aux routes, ce qui la rend difficile à tester.

## Décision

- Persistance : **Tortoise ORM** (async, cohérent avec FastAPI), SQLite par défaut, PostgreSQL possible.
- Couches : `api → services → (core, keystore, models)`. `core` est **pur et synchrone** (aucun import de Tortoise,
  FastAPI ou d'I/O) ; il reçoit et renvoie des objets `cryptography` et des dataclasses/Pydantic.
- Les modèles Tortoise ne sont jamais exposés directement par l'API.

## Alternatives considérées

- **SQLAlchemy 2 async + Alembic** : plus mature pour les migrations, mais changement de cap par rapport au travail
  déjà engagé et au souhait du mainteneur.
- **Garder un stockage fichiers** : pas de transactions, pas de requêtes (CRL, OCSP, ACME).

## Conséquences

- `core` testable en unitaire sans base, ce qui porte l'essentiel de la couverture.
- Les appels crypto coûteux sont faits via `asyncio.to_thread` depuis `services`.
- Mécanisme de migrations à confirmer (Aerich ou natif Tortoise 1.x).
