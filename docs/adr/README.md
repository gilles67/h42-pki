# Architecture Decision Records

| # | Titre | Statut |
|---|---|---|
| [0001](0001-un-conteneur-une-ac.md) | Un conteneur = une AC = un niveau | proposé |
| [0002](0002-tortoise-et-couches.md) | Tortoise ORM et découpage en couches core / services / api | proposé |
| [0003](0003-protocole-federation-dedie.md) | Protocole de fédération dédié plutôt qu'EST entre AC | proposé |
| [0004](0004-abstraction-keystore.md) | Toute signature passe par un keystore abstrait (préparation PKCS#11) | proposé |
| [0005](0005-tls-par-reverse-proxy.md) | TLS et mTLS terminés par un reverse-proxy | proposé |
| [0006](0006-snake-case-json.md) | snake_case pour les champs JSON de l'API et de la configuration | accepté |
| [0007](0007-pas-de-migration-avant-release.md) | Pas de migration de base avant la première release | accepté |
| [0008](0008-api-admin-sans-authentification.md) | API d'administration sans authentification jusqu'à la première release | accepté |
| [0009](0009-profils-integres-lecture-seule.md) | Profils intégrés en lecture seule, approbation par profil | accepté |
| [0010](0010-seul-auto-signe-racine.md) | Le seul certificat auto-signé est celui de l'AC racine | accepté |

Nouvelle décision : copier `0000-template.md`, numéro suivant, mettre à jour ce tableau.
