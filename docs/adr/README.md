# Architecture Decision Records

| # | Titre | Statut |
|---|---|---|
| [0001](0001-un-conteneur-une-ac.md) | Un conteneur = une AC = un niveau | proposé |
| [0002](0002-tortoise-et-couches.md) | Tortoise ORM et découpage en couches core / services / api | proposé |
| [0003](0003-protocole-federation-dedie.md) | Protocole de fédération dédié plutôt qu'EST entre AC | accepté |
| [0004](0004-abstraction-keystore.md) | Toute signature passe par un keystore abstrait (préparation PKCS#11) | proposé |
| [0005](0005-tls-par-reverse-proxy.md) | TLS et mTLS terminés par un reverse-proxy | **remplacé** par 0012 |
| [0006](0006-snake-case-json.md) | snake_case pour les champs JSON de l'API et de la configuration | accepté |
| [0007](0007-pas-de-migration-avant-release.md) | Pas de migration de base avant la première release | accepté |
| [0008](0008-api-admin-sans-authentification.md) | API d'administration sans authentification jusqu'à la première release | accepté |
| [0009](0009-profils-integres-lecture-seule.md) | Profils intégrés en lecture seule, approbation par profil (complété : activation des profils) | accepté |
| [0010](0010-seul-auto-signe-racine.md) | Le seul certificat auto-signé est celui de l'AC racine | accepté |
| [0011](0011-configuration-en-base.md) | Configuration en base, variables d'environnement limitées au démarrage | accepté |
| [0012](0012-http-https-integres.md) | HTTP et HTTPS intégrés au conteneur (lanceur maison Uvicorn) | accepté |
| [0013](0013-certificat-serveur-integre.md) | Certificat du serveur HTTPS émis par l'AC locale | accepté |
| [0014](0014-python-3-13.md) | Passage à Python 3.13 | accepté |
| [0015](0015-federation-invitations.md) | Fédération : invitations, épinglage et approbation | accepté |
| [0016](0016-podman-moteur-de-reference.md) | Podman, moteur de conteneurs de référence | accepté |
| [0017](0017-revocation.md) | Révocation : CRL et OCSP choisis à la création de l'AC | accepté |
| [0018](0018-est.md) | EST : protocoles d'enrôlement désactivés par défaut, comptes, relance, serverkeygen | accepté |

Nouvelle décision : copier `0000-template.md`, numéro suivant, mettre à jour ce tableau.
