# ADR-0003 — Protocole de fédération dédié plutôt qu'EST entre AC

- **Statut** : accepté (mis en œuvre en phase 2, précisé par ADR-0015)
- **Date** : 2026-11-21

## Contexte

Une AC fille doit faire signer son certificat d'AC par sa mère. EST (`simpleenroll`) sait transporter un CSR et serait
réutilisable, mais l'inscription d'une AC demande davantage : contraintes (`pathLen`, NameConstraints) imposées par la
mère, approbation manuelle, enregistrement des métadonnées de la fille (URL publique, URL de fédération), épinglage
de la mère.

## Décision

Une API JSON dédiée `/api/v1/federation` (cf. `docs/protocols/federation.md`), authentifiée par **invitation à usage
unique** créée par un administrateur de la mère. Pas de secret long terme entre conteneurs en v1 : chaque
renouvellement d'AC fille passe par une nouvelle invitation.

> **Précision (2026-11-22)** : les échanges passent par le HTTPS intégré de la mère (ADR-0012), dont le certificat est
> émis par sa propre AC (ADR-0013). La fille le valide par la chaîne de la hiérarchie **et** par l'empreinte de la mère
> communiquée avec l'invitation. Il n'y a pas de mTLS entre conteneurs en v1.

## Alternatives considérées

- **EST entre AC** : standard, mais pas de place pour les métadonnées ni les contraintes ; il faudrait l'étendre de
  façon non standard.
- **Requêtes signées avec la clé de l'AC fille** : évite les jetons, mais utilise la clé d'AC pour signer autre chose
  que des certificats/CRL (mauvaise pratique) et complique le backend PKCS#11.
- **Certificat client de fédération** émis à la fille : envisageable en v2 si des opérations automatiques récurrentes
  apparaissent (ex. renouvellement automatique).

## Conséquences

- Simple et sûr pour un homelab : la signature d'une AC reste un acte délibéré d'administrateur.
- Le renouvellement d'une AC fille n'est pas entièrement automatique (acceptable : événement rare).
