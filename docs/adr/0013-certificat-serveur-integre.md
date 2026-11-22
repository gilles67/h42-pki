# ADR-0013 — Certificat du serveur HTTPS émis par l'AC locale

- **Statut** : accepté
- **Date** : 2026-11-22

## Contexte

Avec HTTP et HTTPS intégrés (ADR-0012), chaque conteneur a besoin d'un certificat pour son listener HTTPS. Le plus
simple, et le plus cohérent pour une PKI, est que l'AC du conteneur l'émette elle-même et le renouvelle sans
intervention.

## Décision

- Dès que l'AC locale est `active`, elle s'émet un certificat pour son serveur HTTPS avec un **profil interne
  `service_tls`** :
  - écrit en base comme les profils intégrés (ADR-0009), mais **non utilisable** par `/api/v1/requests` ni par les
    protocoles d'enrôlement, et absent de `issuance.disabled_profiles` (couper le HTTPS se fait par
    `H42_PKI_HTTPS_ENABLED=false`) ;
  - KU `digitalSignature` (+ `keyEncipherment` si RSA), EKU `serverAuth`, AIA comme les autres certificats ;
  - CN = `H42_PKI_SERVER_HOSTNAME` ; SAN = ce nom, puis `H42_PKI_SERVER_ALT_NAMES` (ADR-0011).
- La clé est générée par le keystore (`PrivateKey.purpose = tls`) et stockée en base, comme les autres clés.
- **Validité de 47 jours, renouvellement quand il reste 15 jours ou moins** (soit au 32e jour en temps normal). Le
  calcul part de la date d'expiration du certificat en service, et non d'un compteur : il résiste à un conteneur
  arrêté plusieurs jours ou à une réémission manuelle. Les deux valeurs sont des réglages `hot`
  (`tls_service.validity_days`, `tls_service.renew_before_days`).
- En cas d'échec, nouvelle tentative chaque jour, avec un avertissement dans le journal et dans `/health`.
- Au démarrage, si les SAN du certificat en service diffèrent de `H42_PKI_SERVER_HOSTNAME` +
  `H42_PKI_SERVER_ALT_NAMES`, le certificat est réémis **avant** l'ouverture du port HTTPS.
- Chaque émission produit une entrée `AuditLog` (`certificate.issue`, `channel = system`).

### Notice : les AC racine et intermédiaires

Par souci de simplicité, **toute AC du projet, même racine ou intermédiaire, et donc même sans le rôle de fournir
des certificats serveur, s'émet un certificat serveur** : uniquement pour son propre serveur HTTPS, avec le profil
interne `service_tls`. C'est un écart volontaire et limité au principe « une racine ne signe que des AC ». Il évite
de devoir fournir un certificat de l'extérieur à certains conteneurs et garde une règle unique pour tous.

## Alternatives considérées

- **Certificat fourni de l'extérieur** pour la racine et les intermédiaires : plus orthodoxe, mais il faudrait un
  mécanisme d'import, un suivi d'expiration manuel et une règle différente selon le rang de l'AC.
- **Certificat auto-signé pour le serveur** : aucun client ne pourrait le valider via la chaîne de la PKI.

## Conséquences

- Tout client qui fait confiance à la racine de la hiérarchie valide le HTTPS de n'importe quel conteneur, ce qui
  sert directement la fédération (une fille vérifie sa mère).
- Le nom sous lequel les autres conteneurs joignent celui-ci (par exemple le nom du service `docker compose`) doit
  figurer dans `H42_PKI_SERVER_ALT_NAMES`, sinon la vérification TLS échoue entre conteneurs.
- C'est la première tâche planifiée du projet (`tasks/`), avant celles des CRL.

## Mise en œuvre (phase 1.1, 2026-11-22)

Décisions inchangées ; précisions apportées par l'implémentation :

- **Même chemin d'émission** : `IssuanceService.issue_service_certificate` (interne, absente de l'API) génère une clé
  **EC P-256** (rapide, acceptée partout), construit le CSR, enregistre une demande sur le canal `system`
  (`requester = system`), puis passe par le même `_issue` que tout autre certificat ; la clé est stockée dans la même
  transaction que le certificat. Profil interne : 47 jours par défaut, 200 au plus (SC-081v3), CN = premier nom.
- **Réémission** (`core/service_tls.py`) : aucun certificat, expiré, CN ou ensemble des SAN différents des
  variables, ou `renew_before_days` jours ou moins restants.
- **Attente de l'AC** : le lanceur regarde toutes les 5 secondes si l'AC est active ; la tâche quotidienne prend le
  relais une fois le HTTPS ouvert. Un changement des réglages `tls_service.*` déclenche une vérification immédiate,
  ce qui permet de forcer un renouvellement sans commande dédiée.
- **HTTPS désactivé** (`H42_PKI_HTTPS_ENABLED=false`) : aucun certificat n'est émis.
- **Limites connues** : les anciennes clés et anciens certificats restent en base (B44, purge en phase 3) ; tant que
  les certificats n'ont ni CDP ni OCSP (phase 3), les clients Windows qui exigent une information de révocation
  refusent ce HTTPS (B41).
