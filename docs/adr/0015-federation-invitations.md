# ADR-0015 — Fédération : invitations, épinglage et approbation

- **Statut** : accepté
- **Date** : 2026-11-25

## Contexte

L'ADR-0003 choisit un protocole dédié pour qu'une AC fille fasse signer son certificat par sa mère, avec une
invitation à usage unique et sans secret long terme. Restaient à fixer : la forme de l'invitation et son stockage, la
façon dont la fille vérifie une mère qu'elle ne connaît pas, qui approuve, et comment l'inscription rejoint le chemin
d'émission unique (ADR-0010). L'API d'administration n'a pas d'authentification jusqu'à la release (ADR-0008).

## Décision

### Invitation et jeton
- Table dédiée **`FederationInvitation`** (et non `EnrollmentCredential`, réservée à EST, SCEP et ACME) : une
  invitation porte les contraintes d'une AC (`path_length`, `validity_days`, `auto_approve`) et est liée à **une** demande.
- Jeton `h42fed_<id>.<secret>`, secret de 32 octets aléatoires en base64url, renvoyé **une seule fois** à la création.
- On stocke le **SHA-256** du secret, comparé en temps constant. Argon2 ou scrypt ne protègent que les secrets
  devinables ; avec 256 bits d'entropie, ils ne feraient que ralentir chaque appel.
- Durée de vie 7 jours par défaut, 30 au plus : elle borne la **première** utilisation. Ensuite, le jeton ne donne
  accès qu'à **sa** demande, jusqu'à 24 h après la décision.
- Un jeton inutilisable (absent, malformé, inconnu, expiré, révoqué, déjà utilisé pour une autre demande) reçoit
  toujours **la même réponse 401**.
- `enroll` est **idempotent** : même jeton, même CSR, même nom et même URL renvoient l'état courant. Une réponse
  perdue se redemande donc sans nouvelle invitation.

### Inscription = `CertificateRequest`
- Profil `sub_ca`, canal `federation`, même chemin que toute émission. L'invitation est consommée dans la transaction
  qui enregistre la demande ; un CSR, un nom ou un profil refusé ne la consomme pas.
- `path_length` effectif = `min(invitation, mère - 1)`, sans limite si les deux sont nuls ; refus si la mère a
  `pathLen = 0`. L'invitation **remplace** le `path_length = 0` du profil, qui interdirait toute AC intermédiaire ;
  `POST /api/v1/requests` garde 0. La validité ne peut que raccourcir celle du profil.
- L'`Authority(kind=child)` est créée avec son certificat, dans la même transaction.

### Approbation
Choisie **par invitation** (`auto_approve`, faux par défaut), et non par le profil. Les décisions manuelles passent par
`/api/v1/requests/{id}/approve|reject` ou `h42pki request …`.

### Épinglage
- Avec l'invitation, la fille reçoit l'empreinte SHA-256 du **certificat de l'AC mère**. Elle télécharge
  `/ca/chain.pem` sans pouvoir vérifier TLS (seul appel dans ce cas, rien n'est envoyé), vérifie l'empreinte puis la
  cohérence de la chaîne.
- Tous les appels suivants vérifient TLS avec l'AC mère comme **seule** ancre et le nom d'hôte de l'URL. Le contexte
  TLS de Python 3.13 active `VERIFY_X509_PARTIAL_CHAIN` (une AC intermédiaire suffit comme ancre) et
  `VERIFY_X509_STRICT` ; le code les pose explicitement et des tests les couvrent. Proxys d'environnement et
  redirections sont ignorés.
- Le certificat reçu est contrôlé (clé, sujet, signature de la mère, CA, `pathLen`, validité) avant l'activation.

### Côté fille
- Le jeton n'est jamais stocké. L'URL, l'empreinte, l'identifiant de l'inscription et le **CSR** le sont : une
  signature ECDSA n'est pas déterministe, le CSR ne peut donc pas être reconstruit à l'identique.
- Un refus définitif du premier envoi, un rejet ou un échec supprime l'AC en attente et sa clé, jamais certifiées. Une
  erreur réseau la garde (`--resume`) ; `h42pki authority abandon` permet d'y renoncer.

## Risque accepté

Tant que l'API n'est pas authentifiée (ADR-0008), **quiconque atteint le port HTTPS peut créer une invitation
auto-approuvée, donc une AC fille**, capable d'émettre des certificats acceptés par tous ceux qui font confiance à la
racine. Les mesures compensatoires de l'ADR-0008 s'appliquent donc pleinement : port publié sur `127.0.0.1` ou réseau
de conteneurs interne, aucune vraie AC. L'authentification reste un prérequis bloquant de la release.

## Alternatives considérées

- **`EnrollmentCredential(kind=federation_token)`** : la moitié des colonnes ne servirait qu'à un seul des usages.
- **Empreinte du certificat TLS** de la mère : il est renouvelé tous les 32 jours environ (ADR-0013).
- **Réponses 401 détaillées** : plus commodes, mais elles diraient à un inconnu quelles invitations existent.
- **Jeton par variable d'environnement** : la liste est fermée (ADR-0011) ; `--token -` lit l'entrée standard.

## Conséquences

- La révocation d'une AC fille marque son certificat et son `Authority` ; les clients ne la verront qu'avec les CRL et
  l'OCSP (phase 3), comme le contrôle par la fille de son propre statut.
- Le nom d'une AC fille révoquée reste pris.
- Le certificat d'AC ne porte pas de nom h42-pki : la fille nomme ses ascendants `<slug du CN>-<empreinte>`.
