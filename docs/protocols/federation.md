# Fédération inter-AC (hiérarchie de conteneurs)

Protocole propre à h42-pki : un conteneur « fille » obtient son certificat d'AC auprès d'un conteneur « mère ».
**Implémenté en phase 2** ; révocation et contrôle du statut par la fille en phase 3 (ADR-0017). Décisions : ADR-0003 (protocole dédié) et ADR-0015 (invitations, épinglage, approbation).

## 1. Principes

- **Aucun secret long terme** entre conteneurs : chaque inscription consomme une **invitation à usage unique**. Un futur
  renouvellement d'AC fille en consommera une nouvelle.
- La mère **impose** `pathLen` et validité ; le CSR ne fournit que la clé et le sujet.
- L'approbation est choisie **par invitation** : manuelle par défaut, immédiate avec `auto_approve`.
- La fille vérifie la mère par **épinglage** de l'empreinte SHA-256 de son certificat d'AC, reçue avec l'invitation.
- Pas de mTLS entre conteneurs. Les routes `/api/v1/federation/*` n'existent qu'en HTTPS.
- Le nom d'hôte de l'URL de la mère doit figurer dans son certificat HTTPS (`H42_PKI_SERVER_HOSTNAME` ou
  `H42_PKI_SERVER_ALT_NAMES`, par exemple le nom du service compose).

## 2. Séquence

```mermaid
sequenceDiagram
    actor Admin
    participant M as Conteneur mère
    participant F as Conteneur fille
    Admin->>M: h42pki federation invite (ou POST /api/v1/federation/invitations)
    M-->>Admin: jeton (une seule fois), parent_fingerprint
    Admin->>F: h42pki authority init --parent-url … --parent-fingerprint … --token -
    F->>M: GET /ca/chain.pem (TLS non vérifié, rien n'est envoyé)
    F->>F: empreinte épinglée ? chaîne cohérente jusqu'à la racine ?
    Note over F,M: à partir d'ici, TLS vérifié avec l'AC mère épinglée
    F->>F: clé + CSR, AC locale pending_signature, ascendants enregistrés
    F->>M: POST /api/v1/federation/enroll (Bearer jeton) {csr_pem, name, public_base_url}
    M->>M: jeton, nom, CSR, contraintes ; CertificateRequest (sub_ca, canal federation)
    alt auto_approve
        M-->>F: 201 {status: issued, certificate_pem, chain_pem}
    else approbation manuelle
        M-->>F: 202 {status: pending, enrollment_id} + Retry-After
        Admin->>M: h42pki request approve ID (ou reject)
        F->>M: GET /api/v1/federation/enroll/{enrollment_id} (Bearer jeton)
        M-->>F: 200 {status: issued | rejected | failed, …}
    end
    F->>F: contrôle du certificat reçu, AC locale active
```

## 3. Côté mère

### Endpoints (HTTPS, erreurs `problem+json`, `Cache-Control: no-store`)

| Méthode | Chemin (`/api/v1/federation`) | Auth | Réponse |
|---|---|---|---|
| POST | `/invitations` `{label?, path_length?, validity_days?, auto_approve?, expires_in_hours?}` | aucune (ADR-0008) | 201 `{invitation, token, parent_fingerprint, parent_url, effective_path_length, expires_at}` ; 422, 503 |
| GET | `/invitations` · `/invitations/{id}` | aucune | sans jeton ; `status` `active\|used\|revoked\|expired` (calculé) |
| DELETE | `/invitations/{id}` | aucune | 200, invitation révoquée ; 409 si utilisée ou déjà révoquée |
| POST | `/enroll` `{csr_pem, name, public_base_url?}` | jeton | 201 `issued`, 202 `pending` + `Retry-After`, 200 si rejouée après un refus ; 401, 409 (nom pris), 422, 503 |
| GET | `/enroll/{enrollment_id}` | jeton | 200 `{status, enrollment_id, certificate_pem, chain_pem, reason}` ; 401 |
| GET | `/children` | aucune | AC filles |
| POST | `/children/{name}/revoke` `{reason}` | aucune | 200 ; 404, 409 si déjà révoquée |

`status` d'une inscription : `pending`, `issued`, `rejected`, `failed` (émission impossible après approbation).
Les décisions passent par `/api/v1/requests/{id}/approve|reject` ; une demande expose `invitation_id` et `child_name`.
`parent_url` est indicative : le port publié par le moteur de conteneurs peut différer.
Raisons de révocation : `unspecified`, `key_compromise`, `ca_compromise`, `affiliation_changed`, `superseded`,
`cessation_of_operation`.

### CLI
- `h42pki federation invite [--label] [--path-length] [--validity-days] [--auto-approve] [--expires-in-hours]` : le
  jeton seul sur **stdout**, le reste (empreinte, `pathLen` effectif, commande pour la fille) sur **stderr** ;
- `h42pki federation invitations | revoke-invitation ID | children | revoke-child NAME --reason …` ;
- `h42pki request list [--status] | show ID | approve ID | reject ID --reason …` (toutes les demandes).

### Contrôles
1. Jeton utilisable, sinon **toujours la même réponse 401**. `expires_at` borne la première utilisation ; ensuite, accès
   à sa seule demande jusqu'à 24 h après la décision.
2. Même CSR, nom et URL → état courant (idempotent) ; autre contenu → 401.
3. Nom valide (B37), ni déjà connu ni dans une inscription en attente (409) ; revérifié à l'approbation.
4. Profil `sub_ca` activé ; CSR signé, algorithme et sujet admis par le profil.
5. `path_length` effectif = `min(invitation, mère - 1)` ; refus si la mère a 0.
6. Validité ≤ invitation ≤ profil, ramenée au `not_after` de la mère.
7. `Authority(kind=child, parent=AC locale)` créée avec son certificat.

Audit : `federation.invite`, `federation.invitation_revoke`, `federation.enroll`, `federation.child_revoke`, plus les
entrées de demande et de certificat. Jamais le jeton.

## 4. Côté fille

`h42pki authority init --parent-url URL --parent-fingerprint SHA256 --token - --name … --common-name …
[--organization …] [--key-algorithm …] [--public-base-url …] [--crl] [--ocsp] [--wait-minutes 10]`

- `--token -` lit le jeton sur l'entrée standard (conseillé : un argument se voit dans `ps` et l'historique).
- `--validity-days` et `--path-length` sont refusés : la mère décide.
- `pending` : attente selon `Retry-After` (borné à 1–60 s) jusqu'à `--wait-minutes`, puis code de sortie **3** ;
  reprise par `h42pki authority init --resume --token -`.
- `rejected`, `failed`, ou refus 4xx du **premier** envoi : l'AC en attente, sa clé et ses ascendants sont supprimés.
- Erreur réseau, TLS ou 5xx, certificat reçu incohérent : l'AC en attente est gardée. `h42pki authority abandon` y renonce.
- Après l'activation, l'AC s'émet son certificat `service_tls` et le lanceur ouvre le HTTPS sans redémarrage.
- `/ca/chain.pem` publie l'AC locale, ses ascendants et la racine.

Enregistré sur la mère directe (`kind=parent`) : `federation_url`, `pinned_fingerprint`. Sur l'AC locale en attente :
`pending_enrollment_id`, `pending_csr_der`, vidés à l'activation. Jamais le jeton.

## 5. Révocation d'une AC fille (phase 3, ADR-0017)

- **Côté mère** : `federation revoke-child` / `POST /children/{name}/revoke` passe par `RevocationService` (comme
  `h42pki certificate revoke` sur le certificat de la fille) : certificat et `Authority` de la fille `revoked`, audit
  `certificate.revoke` et `federation.child_revoke`, CRL de la mère régénérée, cache OCSP invalidé. La passphrase est
  nécessaire si la mère publie une CRL.
- **Effet pour les clients** : visible dans la CRL et l'OCSP de la mère, si elle a été créée avec `--crl` / `--ocsp`
  (une chaîne vérifiée avec `-crl_check_all` est alors refusée).
- **Côté fille** : contrôle quotidien de son propre statut auprès de l'OCSP de sa mère (URL de l'AIA de son
  certificat, TLS épinglé si https), et immédiat par `h42pki authority check-parent` (`docs/protocols/ocsp.md` §5).
  `revoked` : la fille passe `revoked` et refuse toute émission (503), en continuant de publier sa CRL et de répondre
  en OCSP. Mère injoignable ou sans OCSP : avertissement dans le journal et dans `/health`, rien ne change.
- `--crl` et `--ocsp` se passent à `h42pki authority init --parent-url …` comme pour une racine ; `--resume` les
  garde. La première CRL de la fille est publiée dès son activation.

Reporté : renouvellement d'une AC fille (nouvelle invitation, nouvelle clé, ARCHITECTURE §8.3).
Hors périmètre : NameConstraints, mode `external`, mTLS entre conteneurs.

## 6. Racine hors ligne

Une racine peut être arrêtée entre deux signatures ; elle doit être **joignable en HTTPS** pendant une inscription.
Entre deux, elle peut tourner en mode « à vide » (ADR-0012) **seulement si elle a été créée sans `--crl` ni
`--ocsp`** : une AC avec révocation refuse le mode « à vide » (`h42pki serve`, code 2 ; `authority init` refusé de
même). C'est la réponse à l'ancienne décision ouverte n° 1 (ADR-0017) : pas de miroir de la CRL de la racine par ses
filles. Les certificats d'intermédiaires émis par une telle racine ne portent alors ni CDP ni OCSP.

Une racine qui doit publier une CRL reste en ligne (HTTP au moins) ; sa CRL peut avoir une longue validité
(`crl.validity_hours = 4380`, `crl.regenerate_before_hours = 720`).

## 7. Tests

Tortoise est global au processus : une mère et une fille ne peuvent pas avoir chacune leur base dans le même.

- `tests/unit/core/test_federation.py`, `test_chain.py` : jeton, contraintes, chaîne, certificat reçu.
- `tests/integration/test_federation_api.py`, `test_cli_federation.py` : la mère dans le processus du test.
- `tests/integration/test_subordinate.py` : la fille face à une mère simulée (réponses perdues, incohérentes, attente).
- `tests/integration/server/test_federation.py` : **mère réelle en sous-processus, en HTTPS**, pilotée par son API ;
  trois niveaux, avec une intermédiaire comme ancre épinglée.
- `tests/integration/server/test_parent_check.py` : contrôle du statut d'une fille face à une mère réelle.
- `tests/interop/test_compose.py` : `deploy/bootstrap.sh` puis `deploy/revocation-test.sh` (Podman par défaut, ADR-0016).
