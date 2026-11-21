# Fédération inter-AC (hiérarchie de conteneurs)

Protocole propre à h42-pki permettant à un conteneur « fille » d'obtenir son certificat d'AC auprès d'un conteneur
« mère ». Succède aux routes expérimentales `/api/pki/ca/request` et `/api/pki/ca/sign`, supprimées car non
authentifiées et dangereuses (bogues B2, B3).
Justification du choix d'un protocole dédié plutôt qu'EST : ADR-0003.

## 1. Principes

- **Aucun secret long terme** entre conteneurs en v1 : chaque inscription (et chaque renouvellement de l'AC fille)
  consomme une **invitation à usage unique** créée par un administrateur sur la mère.
- La mère **impose** les contraintes de l'AC fille (`pathLen`, NameConstraints, validité, sujet) via le profil `sub_ca`
  et les paramètres de l'invitation ; le CSR de la fille ne peut que les restreindre, jamais les élargir.
- La fille **vérifie** la mère : TLS validé par `parent.ca_bundle`, et empreinte SHA-256 du certificat de la mère
  communiquée avec l'invitation (épinglage).
- Les endpoints publics (chaîne, CRL, OCSP) de la mère restent accessibles sans authentification.

## 2. Séquence

```mermaid
sequenceDiagram
    actor Admin
    participant M as Conteneur mère
    participant F as Conteneur fille
    Admin->>M: POST /api/v1/federation/invitations {name, path_length, name_constraints, validity_days, auto_approve}
    M-->>Admin: {token (affiché une seule fois), parent_fingerprint, expires_at}
    Admin->>F: configure token + fingerprint (secret fichier)
    F->>F: génère clé AC + CSR (BasicConstraints CA, KU keyCertSign/cRLSign)
    F->>M: POST /api/v1/federation/enroll (Bearer token) {csr, name, public_base_url}
    M->>M: vérifie token, CSR, contraintes ; crée ChildAuthorityEnrollment
    alt auto_approve
        M->>M: IssuanceService.issue(profile=sub_ca)
        M-->>F: 201 {status: issued, certificate, chain}
    else approbation manuelle
        M-->>F: 202 {status: pending, enrollment_id} + Retry-After
        Admin->>M: POST /api/v1/federation/enrollments/{id}/approve
        F->>M: GET /api/v1/federation/enroll/{id} (Bearer token)
        M-->>F: 200 {status: issued, certificate, chain}
    end
    F->>F: valide certificat (clé = CSR, émetteur = mère, chaîne → ancre, empreinte épinglée)
    F->>F: Authority.status = active
```

## 3. Endpoints (côté mère)

| Méthode | Chemin | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/federation/invitations` | admin | Crée une invitation ; renvoie le jeton en clair **une seule fois** |
| GET | `/api/v1/federation/invitations` | admin | Liste (sans jetons) |
| DELETE | `/api/v1/federation/invitations/{id}` | admin | Révoque une invitation non utilisée |
| POST | `/api/v1/federation/enroll` | jeton d'invitation | Soumet le CSR de l'AC fille |
| GET | `/api/v1/federation/enroll/{id}` | jeton d'invitation | Statut / récupération du certificat (jeton invalidé après la première récupération réussie + délai de grâce) |
| GET | `/api/v1/federation/enrollments` | admin | Demandes en attente / traitées |
| POST | `/api/v1/federation/enrollments/{id}/approve` · `/reject` | admin | Décision manuelle |
| GET | `/api/v1/federation/children` | admin | AC filles connues (`Authority.kind = child`) |
| POST | `/api/v1/federation/children/{id}/revoke` | admin | Révoque le certificat d'une AC fille |
| GET | `/ca/chain.pem` | aucune | Chaîne de la mère jusqu'à la racine |

Format du jeton : `h42fed_<invitation_id>.<secret 32 octets base64url>`. Seul le hachage du secret est stocké
(`EnrollmentCredential.kind = federation_token`).

## 4. Contrôles côté mère

1. Jeton valide, non expiré, non consommé ; comparaison en temps constant.
2. `csr.is_signature_valid`, algorithme de clé autorisé par le profil `sub_ca`.
3. `path_length` effectif = `min(invitation.path_length, mère.path_length - 1)` ; refus si la mère a `pathLen = 0`.
4. NameConstraints : celles de l'invitation, qui doivent être un sous-ensemble de celles de la mère.
5. Validité ≤ `invitation.validity_days` et ≤ `mère.not_after`.
6. Sujet : `CN` fourni par la fille, autres attributs (`O`, `C`…) selon la politique du profil `sub_ca`.
7. Enregistrement `Authority(kind=child, parent=mère, public_base_url, …)` + `AuditLog`.

## 5. Côté fille

- CLI : `h42pki authority init` (mode `subordinate`) fait l'inscription puis, si `202`, interroge avec `Retry-After`.
  En démarrage conteneur, la même logique tourne dans le lifespan si l'AC est `uninitialized` et qu'un jeton est fourni.
- Tâche périodique : vérifie quotidiennement le statut de son propre certificat via l'OCSP de la mère (URL dans l'AIA).
  Si `revoked` → `Authority.status = revoked`, arrêt de toute émission, alerte dans les logs.
- Renouvellement : nouvelle invitation + `h42pki authority renew` (nouvelle clé recommandée, cf. ARCHITECTURE §8.3).

## 6. Racine hors ligne

Une racine peut être arrêtée entre deux signatures. Contraintes :
- CRL de la racine à longue validité (ex. `crl.validity_hours = 4380`, ~6 mois) et régénérée lors de chaque démarrage ;
- **Décision ouverte** : qui sert la CRL et le certificat de la racine quand elle est arrêtée ? Option proposée :
  `mirror_parent = true` sur l'AC fille, qui met en cache `/crl/{parent}.crl` et `/ca/{parent}.crt` et les sert
  sur sa propre `public_base_url` ; la racine utilise alors comme `public_base_url` un nom DNS pointant vers les filles.

## 7. Tests

- Unitaires : contrôles §4 (chaque refus a son test), format du jeton, validation de chaîne côté fille.
- Intégration : deux applications FastAPI dans le même test (mère + fille) reliées par `httpx.ASGITransport`
  — aucune socket réseau nécessaire.
- Interop : `docker compose` racine → intermédiaire → émettrice, puis `openssl verify -CAfile root.pem -untrusted chain.pem leaf.pem`.
