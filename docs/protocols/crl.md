# CRL et publication AIA

Références : RFC 5280 §5 (CRL), §4.2.1.13 (CRLDistributionPoints), §4.2.2.1 (AuthorityInformationAccess).

## 1. Endpoints

| Chemin | Content-Type | Contenu |
|---|---|---|
| `GET /crl/{authority}.crl` | `application/pkix-crl` | CRL complète courante, **DER** |
| `GET /crl/{authority}-delta.crl` | `application/pkix-crl` | CRL delta (si `crl.delta_enabled`) |
| `GET /ca/{authority}.crt` | `application/pkix-cert` | Certificat de l'AC, DER (cible de l'AIA caIssuers) |
| `GET /ca/{authority}.pem` | `application/x-pem-file` | Idem en PEM |
| `GET /ca/chain.pem` | `application/x-pem-file` | AC locale active + ascendants, **racine incluse** (pas de réglage) |

- Servis en **HTTP** (pas de redirection vers HTTPS), sans authentification, hors de `/api/v1` (tag OpenAPI
  `public`). Aucune requête ne déclenche d'opération sur une clé privée.
- **Implémenté (lot 5b) pour `/ca/*`** : `ETag = "<sha256_fingerprint>"` (empreinte SHA-256 du DER ; pour
  `chain.pem`, SHA-256 du corps), `Last-Modified = not_before` (le plus récent pour la chaîne),
  `Cache-Control: public, max-age=3600`, `If-None-Match` (liste, `W/`, `*`) → `304` sans corps. Nom inconnu → 404,
  aucune AC active → 503 sur `chain.pem` (`application/problem+json`).
- **Prévu pour `/crl/*`** (phase 3) : `Cache-Control: public, max-age=<jusqu'au prochain renouvellement>`,
  `Last-Modified = thisUpdate`, `ETag = sha256(der)`.
- `{authority}` = `Authority.name` d'une AC **locale** active, en cours de rollover ou `retired` (pour que les
  certificats émis avant un rollover restent vérifiables). Le nom est restreint à `[a-z0-9-]` (64 caractères) et
  `chain` est réservé.
- URL inscrite dans l'AIA caIssuers des certificats émis : `{public_base_url}/ca/{authority}.crt`, seulement si
  `Authority.public_base_url` est renseignée (`h42pki authority init|update --public-base-url`) et si le profil a
  `include_aia` ; jamais dans le certificat de la racine.
- URL inscrite dans les certificats émis : `{public_base_url}/crl/{authority}.crl`.

## 2. Contenu de la CRL

Construite par `core/crl.py` avec `x509.CertificateRevocationListBuilder` :

- `issuer_name` = sujet de l'AC, `last_update` = maintenant, `next_update` = maintenant + `crl.validity_hours`.
- Extensions de CRL : `CRLNumber` (monotone, persistant, jamais réutilisé, y compris entre CRL complète et delta),
  `AuthorityKeyIdentifier` ; pour la delta : `DeltaCRLIndicator(base_crl_number)` ; la complète annonce la delta via
  `FreshestCRL` si activée.
- Entrées : chaque certificat `revoked` ou `on_hold` de l'AC, avec `CRLReason` (omise si `unspecified`)
  et `InvalidityDate` si connue.
- Un certificat révoqué **et expiré** peut être retiré de la CRL complète (`crl.keep_expired = false` par défaut) ;
  en delta, un certificat sorti de `certificateHold` apparaît avec la raison `removeFromCRL`.
- Signature par l'AC via `keystore` (algorithme cohérent avec la clé : SHA-256 pour RSA/P-256, SHA-384 pour P-384,
  aucun hash pour Ed25519).

## 3. Régénération

`CrlService.ensure_fresh(authority)` génère une nouvelle CRL si :
1. aucune CRL n'existe ;
2. `now ≥ next_update − crl.regenerate_before_hours` ;
3. une révocation / suspension / levée de suspension a eu lieu depuis la dernière CRL (appel direct par `RevocationService`).

La tâche périodique (`tasks/crl.py`) appelle `ensure_fresh` toutes les 15 min pour chaque AC locale non `retired` dont
au moins un certificat n'a pas expiré. L'endpoint sert toujours la dernière CRL stockée — il ne génère jamais
à la volée (pas de signature déclenchée par une requête anonyme).

## 4. Tests

- Unitaires (`core/crl.py`) : CRL vide ; CRL avec révocations et raisons ; `CRLNumber` croissant ; delta avec
  `DeltaCRLIndicator` ; signature vérifiable (`crl.is_signature_valid(ca_public_key)`) ; certificat expiré retiré.
- Intégration : révoquer via l'API → la CRL servie contient le numéro de série, `CRLNumber` a augmenté ; `ETag`/304.
- Interop : `openssl crl -inform DER -noout -text`, `openssl verify -crl_check -CRLfile` sur un certificat révoqué
  (doit échouer) et non révoqué (doit réussir).
