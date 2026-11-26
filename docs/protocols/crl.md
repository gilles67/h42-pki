# CRL et publication AIA

Références : RFC 5280 §5 (CRL), §4.2.1.13 (CRLDistributionPoints), §4.2.2.1 (AuthorityInformationAccess).
Décision : ADR-0017 (CRL optionnelle choisie à la création de l'AC, une CRL complète, pas de delta ni de suspension).
**Implémenté en phase 3.**

## 1. Endpoints

| Chemin | Content-Type | Contenu |
|---|---|---|
| `GET /crl/{authority}.crl` | `application/pkix-crl` | CRL complète courante, **DER** |
| `GET /ca/{authority}.crt` | `application/pkix-cert` | Certificat de l'AC, DER (cible de l'AIA caIssuers) |
| `GET /ca/{authority}.pem` | `application/x-pem-file` | Idem en PEM |
| `GET /ca/chain.pem` | `application/x-pem-file` | AC locale courante + ascendants, **racine incluse** (pas de réglage) |
| `GET /api/v1/crl` (HTTPS) | `application/json` | Métadonnées de la CRL de l'AC locale : `authority`, `crl_number`, `this_update`, `next_update`, `entries`, `url` ; 404 sans CRL |

- `/ca/*` et `/crl/*` sont servis en **HTTP** et en HTTPS (pas de redirection), sans authentification, hors de
  `/api/v1` (tag OpenAPI `public`). **Aucune requête ne déclenche d'opération sur une clé privée** : `/crl/*` sert la
  dernière CRL stockée.
- `/ca/*` : `ETag = "<sha256_fingerprint>"` (empreinte SHA-256 du DER ; pour `chain.pem`, SHA-256 du corps),
  `Last-Modified = not_before` (le plus récent pour la chaîne), `Cache-Control: public, max-age=3600`,
  `If-None-Match` (liste, `W/`, `*`) → `304` sans corps. Nom inconnu → 404, aucune AC → 503 sur `chain.pem`
  (`application/problem+json`).
- `/crl/*` : `ETag = sha256(der)`, `Last-Modified = thisUpdate`, `Cache-Control: public, max-age=<nextUpdate − maintenant>`,
  304. 404 (`problem+json`) si le nom n'est pas celui d'une AC locale, si l'AC a été créée sans `--crl`, ou si aucune
  CRL n'a encore été générée.
- `{authority}` = `Authority.name` d'une AC **locale** courante (active ou révoquée par sa mère), en cours de rollover
  ou `retired` (pour que les certificats émis avant un rollover restent vérifiables). Le nom est restreint à
  `[a-z0-9-]` (64 caractères) et `chain` est réservé.

## 2. URL inscrites dans les certificats émis

Seulement si `Authority.public_base_url` est renseignée (`h42pki authority init|update --public-base-url`), en
extensions **non critiques**, jamais dans le certificat de la racine :

| Extension | URL | Condition |
|---|---|---|
| AIA caIssuers | `{public_base_url}/ca/{authority}.crt` | profil avec `include_aia` (tous les profils intégrés) |
| CRLDistributionPoints | `{public_base_url}/crl/{authority}.crl` | AC créée avec `--crl` |
| AIA OCSP | `{public_base_url}/ocsp` | AC créée avec `--ocsp` (`docs/protocols/ocsp.md`) |

CDP et OCSP sont ajoutés quel que soit le profil, certificats d'AC filles et `service_tls` compris. `--crl` et
`--ocsp` se choisissent à `h42pki authority init` (racine et subordonnée), sont désactivés par défaut et ne changent
plus ensuite ; changer la `public_base_url` ne touche pas les certificats déjà émis.

## 3. Contenu de la CRL

Construite par `core/crl.py` (`build_crl`, pur) avec `x509.CertificateRevocationListBuilder` :

- `issuer_name` = sujet de l'AC, `last_update` = maintenant (à la seconde), `next_update` = maintenant +
  `crl.validity_hours`.
- Extensions : `CRLNumber` (monotone par AC, persistant, jamais réutilisé), `AuthorityKeyIdentifier` (dérivé du SKI de
  l'AC).
- Entrées : chaque certificat `revoked` de l'AC encore valide, avec `CRLReason` (omise si `unspecified`) et
  `InvalidityDate` si connue. Un certificat révoqué **et expiré** sort de la CRL.
- Signature par la clé de l'AC (hachage selon la clé : SHA-256 pour RSA et P-256, SHA-384 pour P-384, aucun pour
  Ed25519), vérifiée avant enregistrement.
- Stockée en DER dans `Crl` (`crl_number`, `this_update`, `next_update`, `entries_as_of`, `entries`) ; les anciennes
  sont conservées.

Pas de CRL delta, pas de suspension (`certificateHold`, `removeFromCRL`) : une révocation est définitive (ADR-0017).

## 4. Révocation et régénération

`RevocationService.revoke(certificat, motif, invalidity_date?, acteur)` (API `POST /api/v1/certificates/{id}/revoke`,
CLI `h42pki certificate revoke ID --reason … [--invalidity-date …]`, fédération) :
- motifs `x509.ReasonFlags` en snake_case, sauf `certificate_hold` et `remove_from_crl` (422) ; `invalidity_date`
  avec fuseau, jamais dans le futur ;
- 409 : déjà révoqué, certificat d'une AC locale, certificat `service_tls`, certificat non émis par une AC locale ;
- met à jour le certificat (et l'AC fille correspondante), audit `certificate.revoke`, puis **régénère la CRL** de
  l'émetteur et invalide le cache OCSP du processus ;
- si l'émetteur a une CRL et que la passphrase manque (CLI), refus **avant** toute modification.

`CrlService.ensure_fresh(authority)` génère une nouvelle CRL si :
1. aucune CRL n'existe ;
2. `maintenant ≥ next_update − crl.regenerate_before_hours` ;
3. une révocation est postérieure à la lecture des entrées de la dernière CRL (rattrape une génération échouée) ;
4. ou sur demande (révocation, `h42pki crl generate`).

La première CRL est publiée dès l'activation de l'AC (`authority init`). La tâche `crl` du lanceur
(`tasks/maintenance.py`) appelle `refresh_all` au démarrage puis toutes les 15 minutes pour l'AC locale courante
(active ou révoquée) et les AC `rolling_over` / `retired` qui ont encore des certificats non expirés.

Réglages (`hot`) : `crl.validity_hours` (168, au plus 8784), `crl.regenerate_before_hours` (48, inférieur à la
validité). Une racine rarement en ligne peut allonger la validité (par exemple 4380).

CLI : `h42pki crl show [--der]` (sans passphrase), `h42pki crl generate`.

## 5. Tests

- Unitaires (`tests/unit/core/test_crl.py`) : CRL vide ; motifs et `InvalidityDate` ; `unspecified` omis ;
  `CRLNumber` ; certificat expiré retiré ; signature vérifiable (RSA, P-256, P-384, Ed25519) ; motifs de suspension
  refusés.
- Intégration (`test_revocation.py`, `test_cli_revocation.py`, `test_tasks.py`) : révocation par l'API et la CLI, CRL
  régénérée, `ETag` / 304, 404 sans CRL, rattrapage par la tâche, échéance avec `time_machine`.
- Interop : `openssl crl -inform DER -text`, `openssl verify -crl_check -CRLfile` (révoqué refusé, valide accepté)
  dans `tests/interop/test_openssl.py` et `deploy/revocation-test.sh` (hiérarchie Podman, `-crl_check_all`).
