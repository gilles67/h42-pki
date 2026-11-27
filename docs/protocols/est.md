# EST — Enrollment over Secure Transport

Références : RFC 7030, RFC 8951 (clarifications : encodage base64, en-tête `Content-Transfer-Encoding`).
Décision : ADR-0018. **Implémenté en phase 4.**

## 1. Activation et endpoints

EST est **désactivé par défaut** : tant que `est.enabled` est faux (`h42pki config set est.enabled true`, niveau
`hot`), **toutes** les routes `/.well-known/est/…` répondent `404`. HTTPS seulement (ADR-0012) : rien en HTTP.

Préfixe `/.well-known/est/` ; le **label** est un nom de profil : `/.well-known/est/{profil}/simpleenroll`. Sans
label → `est.default_profile` (vide par défaut : `404` « no default EST profile »). Le profil interne `service_tls`
n'est pas un label.

| Méthode | Opération | Entrée | Sortie (succès) | Authentification |
|---|---|---|---|---|
| GET | `cacerts` | — | `application/pkcs7-mime; smime-type=certs-only` base64 : AC locale + ascendants | aucune |
| POST | `simpleenroll` | CSR PKCS#10 DER base64 | 200 certs-only base64, ou 202 + `Retry-After` | Basic ou certificat client |
| POST | `simplereenroll` | idem | idem | certificat client seulement |
| GET | `csrattrs` | — | `application/csrattrs` base64, ou 204 | aucune |
| POST | `serverkeygen` | CSR PKCS#10 DER base64 | 200 `multipart/mixed` (clé `application/pkcs8` + certificat), ou 202 | Basic ou certificat client |
| POST | `fullcmc` | — | 501 | — |

Encodage : corps base64, sauts de ligne, CRLF et espaces tolérés, `Content-Transfer-Encoding` facultatif (RFC 8951) ;
les réponses portent `Content-Transfer-Encoding: base64`, en lignes de 76 caractères terminées par LF (le
`base64 -d` de GNU coreutils refuse CR ; les parties MIME gardent CRLF). Corps limité à 64 Kio.

## 2. Comptes et authentification

- **Comptes EST** (`EnrollmentCredential`, `kind = est_basic`) : API `/api/v1/est/accounts` (`POST`, `GET`,
  `GET /{username}`, `POST /{username}/disable|enable`, `POST /{username}/password`, `DELETE /{username}`) et CLI
  `h42pki est account create|list|show|disable|enable|reset-password|delete`. Mot de passe choisi (8 à 1024
  caractères, par l'entrée standard en CLI : `--password -`) ou généré (24 caractères, montré une seule fois). Hachage
  scrypt (N 2^15, r 8, p 3), compte désactivé ou expiré refusé. Un compte peut demander **tout profil non désactivé**.
  Audit `est.account.*`, jamais de mot de passe.
- **Certificat client** : lu dans la connexion TLS (mTLS facultatif, `scope["extensions"]["tls"]`) ou dans l'en-tête
  `Client-Cert` (RFC 9440) **seulement** depuis `H42_PKI_TRUSTED_PROXIES`. Dans les deux cas, l'application le
  **revérifie** (B45, `services/client_auth.py`) : émis **directement** par une AC locale (courante, révoquée par sa
  mère ou génération précédente), dans sa période de validité, connu en base et non révoqué ; ou émis directement par
  une ancre de `server.client_trust_anchors` (validité seulement). Un EKU sans `clientAuth` est refusé, comme le fait
  OpenSSL à la poignée de main (spike de la phase 4 : un `tls_server` y échoue, « unsuitable certificate purpose »).
- Les ancres TLS du listener (toute la chaîne de l'AC locale + `server.client_trust_anchors`) sont plus larges : un
  certificat émis par l'AC mère passe la poignée de main mais est refusé ici (`401`).
- Identité enregistrée (`requester`, acteur d'audit) : `est:<compte>` ou `est-cert:<SHA-256 du certificat>`.
- Échec → `401` + `WWW-Authenticate: Basic realm="h42pki-est"`, message générique. Pas de *channel binding*
  `tls-unique`.

## 3. Émission, approbation, relance

- `IssuanceService.submit(channel = est)` : même chemin que l'API (ADR-0010), mêmes règles de profil, troncature de
  validité, profils désactivés (`403`).
- Profil en approbation manuelle → `202` + `Retry-After: est.retry_after_seconds` (60). Le client **renvoie la même
  requête** : la demande est retrouvée par (identité, SHA-256 du CSR, opération), sans en créer d'autre :
  `pending` → `202` ; `issued` → `200` avec le même certificat (une nouvelle demande s'il a été révoqué ou a expiré) ;
  `rejected` → `403` « the request was rejected: <motif> » ; `failed` → `503`.
- Audit `est.enroll`, `est.reenroll`, `est.serverkeygen` (identité, profil, demande, SHA-256 du CSR), en plus de
  `request.*` et `certificate.issue`.

## 4. Réenrôlement (RFC 7030 §4.2.2)

`simplereenroll` exige un certificat client émis par une AC locale, valide et non révoqué (Basic seul → `401`). Le
profil est celui de ce certificat (label différent → `400`). Le CSR reprend **exactement** le sujet (DER) et
l'ensemble des SAN ; `ChangeSubjectName` (`id-cmc-changeSubjectName`) est refusé (`400`). Nouvelle clé ou même clé.
L'ancien certificat n'est pas révoqué. Audit `est.reenroll` avec le numéro de série de l'ancien. En pratique :
certificats `tls_client` et `device` (EKU `clientAuth`).

## 5. `csrattrs` (RFC 7030 §4.5)

`CsrAttrs ::= SEQUENCE OF AttrOrOID`, ici seulement des OID (DER écrit à la main, `core/est.py`) : les attributs de
sujet requis par le profil (`commonName`…), et `subjectAltName` si le profil exige des SAN. `204` si le profil
n'impose rien (aucun profil intégré aujourd'hui).

## 6. `serverkeygen` (RFC 7030 §4.4)

- Authentification comme `simpleenroll`. Le CSR ne donne que le sujet et les SAN ; l'algorithme est celui de sa clé si
  le profil l'admet, sinon le premier admis par le profil.
- La clé est générée par le keystore **à l'émission** (immédiate, ou à `request approve` ; `202` d'ici là), le CSR est
  reconstruit avec elle (`core/csr.rebuild_csr`, sujet et SAN seulement), puis émis par `IssuanceService`. La clé est
  **conservée chiffrée** (`PrivateKey.purpose = serverkeygen`, liée au certificat).
- Réponse `multipart/mixed` (frontière aléatoire, `Cache-Control: no-store`) : partie `application/pkcs8` (PKCS#8 DER
  non chiffré, base64, `KeyStore.export_for_enrollment`), puis partie certs-only.
- **Remise unique** : une relance après remise, ou après suppression de la copie, répond `409`. Audit
  `est.serverkeygen.deliver`, sans la clé.
- Suppression de la copie : `DELETE /api/v1/certificates/{id}/private-key` (`204` ; `404` sans clé ; `409` pour une
  clé d'AC ou `service_tls`) et `h42pki certificate delete-key ID`. `GET /api/v1/certificates/{id}` indique
  `has_stored_private_key`. **Aucune route ne relit la clé.**
- Risque : la base et la passphrase donnent aussi les clés non supprimées (ADR-0018).

## 7. Erreurs

Texte brut (`text/plain`), jamais `problem+json` : `400` (base64 ou CSR illisible, refus du profil avec le motif,
réenrôlement qui change l'identité), `401`, `403` (profil désactivé, demande rejetée), `404` (EST désactivé, label ou
opération inconnus, pas de profil par défaut), `405` (mauvaise méthode, `Allow`), `409` (clé déjà remise ou
supprimée), `501` (`fullcmc`), `503` (pas d'AC active, AC révoquée, passphrase absente).

## 8. Tests

- Unitaires : `tests/unit/core/test_passwords.py` (scrypt, temps d'un compte inconnu), `tests/unit/core/test_est.py`
  (base64 tolérant, certs-only, `CsrAttrs` relu par un petit décodeur, `multipart/mixed` relu par `email`).
- Intégration : `test_est_accounts.py` (API et CLI), `test_est.py` (désactivé par défaut, labels, Basic, 401, 403,
  relances, rejet, idempotence, `Client-Cert` d'un proxy de confiance, B45), `test_est_reenroll.py`,
  `test_est_serverkeygen.py`, `server/test_est_tls.py` (vrai certificat client en TLS, rien en HTTP).
- Interop : `deploy/est-test.sh` après `deploy/bootstrap.sh` (curl + openssl), et avec `ESTCLIENT=…` le client
  `estclient` de `github.com/globalsign/est` (v1.0.6, construit dans une image `golang` avec `CGO_ENABLED=1`) :
  `cacerts`, `enroll`, `csrattrs`, `reenroll` (mTLS), `serverkeygen`.
