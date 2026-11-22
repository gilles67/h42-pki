# EST — Enrollment over Secure Transport

Références : RFC 7030, RFC 8951 (clarifications : encodage base64, en-tête `Content-Transfer-Encoding`).

## 1. Endpoints

Préfixe `/.well-known/est/` ; un **label** optionnel sélectionne le profil : `/.well-known/est/{label}/simpleenroll`.
Sans label → `est.default_profile`.

| Méthode | Opération | Entrée | Sortie (succès) | Obligatoire |
|---|---|---|---|---|
| GET | `cacerts` | — | `application/pkcs7-mime` : PKCS#7 *certs-only* base64 (AC locale + chaîne) | oui |
| POST | `simpleenroll` | `application/pkcs10` : CSR DER base64 | 200 `application/pkcs7-mime; smime-type=certs-only` base64 | oui |
| POST | `simplereenroll` | idem | idem | oui |
| GET | `csrattrs` | — | `application/csrattrs` base64 (attributs attendus par le profil), ou 204 | v1.1 |
| POST | `serverkeygen` | `application/pkcs10` | `multipart/mixed` : clé `application/pkcs8` + certificat | optionnel (désactivé par défaut) |
| POST | `fullcmc` | — | 501 | non supporté |

Notes d'encodage (RFC 8951) : corps **toujours** en base64 ; accepter les sauts de ligne et l'absence de
`Content-Transfer-Encoding` ; émettre `Content-Transfer-Encoding: base64` pour la compatibilité.
Demande en attente (approbation manuelle du profil) → `202 Accepted` + `Retry-After`.

## 2. Authentification

EST exige TLS : ses routes n'existent que sur le listener **HTTPS** intégré (ADR-0012).
- **Certificat client lu directement** dans la connexion TLS : mTLS **facultatif** (`CERT_OPTIONAL`), le certificat
  et sa chaîne vérifiée arrivent dans `scope["extensions"]["tls"]`. Un client sans certificat peut donc utiliser
  HTTP Basic sur le même port ; un certificat qui ne remonte pas à une ancre de confiance fait échouer la poignée de
  main.
- **Derrière un reverse-proxy** (facultatif) : le certificat client transmis dans l'en-tête `Client-Cert`
  (RFC 9440) n'est pris en compte que si la requête vient d'un réseau listé dans `H42_PKI_TRUSTED_PROXIES` ;
  sinon l'en-tête est ignoré.
- Ancres de confiance pour les certificats clients : la chaîne de l'AC locale, plus `est.client_trust_anchors`.

| Opération | Méthodes acceptées |
|---|---|
| `cacerts`, `csrattrs` | aucune |
| `simpleenroll` | certificat client émis par une AC listée dans `est.client_trust_anchors` **ou** HTTP Basic (`EnrollmentCredential.kind = est_basic`) |
| `simplereenroll` | certificat client **obligatoire**, valide, non révoqué, émis par cette AC ; le CSR doit reprendre le même sujet et les mêmes SAN (RFC 7030 §4.2.2) |

Échec d'authentification → `401` avec `WWW-Authenticate: Basic realm="h42pki-est"`.
Le *channel binding* `tls-unique` (RFC 7030 §3.5) n'est pas supporté en v1 (ni en TLS direct, ni derrière un proxy).

## 3. Implémentation

- `api/est/routes.py` : décodage base64 → `x509.load_der_x509_csr` → `IssuanceService.submit(channel="est")`
  (même chemin d'émission que l'API, profils désactivés compris, ADR-0009).
- Sortie : `pkcs7.serialize_certificates([cert], serialization.Encoding.DER)` puis base64.
  Pour `cacerts` : certificats de l'AC et de ses ascendants.
- `serverkeygen` : clé générée par le keystore (purpose `serverkeygen`), renvoyée en PKCS#8 **non chiffré** uniquement
  dans la session TLS (option RFC 7030 §4.4.2) ; **non conservée** après la réponse, sauf `est.archive_server_keys`.
- Erreurs : 400 (CSR illisible ou refusé par le profil, message texte court), 401, 403 (profil interdit pour cette
  identité), 503 (AC non active).

## 4. Tests

- Unitaires : décodage base64 tolérant (sauts de ligne, CRLF) ; sérialisation certs-only relisible avec
  `pkcs7.load_der_pkcs7_certificates`.
- Intégration : enrôlement Basic sans certificat client ; réenrôlement avec certificat client présenté en TLS (via
  le lanceur, comme dans l'expérience `docs/spikes/2026-11-tls-launcher.md`) ; réenrôlement avec en-tête
  `Client-Cert` depuis un proxy de confiance ; **même en-tête sans `H42_PKI_TRUSTED_PROXIES`, ou depuis une IP non
  listée → ignoré, donc 401** ; réenrôlement avec sujet différent → 400 ; label inconnu → 404 ; routes EST
  inexistantes sur le listener HTTP.
- Interop : `curl` + `openssl` (`curl --data-binary @csr.b64 -H 'Content-Type: application/pkcs10' -u user:pass
  https://…/.well-known/est/simpleenroll | base64 -d | openssl pkcs7 -inform DER -print_certs`) ;
  optionnellement `estclient` (libest) dans le compose d'interop.
