# OCSP

Références : RFC 6960 (OCSP), RFC 5019 (profil léger / cache, requêtes GET), RFC 8954 (nonce).
Décision : ADR-0017 (OCSP optionnel choisi à la création de l'AC, signé par l'AC, cache). **Implémenté en phase 3.**

## 1. Endpoints

| Méthode | Chemin | Entrée | Sortie |
|---|---|---|---|
| POST | `/ocsp` | corps DER (≤ 64 Kio), `Content-Type: application/ocsp-request` | `application/ocsp-response` |
| GET | `/ocsp/{requête}` | DER encodé **base64 standard** puis URL-encodé (RFC 6960 annexe A.1) ; `/` et `+` acceptés bruts ou encodés | `application/ocsp-response` |

- Servis en HTTP et en HTTPS, sans authentification. L'URL inscrite dans l'AIA des certificats est
  `{public_base_url}/ocsp`, seulement pour une AC créée avec `h42pki authority init --ocsp` (désactivé par défaut,
  immuable) et une `public_base_url`.
- Un seul répondeur par conteneur : il répond pour l'AC locale courante (active ou révoquée par sa mère) et ses
  générations `rolling_over` / `retired` créées avec `--ocsp`, en identifiant l'émetteur par `issuerNameHash` +
  `issuerKeyHash`.
- AC locale créée sans `--ocsp` (ou absente) → **404** `application/problem+json` sur `/ocsp`.

## 2. Traitement

1. Parser avec `x509.ocsp.load_der_ocsp_request` (`core/ocsp.py`). Requête vide, trop grande, illisible, base64
   invalide, CertID dans un hachage non pris en charge, ou **plusieurs CertID** → `responseStatus = malformedRequest`.
   Vérifié (spike de la phase 3, `cryptography` 48) : plusieurs CertID lèvent `NotImplementedError`.
2. Retrouver l'AC émettrice en comparant les hachages (SHA-1 **et** SHA-256 acceptés, SHA-384 et SHA-512 aussi).
   Émetteur inconnu → `responseStatus = unauthorized`.
3. Statut du certificat (`serial_number`, cherché parmi les certificats de cet émetteur) :
   - trouvé, `valid` ou `expired` → `good` ;
   - trouvé, `revoked` → `revoked` (+ `revocation_time`, `revocation_reason` sauf `unspecified`) ;
   - non trouvé → `unknown` (**jamais** `good` pour un numéro jamais émis ; le CertID de la requête est recopié par
     `add_response_by_hash`).
4. Nonce (RFC 8954) : s'il est présent (1 à 32 octets, sinon `malformedRequest`), il est recopié dans la réponse ; une
   réponse avec nonce n'est jamais mise en cache.
5. Réponse : `this_update` = maintenant, `next_update` = maintenant + `ocsp.response_validity_hours` (24, `hot`), sans
   dépasser le `next_update` de la CRL courante si l'AC a une CRL (jamais dans le passé).

Pas de suspension : un certificat révoqué l'est définitivement.

## 3. Répondeur

**Signature directe par la clé de l'AC** (ADR-0017) : `responder_id` = hachage SHA-1 de la clé de l'AC, certificat de
l'AC dans `certificates`, hachage de signature selon la clé (SHA-256 RSA / P-256, SHA-384 P-384, Ed25519). Pas de
répondeur délégué : le profil `ocsp_signer` reste émissible mais ne sert pas ici. Avec une clé sur PKCS#11 (phase 7),
ce choix sera revu (ADR-0004).

## 4. Cache

- Réponses **sans nonce** en mémoire (`OcspCache`, sur l'application) par (AC, numéro de série, algorithme du CertID),
  10 000 entrées au plus, réutilisées jusqu'à mi-validité (`now < this_update + validité / 2`).
- Le statut du certificat est relu en base à chaque requête ; une réponse en cache n'est réutilisée que si ce statut
  (statut, date et motif de révocation) n'a pas changé. Une révocation faite par la CLI, dans un autre processus,
  est donc vue immédiatement ; `RevocationService` vide aussi les entrées concernées dans le processus du serveur.
- En-têtes pour GET (RFC 5019 §6.2) : `Cache-Control: max-age=<next_update − now>, public, no-transform,
  must-revalidate`, `Last-Modified`, `Expires`, `ETag` (SHA-256 de la réponse). POST, réponses avec nonce et erreurs :
  `Cache-Control: no-store`.
- Une requête avec nonce provoque toujours une signature par la clé de l'AC (risque accepté, B54).

## 5. Contrôle par une AC fille de son propre statut

`services/parent_check.py` (tâche quotidienne, première exécution une minute après le démarrage, et
`h42pki authority check-parent`) :
- URL : AIA OCSP du certificat de l'AC locale (inscrit par la mère) ; CertID SHA-1, nonce de 16 octets ; en https, TLS
  vérifié avec l'AC mère épinglée (ADR-0015) ; ni proxy d'environnement ni redirection ;
- la réponse doit être signée par l'AC mère elle-même ; CertID, nonce, `this_update` et `next_update` vérifiés
  (5 minutes de tolérance) ;
- `revoked` → l'AC locale et son certificat passent `revoked` (date et motif de la réponse), audit
  `authority.revoked_by_parent`, erreur dans le journal ; toute émission est ensuite refusée (503) ; CRL et OCSP de
  l'AC restent servis ;
- `unknown`, mère injoignable (`unreachable`), pas d'OCSP (`no_ocsp`, AIA absent ou 404), réponse invalide
  (`invalid_response`) → avertissement, aucun changement d'état ;
- le résultat est enregistré sur l'AC (`parent_check_result`, `parent_check_at`) et affiché par `authority status`
  et `GET /health`.

## 6. Tests

- Unitaires (`tests/unit/core/test_ocsp.py`) : `good` / `revoked` (motif) / `unknown` ; `unauthorized` et
  `malformedRequest` (illisible, deux CertID — fixture produite par `openssl ocsp -serial 1 -serial 2`, nonce de 33
  octets) ; nonce recopié ; CertID SHA-1 et SHA-256 ; signature vérifiable (RSA, P-256, P-384, Ed25519) ;
  `next_update` borné par la CRL ; vérification d'une réponse côté fille.
- Intégration (`tests/integration/test_ocsp.py`) : POST et GET (base64 avec `/` et `+`, encodés ou non), cache
  réutilisé puis invalidé par une révocation (API et autre processus), régénération à mi-validité, en-têtes RFC 5019,
  404 sans OCSP. `tests/integration/server/test_parent_check.py` : mère réelle en sous-processus (`good`, `revoked` puis
  émission refusée, mère injoignable, mère sans OCSP).
- Interop : `openssl ocsp -reqout` / `-reqin -respin` avec et sans nonce (`tests/interop/test_openssl.py`) ;
  `openssl ocsp -issuer -cert -url -CAfile` sur la hiérarchie Podman (`deploy/revocation-test.sh`).
