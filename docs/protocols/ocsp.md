# OCSP

Références : RFC 6960 (OCSP), RFC 5019 (profil léger / cache, requêtes GET), RFC 8954 (nonce).

## 1. Endpoints

| Méthode | Chemin | Entrée | Sortie |
|---|---|---|---|
| POST | `/ocsp` | corps DER, `Content-Type: application/ocsp-request` | `application/ocsp-response` |
| GET | `/ocsp/{requête}` | DER encodé **base64 standard** puis URL-encodé (RFC 6960 annexe A.1) | `application/ocsp-response` |

L'URL inscrite dans l'AIA des certificats est `{public_base_url}/ocsp`. Un seul répondeur par conteneur ; il répond
pour toutes les AC locales (active, `rolling_over`, `retired`) en identifiant l'émetteur par `issuerNameHash` +
`issuerKeyHash`.

## 2. Traitement

1. Parser avec `x509.ocsp.load_der_ocsp_request`. Requête illisible → `responseStatus = malformedRequest`.
   **À vérifier** : `cryptography` ne gère qu'**une seule** `CertID` par requête (lève une erreur sinon) ;
   répondre `malformedRequest` dans ce cas, comportement accepté par les clients usuels (RFC 5019 : une seule requête).
2. Retrouver l'AC émettrice en comparant les hachages (`hash_algorithm` de la requête : SHA-1 **et** SHA-256 doivent
   être acceptés). Émetteur inconnu → `responseStatus = unauthorized`.
3. Statut du certificat (`serial_number`) :
   - trouvé, `valid` → `good` ;
   - trouvé, `revoked` / `on_hold` → `revoked` (+ `revocation_time`, `revocation_reason`) ;
   - non trouvé → `unknown` (ne **jamais** répondre `good` pour un numéro jamais émis).
4. Nonce : si la requête contient l'extension `OCSPNonce` (1 à 32 octets), la recopier dans la réponse ; une réponse
   avec nonce n'est pas mise en cache.
5. Réponse : `this_update` = maintenant, `next_update` = maintenant + `ocsp.response_validity_hours` (≤ `next_update`
   de la CRL courante), signée par le répondeur.

## 3. Répondeur

- `ocsp.responder = "delegated"` (défaut) : certificat dédié émis par chaque AC locale avec le profil `ocsp_signer`
  (EKU `id-kp-OCSPSigning`, extension `OCSPNoCheck`, KU `digitalSignature`, validité 30 jours), renouvelé
  automatiquement à J-7 par une tâche. La réponse inclut le certificat du répondeur (`certificates=[responder]`) et
  utilise `responder_id = HASH`.
- `ocsp.responder = "ca"` : signature directe par la clé de l'AC (plus simple, mais sollicite la clé de l'AC à chaque
  requête — déconseillé si clé sur PKCS#11).

## 4. Cache

- Les réponses **sans nonce** sont précalculables : cache mémoire par `(issuer, serial)` invalidé par
  `RevocationService` et à expiration ; régénération si `now > this_update + validity/2`.
- En-têtes pour GET (RFC 5019 §6) : `Cache-Control: max-age=<next_update − now>, public, no-transform, must-revalidate`,
  `Last-Modified`, `Expires`, `ETag`.

## 5. Tests

- Unitaires : `good` / `revoked` (avec raison) / `unknown` ; émetteur inconnu → `unauthorized` ; requête corrompue →
  `malformedRequest` ; nonce recopié ; CertID SHA-1 et SHA-256 ; signature vérifiable avec le certificat du répondeur.
- Intégration : POST et GET (base64 + URL-encodage, y compris `/` et `+`) ; invalidation du cache après révocation.
- Interop : `openssl ocsp -issuer ca.pem -cert leaf.pem -url http://…/ocsp -CAfile chain.pem -resp_text`
  (avec et sans `-no_nonce`).
