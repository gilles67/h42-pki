# SCEP — Simple Certificate Enrollment Protocol

Référence : RFC 8894. Cible : équipements réseau, bornes Wi-Fi, MDM (Intune, Jamf…), clients `sscep`.
C'est le protocole le plus délicat côté crypto (CMS imbriqués) : à faire **après** EST.

## 1. Endpoint

`/scep` et `/scep/{profile}` ; le suffixe historique `/scep/pkiclient.exe` est accepté.
Paramètres de requête : `operation` (obligatoire), `message` (pour GET).
Servi en HTTP (la sécurité repose sur CMS, pas sur TLS).

| `operation` | Méthode | Réponse |
|---|---|---|
| `GetCACaps` | GET | `text/plain`, une capacité par ligne : `POSTPKIOperation`, `SHA-256`, `SHA-512`, `AES`, `SCEPStandard`, `Renewal`, `GetNextCACert` (si rollover en cours) |
| `GetCACert` | GET | Avec RA : `application/x-x509-ca-ra-cert`, PKCS#7 certs-only DER (AC + RA [+ chaîne]). Sans RA : `application/x-x509-ca-cert`, certificat DER |
| `GetNextCACert` | GET | `application/x-x509-next-ca-cert` (SignedData) — seulement pendant un rollover |
| `PKIOperation` | POST (corps DER, `application/x-pki-message`) ou GET (`message` base64) | `application/x-pki-message` |

## 2. Messages PKIOperation

Structure d'une requête : **SignedData** (signé par la clé du demandeur, avec certificat auto-signé ou certificat
existant pour un renouvellement) → contenu = **EnvelopedData** chiffré pour le **certificat RA** → contenu = CSR PKCS#10
(ou `IssuerAndSerial` pour `GetCert`/`GetCRL`, `IssuerAndSubject` pour `CertPoll`).

Attributs authentifiés (OID `2.16.840.1.113733.1.9.x`) :

| Attribut | OID | Usage |
|---|---|---|
| `messageType` | `.2` | `19` PKCSReq, `17` RenewalReq, `20` CertPoll, `21` GetCert, `22` GetCRL ; réponse `3` CertRep |
| `pkiStatus` | `.3` | `0` SUCCESS, `2` FAILURE, `3` PENDING |
| `failInfo` | `.4` | `0` badAlg, `1` badMessageCheck, `2` badRequest, `3` badTime, `4` badCertId |
| `senderNonce` | `.5` | 16 octets aléatoires |
| `recipientNonce` | `.6` | = `senderNonce` de la requête |
| `transactionID` | `.7` | identifiant de transaction (hachage de la clé publique, en pratique) |

Réponse **CertRep** : SignedData signé par le certificat RA, attributs `messageType=3`, `pkiStatus`, `transactionID`
(recopié), `recipientNonce`, `senderNonce` (nouveau), `failInfo` si échec. En cas de succès, contenu = EnvelopedData
chiffré **pour le certificat signataire de la requête**, contenant un PKCS#7 certs-only avec le certificat émis
(ou la CRL pour `GetCRL`).

## 3. Autorisation

- `PKCSReq` : l'attribut `challengePassword` (OID `1.2.840.113549.1.9.7`) du CSR doit correspondre à une
  `EnrollmentCredential(kind=scep_challenge)` du profil — à usage unique ou multiple selon configuration, expirante.
  Mot de passe invalide → `FAILURE / badRequest`. Profil configuré en approbation manuelle → `PENDING`, puis
  `CertPoll` par le client.
- `RenewalReq` : signée par un certificat **valide** émis par cette AC ; même sujet ; pas de challenge requis.
- `GetCert` / `GetCRL` : signataire doit être un certificat émis par cette AC.
- Rejeu : `transactionID` + `senderNonce` mémorisés dans `ScepTransaction` ; une même transaction déjà émise renvoie
  le même certificat (idempotence exigée par la RFC pour les retransmissions).

## 4. Implémentation

- **Certificat RA** dédié par AC (`PrivateKey.purpose = scep_ra`, RSA 2048+, KU `digitalSignature` + `keyEncipherment`),
  émis automatiquement à l'activation de SCEP. Une AC à clé EC ne peut pas déchiffrer l'enveloppe : le RA est donc
  obligatoire dans ce cas.
- `core/cms.py` :
  - parsing de SignedData / EnvelopedData et de leurs attributs avec **`asn1crypto.cms`** ;
  - vérification de la signature et déchiffrement de la clé de contenu (RSA PKCS#1 v1.5 via `keystore.decrypt`)
    puis du contenu (AES-128/256-CBC ; 3DES accepté en lecture si `scep.allow_legacy_crypto`) avec `cryptography` ;
  - construction des réponses (EnvelopedData + SignedData) avec `asn1crypto` + signatures `cryptography`.
  - **À vérifier** : les API PKCS#7 récentes de `cryptography` (`PKCS7EnvelopeBuilder`, décryptage) pourraient couvrir
    une partie du besoin ; elles ne lisent pas les attributs authentifiés SCEP, d'où `asn1crypto` pour la structure.
- `services/scep.py` : machine à états de `ScepTransaction` (`pending → issued | failed`).

`ScepTransaction` : `transaction_id` (unique par AC), `message_type`, `sender_nonce`, `signer_cert_der`, `status`,
`request` → `CertificateRequest`, `certificate` → `Certificate`, `fail_info`.

## 5. Tests

- Unitaires : construction d'une requête PKCSReq **par les tests eux-mêmes** (fixture utilisant `asn1crypto`, avec
  certificat auto-signé du demandeur), puis aller-retour complet : parse → déchiffrement → émission → CertRep →
  déchiffrement côté test → certificat valide.
- Cas d'erreur : mauvais challenge, signature invalide (`badMessageCheck`), algorithme non supporté (`badAlg`),
  retransmission idempotente, `CertPoll` sur demande en attente, `RenewalReq` avec certificat révoqué.
- Interop : `sscep getca` / `sscep enroll` dans le compose d'interop ; vérifier aussi `GetCACaps` avec un client MDM si
  possible (test manuel documenté).
