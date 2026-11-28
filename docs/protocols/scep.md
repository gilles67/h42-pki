# SCEP — Simple Certificate Enrollment Protocol

Référence : RFC 8894. Cible : équipements réseau, bornes Wi-Fi, MDM (Intune, Jamf…), clients `sscep`.
Décisions : ADR-0019 (et ADR-0018 pour le principe « désactivé par défaut »). En place depuis la phase 5.

## 1. Activation et endpoints

SCEP est **désactivé par défaut** : tant que `scep.enabled` est faux, toutes les routes `/scep…` répondent `404`.

```bash
h42pki config set scep.enabled true            # à chaud ; le lanceur émet aussitôt le certificat RA
h42pki config set scep.default_profile tls_client   # facultatif : profil de /scep sans label
h42pki scep challenge create                   # challenge à usage unique, montré une fois
```

`/scep/{profil}` et `/scep/{profil}/pkiclient.exe` ; sans label, `/scep` et `/scep/pkiclient.exe` utilisent
`scep.default_profile` (vide → `404`). Un profil inconnu ou interne (`service_tls`, `scep_ra`) → `404`.
Servi en **HTTP et HTTPS** (la sécurité repose sur CMS, pas sur TLS). Paramètres : `operation` (obligatoire),
`message` (base64, pour `PKIOperation` en GET ; les espaces sont relus comme des `+`).

| `operation` | Méthode | Réponse |
|---|---|---|
| `GetCACaps` | GET | `text/plain`, une capacité par ligne : `POSTPKIOperation`, `SHA-256`, `SHA-512`, `AES`, `SCEPStandard`, `Renewal` ; `DES3` et `SHA-1` en plus si `scep.allow_legacy_crypto` |
| `GetCACert` | GET | `application/x-x509-ca-ra-cert`, PKCS#7 certs-only DER : AC, RA, ascendants de l'AC (ordre non garanti : `SET OF` DER trié). `503` tant que le RA n'existe pas |
| `PKIOperation` | POST (corps DER ≤ 64 Kio, `application/x-pki-message`) ou GET (`message`) | `application/x-pki-message` |

Pas de `GetNextCACert` (rollover d'AC : phase 7). Autre `operation` → `400`. Erreurs HTTP en **texte brut** ; un
message illisible (pas un `SignedData`) → `400`. Une fois le message lu, toute erreur est un `CertRep FAILURE`.

## 2. Messages PKIOperation

Requête : **SignedData** (signé par la clé du demandeur, avec un certificat auto-signé, ou son certificat actuel pour
un renouvellement) → contenu = **EnvelopedData** chiffré pour le **certificat RA** → contenu = CSR PKCS#10
(`PKCSReq`, `RenewalReq`), `IssuerAndSubject` (`CertPoll`) ou `IssuerAndSerialNumber` (`GetCert`, `GetCRL`).

Attributs authentifiés (OID `2.16.840.1.113733.1.9.x`) :

| Attribut | OID | Usage |
|---|---|---|
| `messageType` | `.2` | `19` PKCSReq, `17` RenewalReq, `20` CertPoll, `21` GetCert, `22` GetCRL ; réponse `3` CertRep |
| `pkiStatus` | `.3` | `0` SUCCESS, `2` FAILURE, `3` PENDING |
| `failInfo` | `.4` | `0` badAlg, `1` badMessageCheck, `2` badRequest, `3` badTime, `4` badCertId |
| `senderNonce` | `.5` | 16 octets aléatoires |
| `recipientNonce` | `.6` | = `senderNonce` de la requête |
| `transactionID` | `.7` | identifiant de transaction (hachage de la clé publique du demandeur) |

Réponse **CertRep** : SignedData signé par le **RA qui a déchiffré la requête**, attributs `messageType=3`,
`pkiStatus`, `transactionID` (recopié), `recipientNonce`, `senderNonce` (nouveau), `failInfo` si échec ; même
hachage que la requête. En cas de succès, contenu = EnvelopedData chiffré **pour le certificat signataire de la
requête** (même algorithme que la requête), contenant un PKCS#7 certs-only avec le certificat émis (ou la CRL).

Algorithmes admis : SHA-256/384/512, AES-128/256-CBC, signataire RSA ; 3DES et SHA-1 seulement si
`scep.allow_legacy_crypto`. Sinon `badAlg`. Signature ou `messageDigest` faux → `badMessageCheck` ; enveloppe pour un
autre destinataire, clé de contenu ou contenu indéchiffrable → le **même** `badMessageCheck` (pas d'oracle).

## 3. Autorisation

- **`PKCSReq`** : l'attribut `challengePassword` (OID `1.2.840.113549.1.9.7`) du CSR doit être un challenge SCEP
  actif, non expiré et non épuisé. Inconnu, désactivé, expiré, épuisé → `FAILURE / badRequest`. Un challenge vaut pour
  tout profil non désactivé ; à usage limité, il est consommé à l'acceptation de la demande.
- Profil en approbation manuelle → `PENDING` ; le client interroge par `CertPoll` : `PENDING`, puis `SUCCESS` après
  `h42pki request approve`, `FAILURE / badRequest` après `request reject`. Transaction inconnue → `badCertId`.
- **Renouvellement** : `RenewalReq`, ou `PKCSReq` **sans challenge** signé par un certificat non auto-signé (forme
  de `sscep`) : le signataire est un certificat émis directement par cette AC, valide (`badTime` sinon), non révoqué ;
  même sujet ; profil de ce certificat ; pas de challenge.
- **`GetCert` / `GetCRL`** : signataire émis par cette AC. Certificat inconnu → `badCertId` ; AC sans CRL →
  `badRequest`. Un émetteur égal au sujet d'un RA de l'AC (et, pour `GetCRL`, son numéro de série) désigne l'AC : c'est
  ce qu'envoie `sscep`.
- **Retransmission** : même `transactionID` signé par la même **clé** (même avec un nouveau certificat auto-signé) →
  même réponse, sans nouvelle demande ; même `transactionID` et autre clé → `badRequest`. Un `senderNonce` déjà vu →
  `badRequest` (nonces purgés après 30 jours).

## 4. Implémentation

- **RA dédié** (jamais la clé de l'AC, ADR-0019) : profil interne `scep_ra`, RSA 3072, KU `digitalSignature` +
  `keyEncipherment`, `PrivateKey.purpose = scep_ra`, `CN=<nom de l'AC> SCEP RA`. Émis par la tâche `scep_ra` du
  lanceur (démarrage, chaque jour, changement d'un réglage `scep.*`) ; validité `scep.ra_validity_days` (365),
  renouvelé à `scep.ra_renew_before_days` (30) de la fin. Les anciens RA non expirés déchiffrent encore ; les RA
  expirés sont purgés. `GET /api/v1/authority` (`scep_ra`) et `/health` (`scep`) le montrent.
- `core/cms.py` (pur) : lecture de SignedData / EnvelopedData et des attributs SCEP avec **`asn1crypto`**
  (`cryptography` ne lit ni n'écrit d'attributs authentifiés arbitraires), vérification de la signature et
  déchiffrement du contenu avec `cryptography`, construction du `CertRep` dont les attributs signés sont rendus à
  l'appelant pour signature.
- Keystore : `decrypt` (clé de contenu, RSA PKCS#1 v1.5) et `sign` (CertRep) avec la clé du RA ; `seal` / `open`
  pour le CSR. Toute erreur → `KeyOperationFailed` sans détail.
- `services/scep.py` (`ScepService`), `services/scep_ra.py` (`ScepRaManager`), `services/scep_challenges.py`.
  Émission par `IssuanceService.submit(channel = scep)`, demandeur `scep:<ID du challenge>` ou
  `scep-cert:<empreinte>` ; audit `scep.enroll`, `scep.renew`, `scep.challenge.*`.
- **CSR scellé** : le CSR (qui contient le challenge) est stocké chiffré par le keystore, SHA-256 en clair.

`ScepTransaction` : `transaction_id` (unique par AC), `message_type`, `sender_nonce`, `signer_cert_der`, `status`
(`pending | issued | failed`), `request` → `CertificateRequest`, `certificate` → `Certificate`, `fail_info`.
`ScepNonce` : nonces vus (unique par AC).

## 5. Challenges

Texte `<ID>-<SECRET>` (8 + 1 + 32 caractères `A-Z0-9`), généré par le serveur, **montré une fois**, stocké en SHA-256.

| Action | API (`/api/v1/scep/challenges`) | CLI (`h42pki scep challenge …`) |
|---|---|---|
| créer (usage unique par défaut) | `POST` `{max_uses, expires_in_hours, description}` → `201` `{challenge, details}` | `create [--reusable \| --max-uses N] [--expires-in-hours H] [--description …]` |
| lister, voir | `GET`, `GET /{id}` | `list`, `show ID` |
| désactiver, réactiver | `POST /{id}/disable`, `POST /{id}/enable` | `disable ID`, `enable ID` |
| supprimer | `DELETE /{id}` | `delete ID` |

La CLI écrit le challenge seul sur la sortie standard (le reste sur l'erreur standard).

## 6. Clients

`sscep` 0.10 (construit depuis ses sources par `deploy/sscep/Containerfile`, absent de Debian) :

```bash
sscep getca   -u http://pki.example/scep/tls_client -c ca.crt          # écrit ca.crt-0, ca.crt-1… : AC et RA
sscep enroll  -u http://pki.example/scep/tls_client -c ra.crt -e ra.crt \
              -k device.key -r device.csr -l device.crt -E aes256 -S sha256 [-t 5 -T 300]
sscep enroll  … -K device.key -O device.crt          # renouvellement : nouveau CSR sans challenge
sscep getcert -u … -c ra.crt -e ra.crt -k device.key -l device.crt -s 1B:DE:… -w copy.crt
sscep getcrl  -u … -c ra.crt -e ra.crt -k device.key -l device.crt -w crl.der
```

`-c` doit être le **certificat RA** : `sscep` vérifie la signature de la réponse avec ce certificat. Le challenge va
dans le CSR (`challengePassword` de `openssl req`), jamais sur une ligne de commande.

## 7. Tests

- Unitaires (`tests/unit/core/test_cms.py`, `test_challenges.py`) : client SCEP écrit par les tests
  (`tests/scep_client.py`), aller-retour `PKCSReq` → `CertRep` (AES-128, AES-256, 3DES si autorisé), signature
  altérée, algorithme interdit, clé de contenu ou contenu faux → même erreur.
- Intégration (`test_scep.py`, `test_scep_pki.py`, `test_scep_ra.py`, `test_scep_challenges.py`) : `404` désactivé,
  `GetCACaps`, `GetCACert`, `PKCSReq` automatique et manuel (`PENDING` → `CertPoll`), challenges épuisés, expirés,
  désactivés, retransmissions, nonce rejoué, renouvellement valide / révoqué / expiré / autre sujet, `GetCert`,
  `GetCRL`, ancien RA après renouvellement, keystore espion (la clé de l'AC n'est jamais utilisée), journaux et audit
  sans challenge.
- Interop : `deploy/scep-test.sh` avec `sscep` (enchaîné par `tests/interop/test_compose.py`).
