# ADR-0017 — Révocation : CRL et OCSP choisis à la création de l'AC

- **Statut** : accepté
- **Date** : 2026-11-26

## Contexte

La phase 3 ajoute la révocation. La conception initiale (`docs/protocols/crl.md`, `ocsp.md`, ARCHITECTURE §8.2)
prévoyait une CRL complète et une CRL delta, la suspension (`certificateHold`), un répondeur OCSP délégué
auto-renouvelé, et des réglages `crl.delta_enabled`, `ocsp.enabled`, `ocsp.responder`. Deux questions restaient
ouvertes : la publication par une racine arrêtée (décision ouverte n° 1, `federation.md` §6) et la façon dont une AC
fille apprend sa propre révocation (reportée de la phase 2, B50).

Pour un homelab, chaque élément optionnel est un réglage de plus à comprendre et un cas de plus à tester. Surtout,
les URL de révocation inscrites dans un certificat (CDP, AIA OCSP) l'engagent pour toute sa durée de vie : un
service qu'on pourrait couper après coup laisserait des certificats pointer vers une URL morte.

## Décision

### CRL et OCSP optionnels, choisis une fois pour toutes
- `h42pki authority init --crl --ocsp` (racine **et** subordonnée), **désactivés par défaut**. Stockés sur l'AC
  (`Authority.crl_enabled`, `ocsp_enabled`) ; ce ne sont pas des réglages et aucun chemin ne les modifie.
- Ils décident de ce que l'AC inscrit dans les certificats qu'elle émet, **tous profils confondus** (certificats
  d'AC filles et `service_tls` compris), en extensions non critiques, seulement si `public_base_url` est défini :
  CDP `{public_base_url}/crl/{name}.crl`, AIA OCSP `{public_base_url}/ocsp`. Jamais sur le certificat de la racine.
- Les réglages `crl.delta_enabled`, `ocsp.enabled` et `ocsp.responder` disparaissent ; restent
  `crl.validity_hours` (168), `crl.regenerate_before_hours` (48) et `ocsp.response_validity_hours` (24), niveau `hot`.

### Pas de mode « à vide » avec révocation (réponse à la décision ouverte n° 1)
- Une AC avec CRL ou OCSP **refuse de démarrer** sans listener (`h42pki serve`, code de sortie 2) ; `authority init
  --crl|--ocsp` est refusé de même quand les variables du conteneur désactivent HTTP et HTTPS.
- Une racine destinée à rester hors ligne se crée **sans** CRL ni OCSP : ses certificats (ceux des intermédiaires)
  ne portent alors aucune URL de révocation, et la révocation d'une intermédiaire se gère par son remplacement. Le
  miroir de la CRL d'une racine arrêtée par ses filles (`mirror_parent`) n'est pas retenu.

### Une CRL complète, pas de delta
- Une seule CRL par AC, numérotée (`CRLNumber` croissant, jamais réutilisé), signée par la clé de l'AC, régénérée à
  chaque révocation et par une tâche toutes les 15 minutes (aucune CRL, échéance proche, révocation non couverte).
- Les certificats révoqués **et expirés** en sortent ; `CRLReason` est omise pour `unspecified`.
- La publication (`/crl/{name}.crl`, HTTP et HTTPS) sert la dernière CRL stockée et **ne signe jamais** à la demande.

### OCSP signé par l'AC, avec cache
- Pas de répondeur délégué : la réponse est signée par la clé de l'AC (`responder_id` par hachage de clé, certificat de
  l'AC joint). Le profil `ocsp_signer` reste émissible mais ne sert pas au répondeur.
- Chaque réponse sollicitant la clé de l'AC, les réponses **sans nonce** sont mises en cache en mémoire par
  (AC, numéro de série, algorithme du CertID), réutilisées jusqu'à mi-validité et seulement si le statut stocké du
  certificat n'a pas changé (ce qui couvre une révocation faite par la CLI dans un autre processus).
- Une réponse **avec nonce** est toujours signée à nouveau : un client anonyme peut donc provoquer une signature par
  requête (risque accepté en homelab, B54).
- **Impact sur PKCS#11 (ADR-0004)** : l'ADR-0004 préconisait le répondeur délégué pour ne pas solliciter le jeton à
  chaque requête. Avec une clé d'AC sur carte à puce, ce choix devra être revu (répondeur délégué ou cache plus
  agressif) lors du spike de la phase 7.

### Révocation définitive
- Motifs RFC 5280, sauf `certificate_hold` et `remove_from_crl`, refusés (422). Pas de suspension ni de levée.
- Révocation par `POST /api/v1/certificates/{id}/revoke` et `h42pki certificate revoke` (sans authentification
  jusqu'à la release, ADR-0008), et par la fédération pour une AC fille ; tout passe par `RevocationService`.
- Refus (409) : certificat déjà révoqué, certificat d'une AC locale, `service_tls` (géré par le système), certificat
  non émis par une AC locale.

### Contrôle par une AC fille de son propre statut
- Chaque jour (et par `h42pki authority check-parent`), une AC subordonnée interroge l'OCSP de sa mère, à l'URL de
  l'AIA de son propre certificat, avec un nonce ; en https, TLS est vérifié avec l'AC mère épinglée (ADR-0015). La
  réponse doit être signée par l'AC mère elle-même.
- `revoked` : l'AC passe `revoked`, n'émet plus rien (503, y compris le renouvellement de son certificat HTTPS), mais
  continue de publier sa CRL et de répondre en OCSP pour ses certificats.
- Mère injoignable, sans OCSP ou réponse invalide : avertissement dans le journal et dans `/health`, sans changement
  d'état.

## Alternatives considérées

- **Options modifiables par réglage** : simple à exposer, mais les URL déjà inscrites deviendraient mortes.
- **CRL delta** : utile pour de grosses CRL ; inutile à l'échelle d'un homelab et double la logique.
- **Répondeur délégué** : protège la clé de l'AC mais ajoute un certificat, une clé et une tâche de renouvellement
  par AC ; le cache suffit avec une clé logicielle.
- **Miroir de la CRL d'une racine arrêtée par ses filles** : résout la décision n° 1 au prix d'une synchronisation
  entre conteneurs ; la racine hors ligne sans révocation est plus simple et usuelle en homelab.
- **Suspension** : rarement utile, et source d'erreurs (certificats « en attente » oubliés).

## Conséquences

- Les clients qui exigent une information de révocation (Windows, B41) l'obtiennent dès qu'une AC est créée avec
  `--crl` ou `--ocsp` et une `public_base_url`.
- Une AC créée sans révocation ne peut pas l'activer plus tard : il faut une nouvelle AC (rollover, phase 7).
- Une AC révoquée par sa mère perd son HTTPS au plus tard à l'expiration de son certificat `service_tls` (47 jours) ;
  la publication en HTTP continue.
- Tâches planifiées du lanceur : CRL (15 min), statut `expired` (1 h, B34), purge des clés `service_tls` remplacées
  (1 jour, B44), contrôle auprès de la mère (1 jour) ; toutes tournent aussi en mode « à vide ».
- La table `Crl` et les nouveaux champs de `Authority` arrivent sans migration (ADR-0007).
