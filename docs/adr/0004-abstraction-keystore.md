# ADR-0004 — Toute signature passe par un keystore abstrait (préparation PKCS#11)

- **Statut** : proposé
- **Date** : 2026-11-21

## Contexte

L'image Docker embarque déjà OpenSC et `PyKCS11` : l'intention est de pouvoir garder la clé d'AC sur une carte à puce
ou un HSM. Aujourd'hui les clés sont chargées en mémoire depuis la base et utilisées directement.

`cryptography` signe certificats, CRL et réponses OCSP uniquement avec **ses propres objets clé** : on ne peut pas lui
passer un objet qui délègue la signature à un jeton PKCS#11.

## Décision

- Interface `KeyBackend` (`generate`, `sign`, `decrypt`, `public_key`) ; **aucun** autre module ne manipule une clé
  privée.
- v1 : backend logiciel (PKCS#8 chiffré). Il peut exposer l'objet `cryptography` aux builders.
- Phase 7 : spike PKCS#11 obligatoire. Piste principale : construire le `TBSCertificate` / `TBSCertList` /
  `ResponseData` avec `asn1crypto`, le faire signer par le jeton, puis assembler la structure finale ; vérifier le
  résultat avec `cryptography`.

## Alternatives considérées

- Utiliser directement les objets `cryptography` partout : bloque définitivement PKCS#11.
- Bibliothèque tierce de construction X.509 compatible PKCS#11 : à évaluer pendant le spike.

## Conséquences

- Les builders de `core` doivent accepter « un signataire » plutôt qu'une clé, ou disposer d'un double chemin
  (`cryptography` direct / assemblage `asn1crypto`).
- Avec PKCS#11, préférer le répondeur OCSP délégué (clé logicielle) pour ne pas solliciter le jeton à chaque requête.

## Mise en œuvre (lot 4, 2026-11-21)

- L'interface est implémentée sous le nom **`KeyStore`** (`keystore/base.py`), pour ne pas la confondre avec l'enum
  `KeyBackend` (`software|pkcs11`) du modèle `PrivateKey`. Version v1 : `generate(algorithm)` et `load(stored)`.
- Comme prévu pour la v1, le backend logiciel remet l'objet `cryptography` au service, qui le passe aux builders de
  `core`. Les fonctions de (dé)chiffrement de `core/keys.py` ne sont appelées que par `keystore`, seul détenteur de la
  passphrase. `sign`, `decrypt` et `purpose` arrivent avec le spike PKCS#11 (phase 7). Détails : ARCHITECTURE §8.1.
