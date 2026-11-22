# ADR-0006 — snake_case pour les champs JSON de l'API et de la configuration

- **Statut** : accepté
- **Date** : 2026-11-21

## Contexte

Les modèles Pydantic d'origine (`pki_models.py`) utilisent des noms en PascalCase (`CommonName`, `PathLength`,
`CertificateAuthority`), qui se retrouvent dans l'API JSON et dans les colonnes JSON de la base. Ce n'est pas
idiomatique en Python, et ça mélange deux conventions dans le même code. La base est jetable avant le lot 3 :
c'est le bon moment pour changer.

## Décision

- Tous les champs des schémas Pydantic, des colonnes JSON en base, de l'API d'administration, de la fédération et
  de la configuration (réglages en base depuis l'ADR-0011, qui remplace le TOML envisagé) sont en **snake_case**, sans alias PascalCase ou camelCase.
- Attributs de sujet : on reprend les noms de `cryptography.x509.oid.NameOID` en minuscules : `country_name`,
  `state_or_province_name`, `locality_name`, `organization_name`, `organizational_unit_name`, `common_name`,
  `email_address`.
- Extensions : `basic_constraints.ca`, `basic_constraints.path_length`, `key_usage.digital_signature`,
  `key_usage.key_cert_sign`, `key_usage.crl_sign`…, `extended_key_usage` = liste de noms
  (`server_auth`, `client_auth`, `code_signing`, `email_protection`, `time_stamping`, `ocsp_signing`).
  Ce sont les mêmes noms que dans les arguments de `cryptography`.
- **Exception** : les formats imposés par une RFC gardent leurs noms d'origine (ACME RFC 8555 en camelCase :
  `termsOfServiceAgreed`, `newOrder`, `externalAccountBinding`… ; `problem+json` RFC 9457). Ils sont modélisés avec
  des `Field(alias=...)` dans `api/acme/schemas.py`.

## Alternatives considérées

- Garder le PascalCase : moins de travail tout de suite, mais conventions incohérentes durablement.
- camelCase, comme beaucoup d'API web : pas idiomatique en Python, et ça impose des alias partout.

## Conséquences

- Les modèles de `h42pki/ca/pki_models.py` sont renommés pendant la réécriture des lots 3 et 4. Le schéma de base
  est recréé (pas de migration des anciennes données JSON).
- Un validateur Pydantic, ou `model_config = ConfigDict(extra="forbid")`, fait échouer explicitement les anciens noms
  PascalCase au lieu de les ignorer en silence.
