# Charte graphique — h42-pki

> Statut : **v1** (2026-11-22). Logo retenu : la « maison porte-serrure » dans un carré arrondi.

## Logo

Une maison dont le **toit est une hiérarchie d'AC** : la racine en couleur d'accent au faîte, deux AC filles aux
extrémités. La **porte est un trou de serrure** (couleur d'accent) : on n'entre qu'avec la bonne clé. Le tout dans
un carré arrondi bleu nuit (rayon 28/120).

| Fichier | Usage |
|---|---|
| `h42-pki.svg` | Logo principal (carré bleu nuit), à partir de 48 px |
| `h42-pki-dark.svg` | Sur fond sombre (carré `#1E2F4A`, se détache du fond `#0F1B2D`) |
| `h42-pki-inverse.svg` | Carré blanc, maison bleu nuit : fonds très sombres, photos |
| `h42-pki-mono.svg` | Une seule couleur (blanc sur bleu nuit) : impression, tampons, badges |
| `h42-pki-32.svg` | Petit format (≤ 32 px) : traits renforcés, sans les nœuds latéraux du toit |
| `h42-pki-16.svg` | 16 px : maison et serrure réduite à un point |
| `favicon.ico` | 16, 32 et 48 px |
| `h42-pki-512.png`, `h42-pki-256.png`, `h42-pki-48.png` | Icône de l'image Docker, avatar du dépôt, OpenAPI |

Ne pas déformer, recolorer la maison, ni retirer le carré (sauf version monochrome). Zone de protection : 1/8 de la
largeur du carré tout autour.

## Couleurs

| Nom | Valeur | Rôle |
|---|---|---|
| Bleu nuit | `#0F1B2D` | Carré du logo, texte principal, fonds sombres |
| Bleu nuit clair | `#1E2F4A` | Carré du logo sur fond sombre |
| Accent | `#14B8A6` | Racine et serrure ; « -pki » sur fond sombre |
| Accent texte | `#0F766E` | « -pki » et liens sur fond clair (contraste AA) |
| Gris texte | `#4A5568` | Texte secondaire |
| Fond | `#F4F6F8` | Fond clair des pages |

## Typographie

- **Space Grotesk** 700 / 500 : nom et titres. Nom : « h42 » en 700, « -pki » en 500 et en couleur d'accent.
- **Inter** 400–600 : texte courant.
- **JetBrains Mono** 500 : code, étiquettes techniques.

Le nom n'est pas vectorisé dans les SVG : composer le logo + nom en HTML (README, future interface web) avec ces
polices, plutôt qu'une image.

## Intégration prévue dans le dépôt

- `docs/assets/brand/` : tous les fichiers ci-dessus.
- `README.md` : `<img src="docs/assets/brand/h42-pki.svg" width="96" alt="h42-pki">` en en-tête.
- `src/h42pki/static/favicon.ico` servi en `/favicon.ico` (route publique, HTTP et HTTPS, §6 de l'architecture).
- Image Docker : label OCI `org.opencontainers.image.logo` (ou icône Docker Hub) avec `h42-pki-512.png`.
