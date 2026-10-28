# Veille CVE

Application web locale de veille sur les CVE récentes, orientée pentest.

## Installation et lancement (Linux)

### Sans Docker

Prérequis : Python 3.9+ avec le module `venv`, et un accès Internet.

Créer un venv, puis :
```bash
chmod +x run.sh 
./run.sh      # installe les dépendances au premier lancement puis démarre
```

Ouvrir ensuite http://127.0.0.1:6060 dans un navigateur.

### Avec Docker

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

Détails et options : [docker/README.md](docker/README.md).

Au démarrage, si la dernière mise à jour date d'avant aujourd'hui, les données sont rafraîchies
en arrière-plan (l'interface reste utilisable, la progression s'affiche en haut à droite).
Le bouton **↻** force un rafraîchissement.

Le bouton **menu** permet principalement d'appliquer des filtres. 
Pages : **Trending** (page d'accueil : les 20 CVE aux PoC GitHub les plus étoilés créés ces 3 derniers mois
— une CVE n'y figure qu'une fois, ses dépôts étant regroupés sous le plus étoilé,rafraîchi toutes les 6 h), 
**Toutes les vulns**, **Favoris** (les favoris ne sont jamais purgés).
**Période** : porte au choix sur la **date de publication** de la CVE (défaut).  


Recherche : seule la barre de recherche interroge l'API NVD ; les filtres (sévérité, technos,
composant, période…) ne font que filtrer ce qui est déjà en base. La profondeur se règle avec
le menu **Recherche sur…** à côté de **Tri** (1 mois, 3 mois, **6 mois** par défaut, 1, 2 ou 3 ans).
- Ordres de grandeur sans clé NVD, sur 6 mois : nginx ~7 s, microsoft ~15 s, windows ~35 s.
- Avec une clé, la recherche est découpée en plages de dates (réponses petites et rapides) :
  mesuré sur « drupal » / 3 ans, 25 s contre 75 s auparavant, où la requête unique dépassait
  parfois le délai. Une plage en échec n'annule plus la recherche : les résultats obtenus sont
  conservés, l'interface signale « NVD partiellement indisponible » et un nouvel essai complète
  (une recherche partielle n'est pas mise en cache).

**Magic filters** (en bas du menu de gauche) : recherches prédéfinies regroupant plusieurs technos
selon un scénario de test. Un clic lance la recherche NVD de toutes ses technos et affiche les CVE correspondant à l'une d'elles ; les autres filtres (PoC, sévérité…) s'appliquent
par-dessus. 

Par défaut : **Active Directory**, 20 technos clés pour l'élévation de privilèges en environnement
Active Directory . ~3-4 min au premier
lancement sans clé NVD (6 mois), puis en cache 12 h.



## Configuration (variables d'environnement)

| Variable | Défaut | Rôle |
|---|---|---|
| `VEILLE_DAYS` | `5` | Historique conservé (jours) |
| `NVD_API_KEY` | – | Optionnelle ([gratuite](https://nvd.nist.gov/developers/request-an-api-key)) : recherches ~8× plus rapides. Peut aussi être saisie dans le menu (**Clé API NVD**, en bas), auquel cas elle est stockée en base et prime sur cette variable |
| `GITHUB_TOKEN` | – | Optionnel, évite le rate-limit GitHub |
| `VEILLE_HOST` / `VEILLE_PORT` | `127.0.0.1` / `6060` | Adresse d'écoute |

Exemple : `VEILLE_PORT=8080 NVD_API_KEY=xxxx ./run.sh`
