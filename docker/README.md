# Veille CVE — déploiement Docker

Image de ~75 Mo, sans compilateur ni cache de build. Première construction ~20 s,
reconstruction après modification du code < 1 s.

## Prérequis

Docker 20.10+ (BuildKit activé par défaut) et le plugin Compose.

```bash
docker --version && docker compose version
```

## Démarrage

Depuis la **racine du projet** (pas depuis ce dossier) :

```bash
docker compose -f docker/docker-compose.yml up -d --build
```

Puis ouvrir http://127.0.0.1:6060

Au premier démarrage, l'application télécharge les CVE en arrière-plan (~1 min) :
l'interface est utilisable immédiatement, la progression s'affiche en haut à droite.

## Sans Compose

```bash
# depuis la racine du projet
docker build -f docker/Dockerfile -t veille-cve .

docker run -d --name veille-cve \
  -p 127.0.0.1:6060:6060 \
  -v veille-data:/app/data \
  veille-cve
```

## Mettre à jour après une modification du code

```bash
# depuis la racine du projet
docker compose -f docker/docker-compose.yml up -d --build
```

Compose reconstruit l'image et recrée le conteneur **uniquement si l'image a changé**.
Grâce à l'ordre des couches, seule la copie du code est refaite : moins d'une seconde.
Le volume de données n'est pas touché.

Si rien ne semble pris en compte :

```bash
# vérifier que le conteneur tourne bien sur l'image fraîche
docker inspect -f '{{.Image}}' veille-cve
docker images -q veille-cve:latest          # les deux doivent correspondre

# forcer la recréation du conteneur
docker compose -f docker/docker-compose.yml up -d --build --force-recreate

# reconstruire en ignorant complètement le cache
docker compose -f docker/docker-compose.yml build --no-cache
docker compose -f docker/docker-compose.yml up -d
```

## Options

À régler dans `docker-compose.yml` (section `environment`) ou avec `-e` :

| Variable | Défaut | Rôle |
|---|---|---|
| `VEILLE_DAYS` | `5` | Historique conservé, en jours |
| `NVD_API_KEY` | – | Clé NVD [gratuite](https://nvd.nist.gov/developers/request-an-api-key) : recherches ~8× plus rapides |
| `GITHUB_TOKEN` | – | Évite le rate-limit GitHub (page Trending) |
| `VEILLE_PORT` | `6060` | Port **interne** au conteneur ; pour changer le port exposé, modifier `ports:` |

`VEILLE_HOST` vaut `0.0.0.0` dans l'image (indispensable pour sortir du conteneur).
L'exposition réelle est contrôlée par `ports:`, pas par cette variable.

## Commandes utiles

```bash
docker compose -f docker/docker-compose.yml logs -f      # suivre les logs
docker compose -f docker/docker-compose.yml restart      # relancer (met à jour les CVE du jour)
docker compose -f docker/docker-compose.yml up -d --build # reconstruire après modification du code
docker compose -f docker/docker-compose.yml down         # arrêter (le volume est conservé)
docker compose -f docker/docker-compose.yml down -v      # arrêter ET supprimer les données
```

## Données

La base SQLite vit dans le volume nommé `docker_veille-data`, monté sur `/app/data`.
Elle survit aux `down`, aux reconstructions et aux changements de version.

```bash
# sauvegarde
docker run --rm -v docker_veille-data:/data -v "$PWD":/out alpine \
  tar czf /out/veille-data.tar.gz -C /data .
```

Un volume **nommé** est recommandé : avec un bind mount (`-v ./data:/app/data`),
le conteneur tourne sans privilèges (uid 100) et peut ne pas avoir le droit
d'écrire dans le dossier de l'hôte.

## Sécurité

- Le port est publié sur `127.0.0.1` uniquement : l'application n'a **aucune
  authentification**. Ne la publiez sur le réseau qu'en connaissance de cause.
- Le conteneur tourne sous un utilisateur non privilégié (`veille`, uid 100).
- Les recherches sont envoyées à la NVD et à GitHub : à garder en tête en mission.

## Choix techniques

- **Alpine** : `ijson` publie des roues `musllinux`, donc aucune compilation n'est
  nécessaire malgré son extension C. Cela évite d'embarquer gcc.
- **Deux étages** : les dépendances sont installées dans un virtualenv jetable ;
  seul le virtualenv terminé est recopié. Ni pip, ni cache dans l'image finale.
- **Ordre des couches** : `requirements.txt` est copié et installé avant le code,
  donc une modification du code ne réinstalle pas les dépendances.
- **Cache pip monté** (`--mount=type=cache`) : les reconstructions ne retéléchargent rien.
- **`.dockerignore`** (à la racine du projet, pas ici — Docker ne le lit que dans le
  contexte de build) : exclut `data/` (~120 Mo) et `.venv/`, le contexte envoyé au
  démon se limite au code.
- **Serveur intégré de Flask**, mono-processus : le thread de mise à jour en arrière-plan
  doit rester unique. Un serveur multi-worker lancerait plusieurs mises à jour concurrentes.
