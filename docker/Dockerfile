# syntax=docker/dockerfile:1
#
# Image de la veille CVE. Deux étages : les dépendances sont installées dans un
# virtualenv jetable, seul le virtualenv terminé est recopié dans l'image finale
# (ni pip, ni cache, ni compilateur dedans).
#
# Base Alpine : ijson publie des roues musllinux, donc aucune compilation n'est
# nécessaire malgré son extension C.

ARG PYTHON_VERSION=3.12

# --------------------------------------------------------------------- étage 1
FROM python:${PYTHON_VERSION}-alpine AS build

COPY requirements.txt /tmp/requirements.txt

# Le cache pip est monté (hors image) : les reconstructions ne retéléchargent rien.
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install -r /tmp/requirements.txt

# --------------------------------------------------------------------- étage 2
FROM python:${PYTHON_VERSION}-alpine

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    VEILLE_HOST=0.0.0.0 \
    VEILLE_PORT=6060

COPY --from=build /opt/venv /opt/venv

WORKDIR /app
# Le code est copié après les dépendances : une modification du code ne réinstalle rien.
COPY app.py db.py magic.py tags.py updater.py versions.py ./
COPY static ./static

# Exécution sans privilèges. data/ appartient à l'utilisateur pour que le volume
# monté par-dessus hérite des bons droits.
RUN addgroup -S veille && adduser -S -G veille veille && \
    mkdir -p /app/data && chown -R veille:veille /app
USER veille

EXPOSE 6060

# wget est fourni par busybox : pas de paquet supplémentaire à installer.
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- "http://127.0.0.1:${VEILLE_PORT}/api/status" >/dev/null || exit 1

CMD ["python", "app.py"]
