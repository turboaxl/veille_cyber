#!/usr/bin/env bash
# Lance la veille CVE : prépare l'environnement Python si besoin, puis démarre l'application.
# Au démarrage, les CVE sont mises à jour si la base date d'avant aujourd'hui.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null; then
  echo "Python 3 est introuvable. Installez-le (ex. : sudo apt install python3 python3-venv)." >&2
  exit 1
fi
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
  echo "Python 3.9 ou plus récent est requis (version actuelle : $(python3 -V))." >&2
  exit 1
fi

# (Ré)installe les dépendances au premier lancement, ou si requirements.txt a changé,
# ou si une installation précédente a échoué (le marqueur n'est écrit qu'en cas de succès).
if [ ! -f .venv/.installed ] || [ requirements.txt -nt .venv/.installed ]; then
  if [ ! -x .venv/bin/python ]; then
    rm -rf .venv
    if ! python3 -m venv .venv; then
      echo "Impossible de créer l'environnement virtuel." >&2
      echo "Sur Debian / Ubuntu : sudo apt install python3-venv" >&2
      rm -rf .venv
      exit 1
    fi
  fi
  echo "Installation des dépendances…"
  .venv/bin/pip install -q --upgrade pip
  .venv/bin/pip install -q -r requirements.txt
  touch .venv/.installed
fi

echo "→ http://${VEILLE_HOST:-127.0.0.1}:${VEILLE_PORT:-6060}"
exec .venv/bin/python app.py
