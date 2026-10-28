"""Magic filters : recherches prédéfinies regroupant plusieurs technos selon un scénario de test."""
import json

import db

# « Active Directory » : technos les plus exploitées pour l'élévation de privilèges en environnement
# Active Directory (cf. https://www.thehacker.recipes/ad/). Termes choisis pour la recherche NVD
# (qui porte sur la description des CVE), en expression exacte.
SEED_VERSION = 3

# Anciens noms des filtres livrés par défaut : renommés au démarrage, sans perdre les technos
# ajoutées par l'utilisateur ni sa position dans la liste.
RENAMED = {"Test interne": "Active Directory"}

DEFAULTS = {
    "Active Directory": [
        # Identité & services Active Directory
        "Active Directory", "Kerberos", "NTLM", "Certificate Services",
        "Lightweight Directory Access Protocol", "Netlogon", "Group Policy",
        "Local Security Authority",
        # Services souvent exploités dans le domaine
        "Windows SMB", "Print Spooler", "Exchange Server", "Configuration Manager",
        "SQL Server", "Windows Server Update Service",
        # Élévation de privilèges locale (noyau / pilotes / moteurs)
        "Windows Kernel", "Win32k", "Common Log File System", "Ancillary Function Driver",
        "Cloud Files Mini Filter", "Microsoft Defender",
    ],
}


def seed(conn):
    """Initialise les magic filters par défaut au premier lancement, puis les complète avec les
    nouveaux termes des versions suivantes. Respecte l'utilisateur : un filtre supprimé n'est pas
    recréé, et ses propres technos sont conservées (on ne fait qu'ajouter les termes manquants)."""
    ver = int(db.get_meta(conn, "magic_seed_version", "0"))
    if ver >= SEED_VERSION:
        return
    if db.get_meta(conn, "magic_seeded") != "1":
        for i, (name, terms) in enumerate(DEFAULTS.items()):
            conn.execute("INSERT OR IGNORE INTO magic_filters(name, terms, position) VALUES (?, ?, ?)",
                         (name, json.dumps(terms), i))
        db.set_meta(conn, "magic_seeded", "1")
    else:
        for old, new in RENAMED.items():
            if get_terms(conn, old) is not None and get_terms(conn, new) is None:
                conn.execute("UPDATE magic_filters SET name = ? WHERE name = ?", (new, old))
        for name, terms in DEFAULTS.items():
            existing = get_terms(conn, name)
            if existing is None:
                continue  # filtre supprimé par l'utilisateur : on ne le recrée pas
            lower = {e.lower() for e in existing}
            merged = existing + [t for t in terms if t.lower() not in lower]
            if merged != existing:
                set_terms(conn, name, merged)
    db.set_meta(conn, "magic_seed_version", str(SEED_VERSION))
    conn.commit()


def all_filters(conn):
    return [{"name": r["name"], "terms": json.loads(r["terms"])}
            for r in conn.execute("SELECT name, terms FROM magic_filters ORDER BY position, name")]


def get_terms(conn, name):
    row = conn.execute("SELECT terms FROM magic_filters WHERE name = ?", (name,)).fetchone()
    return json.loads(row["terms"]) if row else None


def create(conn, name):
    pos = conn.execute("SELECT COALESCE(MAX(position), -1) + 1 FROM magic_filters").fetchone()[0]
    conn.execute("INSERT INTO magic_filters(name, terms, position) VALUES (?, '[]', ?)", (name, pos))


def delete(conn, name):
    conn.execute("DELETE FROM magic_filters WHERE name = ?", (name,))


def set_terms(conn, name, terms):
    conn.execute("UPDATE magic_filters SET terms = ? WHERE name = ?", (json.dumps(terms), name))
