import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "data" / "veille.db"
SCHEMA_VERSION = "2"

SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    id            TEXT PRIMARY KEY,
    published     TEXT NOT NULL,
    last_modified TEXT,
    status        TEXT,
    description   TEXT,
    score         REAL,
    severity      TEXT,
    cvss_version  TEXT,
    vector        TEXT,
    cwes          TEXT,   -- JSON list
    products      TEXT,   -- JSON list "vendor product"
    refs          TEXT,   -- JSON list {url, tags}
    tags          TEXT DEFAULT '[]',   -- JSON list (copie de cve_tags pour l'affichage)
    -- champs dérivés des sources d'exploits (recalculés par rebuild_pocs)
    pocs          TEXT DEFAULT '[]',
    has_poc       INTEGER DEFAULT 0,
    poc_count     INTEGER DEFAULT 0,
    max_stars     INTEGER DEFAULT -1,
    search        TEXT DEFAULT '',
    pinned        INTEGER DEFAULT 0   -- 1 = ajoutée par une recherche : conservée plus longtemps
);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published);
CREATE INDEX IF NOT EXISTS idx_cves_poc ON cves(has_poc, published);

CREATE TABLE IF NOT EXISTS cve_tags (
    cve_id TEXT NOT NULL,
    tag    TEXT NOT NULL,
    PRIMARY KEY (cve_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_tags_tag ON cve_tags(tag, cve_id);

CREATE TABLE IF NOT EXISTS poc_cache (
    cve_id TEXT PRIMARY KEY,
    sha    TEXT,
    repos  TEXT          -- JSON list
);

CREATE TABLE IF NOT EXISTS exploitdb (
    edb_id   TEXT,
    cve_id   TEXT,
    title    TEXT,
    date     TEXT,
    type     TEXT,
    platform TEXT,
    verified INTEGER,
    PRIMARY KEY (edb_id, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_edb_cve ON exploitdb(cve_id);

-- Plages de versions affectées (cf. versions.py)
CREATE TABLE IF NOT EXISTS cve_versions (
    cve_id     TEXT NOT NULL,
    product    TEXT NOT NULL,     -- "vendor product" en minuscules
    exact      TEXT,
    start      TEXT,
    start_incl INTEGER,
    end        TEXT,
    end_incl   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_versions_cve ON cve_versions(cve_id);

-- Dépôts de PoC trouvés par la recherche GitHub en direct (trending, surnoms) : ils complètent
-- PoC-in-GitHub, dont l'index ignore une partie des dépôts récents.
CREATE TABLE IF NOT EXISTS github_pocs (
    cve_id      TEXT NOT NULL,
    url         TEXT NOT NULL,
    name        TEXT,
    description TEXT,
    stars       INTEGER,
    date        TEXT,
    PRIMARY KEY (cve_id, url)
);
CREATE INDEX IF NOT EXISTS idx_github_pocs_cve ON github_pocs(cve_id);

-- Surnoms trouvés via GitHub (ex. « RedSun » -> CVE-2026-41091)
CREATE TABLE IF NOT EXISTS cve_aliases (
    cve_id TEXT NOT NULL,
    alias  TEXT NOT NULL,
    PRIMARY KEY (cve_id, alias)
);

-- Magic filters : recherches prédéfinies multi-technos (ex. « Active Directory »)
CREATE TABLE IF NOT EXISTS magic_filters (
    name     TEXT PRIMARY KEY,
    terms    TEXT NOT NULL DEFAULT '[]',   -- JSON list de termes / technos
    position INTEGER
);

-- Vulnérabilités likées (jamais purgées)
CREATE TABLE IF NOT EXISTS likes (
    cve_id   TEXT PRIMARY KEY,
    liked_at TEXT
);

-- Recherches déjà envoyées à la NVD (évite de réinterroger l'API pour le même terme)
CREATE TABLE IF NOT EXISTS search_cache (
    term       TEXT PRIMARY KEY,
    days       INTEGER,
    fetched_at TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init():
    with connect() as conn:
        version = None
        try:
            version = get_meta(conn, "schema_version")
        except sqlite3.OperationalError:
            pass
        if version != SCHEMA_VERSION:
            # Schéma incompatible : on repart d'une base vide (les données sont re-téléchargées)
            for (name,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
                conn.execute(f'DROP TABLE IF EXISTS "{name}"')
        conn.executescript(SCHEMA)
        # Migration douce : colonne ajoutée après la v2
        for column in ("pinned INTEGER DEFAULT 0", "poc_date TEXT"):
            try:
                conn.execute(f"ALTER TABLE cves ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass
        set_meta(conn, "schema_version", SCHEMA_VERSION)


def get_meta(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, str(value)))
