"""Récupération et enrichissement des CVE.

Sources (aucune API à quota) :
  - Flux JSON 2.0 de la NVD        : CVE, description, CVSS, CWE, produits, références
      * premier chargement / rattrapage : flux annuels (nvdcve-2.0-<année>.json.gz)
      * mise à jour quotidienne          : flux « modified » + « recent » (8 derniers jours)
  - nomi-sec/PoC-in-GitHub         : dépôts GitHub de PoC (avec nombre d'étoiles)
  - Exploit-DB (files_exploits.csv): exploits publics référencés par CVE
"""
import csv
import gzip
import hashlib
import io
import json
import logging
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import ijson
import requests

import db
import versions
from tags import PRODUCT_SCOPED, PRODUCT_VENDOR, TAGS, compute_tags

log = logging.getLogger("veille")

WINDOW_DAYS = int(os.environ.get("VEILLE_DAYS", "5"))     # historique conservé
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")             # optionnel

SEARCH_DEFAULT_DAYS = 3 * 365           # période couverte par une recherche (3 ans)
PINNED_DAYS = SEARCH_DEFAULT_DAYS + 7    # conservation des CVE ajoutées par une recherche
ALIAS_THRESHOLD = 20                     # en dessous, la recherche est aussi tentée comme surnom sur GitHub
ALIAS_MAX_CVES = 5                       # CVE récupérées au plus via les dépôts GitHub
SEARCH_CACHE_TTL = timedelta(hours=12)   # une même recherche n'est pas renvoyée à la NVD avant 12 h
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Source amont de la NVD, officielle (MITRE / CVE Program), sans quota ni clé : utilisée en
# priorité pour les recherches par identifiant, ce qui réserve le budget NVD aux recherches
# par mot-clé (seule la NVD sait les faire).
CVE_RECORD_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
# Clé NVD : fournie par l'environnement et/ou saisie dans l'interface (stockée en base).
# Elle est lue à chaque appel, pour pouvoir être changée sans redémarrer.
NVD_API_KEY_ENV = os.environ.get("NVD_API_KEY")
NVD_DELAY_WITH_KEY = 0.7                                     # quota : 50 requêtes / 30 s
NVD_DELAY_WITHOUT_KEY = 6.2                                  # quota : 5 requêtes / 30 s
_api_key = NVD_API_KEY_ENV or None
_api_key_lock = threading.Lock()


def get_api_key():
    with _api_key_lock:
        return _api_key


def set_api_key(key):
    """Définit la clé utilisée par les prochains appels (None pour revenir sans clé)."""
    global _api_key
    with _api_key_lock:
        _api_key = (key or "").strip() or None


def load_api_key(conn):
    """Clé saisie dans l'interface si elle existe, sinon celle de l'environnement."""
    set_api_key(db.get_meta(conn, "nvd_api_key") or NVD_API_KEY_ENV)


def api_key_delay():
    return NVD_DELAY_WITH_KEY if get_api_key() else NVD_DELAY_WITHOUT_KEY


def validate_api_key(key):
    """Teste la clé auprès de la NVD. True = valide, False = refusée, None = NVD injoignable."""
    try:
        r = session.get(NVD_API_URL, params={"resultsPerPage": 1},
                        headers={"apiKey": key}, timeout=20)
    except requests.RequestException:
        return None
    if r.status_code == 200:
        return True
    if r.status_code in (403, 404):   # la NVD répond 404 sur une clé inconnue
        return False
    return None
NVD_API_MAX_RANGE = 119                                       # jours max par plage de dates (API)

FEED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{name}.{ext}"
FEED_YEARS_BACK = 2    # années d'ID antérieures à la fenêtre relues lors d'un chargement complet
INCREMENTAL_MAX_AGE = timedelta(days=7)    # les flux modified/recent couvrent 8 jours
FEED_DIR = db.DB_PATH.parent / "feeds"

GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
TRENDING_DAYS = 90                       # PoC créés sur les 3 derniers mois
TRENDING_SIZE = 20
TRENDING_TTL = timedelta(hours=6)
TRENDING_CACHE_VERSION = 2               # incrémenté quand la forme des items change
POC_TREE_URL = "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/git/trees/master?recursive=1"
POC_RAW_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{path}"
EDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# Domaines dont un lien NVD tagué "Exploit" est considéré comme du code d'exploitation
EXPLOIT_CODE_DOMAINS = ("github.com", "gist.github.com", "gitlab.com", "exploit-db.com",
                        "www.exploit-db.com", "packetstormsecurity.com", "packetstorm.news")
NOT_CODE_PATH = re.compile(r"/(security/advisories|commit|commits|pull|issues|releases|compare)/")

session = requests.Session()
session.headers["User-Agent"] = "veille-cyber/1.0"


class Status:
    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.message = ""
        self.error = None

    def set(self, msg, quiet=False):
        if not quiet:
            log.info(msg)
        with self.lock:
            self.message = msg

    def as_dict(self):
        with self.lock:
            return {"running": self.running, "message": self.message, "error": self.error}


status = Status()


def _utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# --------------------------------------------------------------------------- HTTP

def _get(url, params=None, headers=None, retries=5, stream=False, timeout=60):
    for attempt in range(retries):
        try:
            r = session.get(url, params=params, headers=headers, timeout=timeout, stream=stream)
            if r.status_code == 200:
                return r
            if r.status_code == 404:
                return None
            log.warning("HTTP %s sur %s (tentative %d)", r.status_code, url, attempt + 1)
        except requests.RequestException as e:
            log.warning("Erreur réseau sur %s : %s", url, e)
        time.sleep(min(30, 5 * (attempt + 1)))
    raise RuntimeError(f"Échec de récupération : {url}")


# --------------------------------------------------------------------------- Flux NVD

def _feed_sha(name):
    r = _get(FEED_URL.format(name=name, ext="meta"))
    meta = dict(line.split(":", 1) for line in r.text.splitlines() if ":" in line)
    return meta.get("sha256", "").strip(), int(meta.get("gzSize", "0").strip() or 0)


def _download_feed(name, size):
    FEED_DIR.mkdir(parents=True, exist_ok=True)
    path = FEED_DIR / f"{name}.json.gz"
    for _ in range(3):
        r = _get(FEED_URL.format(name=name, ext="json.gz"), stream=True)
        done = 0
        with open(path, "wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
                done += len(chunk)
                status.set(f"NVD {name} : téléchargement {done >> 20}/{max(1, size >> 20)} Mo", quiet=True)
        try:
            with gzip.open(path) as g:
                while g.read(1 << 24):
                    pass
            return path
        except (OSError, EOFError):
            log.warning("Flux %s corrompu, nouvel essai", name)
    raise RuntimeError(f"Flux NVD {name} illisible")


def _pick_cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry["cvssData"]
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return data.get("baseScore"), (severity or "").upper() or None, data.get("version"), data.get("vectorString")
    return None, None, None, None


def _products(cve):
    out = []
    for aff in cve.get("affected", []) or []:
        for d in aff.get("affectedData", []) or []:
            vp = f"{d.get('vendor', '')} {d.get('product', '')}".strip()
            if vp and vp.lower() not in ("n/a n/a", "n/a"):
                out.append(vp)
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable", True):
                    continue
                parts = m.get("criteria", "").split(":")
                if len(parts) > 4:
                    out.append(f"{parts[3]} {parts[4]}".replace("_", " ").replace("\\", ""))
    seen, uniq = set(), []
    for p in out:
        if p.lower() not in seen:
            seen.add(p.lower())
            uniq.append(p)
    return uniq


def parse_cve(cve):
    """Retourne (ligne pour UPSERT_SQL, {"tags": [...], "versions": [...]})."""
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    score, severity, version, vector = _pick_cvss(cve.get("metrics", {}))
    cwes = sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                   if d.get("value", "").startswith("CWE-")})
    refs = [{"url": r["url"], "tags": r.get("tags", [])} for r in cve.get("references", [])]
    products = _products(cve)
    tags = compute_tags(desc, products)
    row = (cve["id"], cve["published"], cve.get("lastModified"), cve.get("vulnStatus"), desc,
           score, severity, version, vector, json.dumps(cwes), json.dumps(products),
           json.dumps(refs), json.dumps(tags))
    return row, {"tags": tags, "versions": versions.extract(cve)}


UPSERT_SQL = """
INSERT INTO cves (id, published, last_modified, status, description, score, severity,
                  cvss_version, vector, cwes, products, refs, tags)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
    published=excluded.published, last_modified=excluded.last_modified, status=excluded.status,
    description=excluded.description, score=excluded.score, severity=excluded.severity,
    cvss_version=excluded.cvss_version, vector=excluded.vector, cwes=excluded.cwes,
    products=excluded.products, refs=excluded.refs, tags=excluded.tags
"""


def _delete_cves(conn, ids):
    ids = list(ids)
    for table, col in (("cves", "id"), ("cve_tags", "cve_id"), ("cve_versions", "cve_id"),
                       ("cve_aliases", "cve_id"), ("github_pocs", "cve_id"), ("poc_cache", "cve_id")):
        conn.executemany(f"DELETE FROM {table} WHERE {col} = ?", [(i,) for i in ids])


def _write_batch(conn, batch):
    conn.executemany(UPSERT_SQL, [row for row, _ in batch])
    ids = [(row[0],) for row, _ in batch]
    conn.executemany("DELETE FROM cve_tags WHERE cve_id = ?", ids)
    conn.executemany("INSERT INTO cve_tags(cve_id, tag) VALUES (?, ?)",
                     [(row[0], t) for row, extra in batch for t in extra["tags"]])
    conn.executemany("DELETE FROM cve_versions WHERE cve_id = ?", ids)
    conn.executemany("INSERT INTO cve_versions VALUES (?, ?, ?, ?, ?, ?, ?)",
                     [(row[0], *rng) for row, extra in batch for rng in extra["versions"]])
    conn.commit()


def update_nvd(conn):
    """Charge les flux NVD nécessaires. Retourne l'ensemble des CVE insérées / modifiées."""
    now = _utcnow()
    cutoff = (now - timedelta(days=WINDOW_DAYS)).isoformat()
    last_sync = db.get_meta(conn, "nvd_last_sync")
    last_window = int(db.get_meta(conn, "window_days", "0"))

    full = (not last_sync or last_window < WINDOW_DAYS
            or now - datetime.fromisoformat(last_sync) > INCREMENTAL_MAX_AGE)
    if full and last_window < WINDOW_DAYS:
        conn.execute("DELETE FROM meta WHERE key LIKE 'feed_sha:%'")  # fenêtre élargie : tout relire
    # Les flux annuels sont découpés par année de l'identifiant, pas de publication : une
    # CVE-2024-xxx peut être publiée aujourd'hui. On relit donc aussi les FEED_YEARS_BACK années
    # précédant la fenêtre (>99,9 % des CVE récentes) ; les flux quotidiens couvrent ensuite tout.
    first_year = datetime.fromisoformat(cutoff).year - FEED_YEARS_BACK
    # Fenêtre <= 7 jours : les flux modified/recent (8 jours) suffisent, pas besoin des annuels.
    need_yearly = full and WINDOW_DAYS > INCREMENTAL_MAX_AGE.days
    feeds = [str(y) for y in range(first_year, now.year + 1)] if need_yearly else []
    feeds += ["modified", "recent"]

    known = {r[0] for r in conn.execute("SELECT id FROM cves")}
    changed = set()
    for i, name in enumerate(feeds, 1):
        sha, size = _feed_sha(name)
        if sha and db.get_meta(conn, f"feed_sha:{name}") == sha:
            continue  # flux inchangé depuis le dernier traitement
        path = _download_feed(name, size)
        batch, rejected, read = [], [], 0
        with gzip.open(path) as f:
            for cve in ijson.items(f, "vulnerabilities.item.cve", use_float=True):
                read += 1
                if cve.get("vulnStatus") == "Rejected":
                    rejected.append(cve["id"])
                    continue
                if cve["published"] < cutoff and cve["id"] not in known:
                    continue
                batch.append(parse_cve(cve))
                if len(batch) >= 2000:
                    _write_batch(conn, batch)
                    changed.update(row[0] for row, _ in batch)
                    batch.clear()
                if read % 5000 == 0:
                    status.set(f"NVD {name} ({i}/{len(feeds)}) : {read:,} CVE lues".replace(",", " "))
        _write_batch(conn, batch)
        changed.update(row[0] for row, _ in batch)
        _delete_cves(conn, rejected)
        changed.difference_update(rejected)
        db.set_meta(conn, f"feed_sha:{name}", sha)
        conn.commit()
        path.unlink(missing_ok=True)

    pin_cutoff = (now - timedelta(days=max(PINNED_DAYS, WINDOW_DAYS))).isoformat()
    old = [r[0] for r in conn.execute(
        """SELECT id FROM cves WHERE ((published < ? AND pinned = 0) OR published < ?)
           AND id NOT IN (SELECT cve_id FROM likes)""", (cutoff, pin_cutoff))]
    _delete_cves(conn, old)
    db.set_meta(conn, "nvd_last_sync", now.isoformat())
    db.set_meta(conn, "window_days", WINDOW_DAYS)
    conn.commit()
    return changed


# --------------------------------------------------------------------------- PoC-in-GitHub

def _slim_repo(r):
    return {
        "name": r.get("full_name"),
        "url": r.get("html_url"),
        "description": r.get("description"),
        "stars": r.get("stargazers_count", 0) or 0,
        "forks": r.get("forks_count", 0) or 0,
        "updated": (r.get("pushed_at") or r.get("updated_at") or "")[:10],
        "fork": bool(r.get("fork")),
    }


_poc_index = {"at": 0.0, "index": {}}
_poc_index_lock = threading.Lock()


def _get_poc_index(max_age=3600):
    """Index {CVE: (chemin, sha)} du dépôt PoC-in-GitHub, gardé en mémoire (API GitHub : 60 req/h)."""
    with _poc_index_lock:
        if time.time() - _poc_index["at"] > max_age:
            headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"} if GITHUB_TOKEN else None
            tree = _get(POC_TREE_URL, headers=headers).json().get("tree", [])
            index = {}
            for t in tree:
                if t["type"] == "blob" and t["path"].endswith(".json"):
                    cve_id = t["path"].rsplit("/", 1)[-1][:-5].upper()
                    if CVE_RE.fullmatch(cve_id):
                        index[cve_id] = (t["path"], t["sha"])
            _poc_index.update(at=time.time(), index=index)
        return _poc_index["index"]


def update_pocs(conn, ids=None):
    """Met à jour le cache PoC-in-GitHub (toutes les CVE ou seulement `ids`).
    Retourne les CVE dont la liste de PoC a changé."""
    report = ids is None
    if report:
        status.set("PoC-in-GitHub : récupération de l'index…")
    index = _get_poc_index(max_age=0 if report else 3600)

    ours = set(ids) if ids is not None else {r["id"] for r in conn.execute("SELECT id FROM cves")}
    cache = {r["cve_id"]: r["sha"] for r in conn.execute("SELECT cve_id, sha FROM poc_cache")}
    todo = [(cid, *index[cid]) for cid in ours & index.keys() if cache.get(cid) != index[cid][1]]

    def fetch(item):
        cid, path, sha = item
        r = _get(POC_RAW_URL.format(path=path), retries=3)
        repos = [_slim_repo(x) for x in (r.json() if r else [])]
        return cid, sha, json.dumps(repos)

    results = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for i, res in enumerate(pool.map(fetch, todo), 1):
            results.append(res)
            if report and (i % 20 == 0 or i == len(todo)):
                status.set(f"PoC-in-GitHub : {i}/{len(todo)} fiches PoC téléchargées")
    conn.executemany("INSERT OR REPLACE INTO poc_cache(cve_id, sha, repos) VALUES (?,?,?)", results)
    conn.commit()
    return {cid for cid, _, _ in results}


# --------------------------------------------------------------------------- Exploit-DB

def update_exploitdb(conn):
    status.set("Exploit-DB : téléchargement de l'index…")
    r = _get(EDB_CSV_URL)
    rows = []
    for row in csv.DictReader(io.StringIO(r.text)):
        for cve_id in {c.upper() for c in CVE_RE.findall(row.get("codes") or "")}:
            rows.append((row["id"], cve_id, row["description"], row["date_published"],
                         row["type"], row["platform"], int(row.get("verified") or 0)))
    conn.execute("DELETE FROM exploitdb")
    conn.executemany("INSERT OR IGNORE INTO exploitdb VALUES (?,?,?,?,?,?,?)", rows)
    conn.commit()


# --------------------------------------------------------------------------- Dérivés

def _is_exploit_code_ref(ref):
    if "Exploit" not in ref.get("tags", []):
        return False
    u = urlparse(ref["url"])
    return u.netloc.lower() in EXPLOIT_CODE_DOMAINS and not NOT_CODE_PATH.search(u.path + "/")


def rebuild_pocs(conn, ids):
    """Recalcule la liste des PoC (triés par étoiles), has_poc et le texte de recherche pour `ids`."""
    ids = list(ids)
    if not ids:
        return
    conn.execute("CREATE TEMP TABLE IF NOT EXISTS _ids(id TEXT PRIMARY KEY)")
    conn.execute("DELETE FROM _ids")
    conn.executemany("INSERT OR IGNORE INTO _ids VALUES (?)", [(i,) for i in ids])

    pocs_by_cve = {r["cve_id"]: json.loads(r["repos"] or "[]") for r in conn.execute(
        "SELECT cve_id, repos FROM poc_cache WHERE cve_id IN (SELECT id FROM _ids)")}
    gh_by_cve = {}
    for r in conn.execute("SELECT * FROM github_pocs WHERE cve_id IN (SELECT id FROM _ids)"):
        gh_by_cve.setdefault(r["cve_id"], []).append(
            {"name": r["name"], "url": r["url"], "description": r["description"],
             "stars": r["stars"], "updated": r["date"], "source": "github"})
    edb_by_cve = {}
    for r in conn.execute("SELECT * FROM exploitdb WHERE cve_id IN (SELECT id FROM _ids)"):
        edb_by_cve.setdefault(r["cve_id"], []).append(r)

    aliases = {}
    for r in conn.execute("SELECT cve_id, alias FROM cve_aliases WHERE cve_id IN (SELECT id FROM _ids)"):
        aliases.setdefault(r["cve_id"], []).append(r["alias"])

    updates = []
    for row in conn.execute("SELECT id, description, products, refs FROM cves WHERE id IN (SELECT id FROM _ids)"):
        cid = row["id"]
        products = json.loads(row["products"] or "[]")
        refs = json.loads(row["refs"] or "[]")

        pocs = [{**repo, "source": "github"} for repo in pocs_by_cve.get(cid, [])]
        seen_urls = {p["url"].rstrip("/").lower() for p in pocs}
        for repo in gh_by_cve.get(cid, []):  # dépôts vus par la recherche GitHub en direct
            if repo["url"].rstrip("/").lower() not in seen_urls:
                seen_urls.add(repo["url"].rstrip("/").lower())
                pocs.append(repo)
        for e in edb_by_cve.get(cid, []):
            pocs.append({"name": e["title"], "url": f"https://www.exploit-db.com/exploits/{e['edb_id']}",
                         "description": f"Exploit-DB #{e['edb_id']} · {e['type']} · {e['platform']}"
                                        + (" · vérifié" if e["verified"] else ""),
                         "stars": None, "updated": e["date"], "source": "exploit-db"})
        known = {p["url"].rstrip("/").lower() for p in pocs}
        for ref in refs:
            if _is_exploit_code_ref(ref) and ref["url"].rstrip("/").lower() not in known:
                known.add(ref["url"].rstrip("/").lower())
                pocs.append({"name": ref["url"].split("://", 1)[-1], "url": ref["url"],
                             "description": "Référence NVD taguée « Exploit »", "stars": None,
                             "source": "nvd"})
        # Tri : étoiles décroissantes, sources sans étoiles à la fin
        pocs.sort(key=lambda p: (p["stars"] is None, -(p["stars"] or 0)))

        max_stars = max((p["stars"] for p in pocs if p["stars"] is not None), default=-1)
        # Date du PoC le plus récent : permet de filtrer sur l'activité d'exploitation
        poc_date = max((p.get("updated") or "" for p in pocs), default="") or None
        # Texte de recherche : identifiant, surnoms, description NVD et produits affectés.
        # Les noms / descriptions des dépôts de PoC sont exclus (bruit : « Windows-friendly checker »…).
        search = " ".join([cid, *aliases.get(cid, []), row["description"] or "", *products]).lower()
        updates.append((json.dumps(pocs), int(bool(pocs)), len(pocs), max_stars, poc_date, search, cid))

    conn.executemany("""UPDATE cves SET pocs=?, has_poc=?, poc_count=?, max_stars=?, poc_date=?,
                        search=? WHERE id=?""", updates)
    conn.commit()


def _tags_hash():
    payload = {"tags": TAGS, "scoped": sorted(PRODUCT_SCOPED), "vendors": PRODUCT_VENDOR}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def retag_if_needed(conn):
    """Recalcule tous les tags si tags.py a été modifié depuis le dernier calcul."""
    h = _tags_hash()
    if db.get_meta(conn, "tags_hash") == h:
        return
    total = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    log.info("tags.py modifié : recalcul des tags pour %d CVE…", total)
    rows = conn.execute("SELECT id, description, products FROM cves").fetchall()
    conn.execute("DELETE FROM cve_tags")
    updates, pairs = [], []
    for r in rows:
        tags = compute_tags(r["description"] or "", json.loads(r["products"] or "[]"))
        updates.append((json.dumps(tags), r["id"]))
        pairs += [(r["id"], t) for t in tags]
    conn.executemany("UPDATE cves SET tags = ? WHERE id = ?", updates)
    conn.executemany("INSERT INTO cve_tags(cve_id, tag) VALUES (?, ?)", pairs)
    db.set_meta(conn, "tags_hash", h)
    conn.commit()


# --------------------------------------------------------------------------- Recherche à la demande

_nvd_api_lock = threading.Lock()
_nvd_api_last = 0.0


def _nvd_api(params):
    """Appel à l'API NVD, sérialisé et espacé pour respecter le quota."""
    global _nvd_api_last
    key = get_api_key()
    headers = {"apiKey": key} if key else None
    with _nvd_api_lock:
        wait = api_key_delay() - (time.time() - _nvd_api_last)
        if wait > 0:
            time.sleep(wait)
        try:
            return _get(NVD_API_URL, params=params, headers=headers, retries=3, timeout=120).json()
        finally:
            _nvd_api_last = time.time()


# Recherches en cours : {terme: "page/pages"} (affiché par l'interface)
search_progress = {}


def github_cve_ids(term, limit=ALIAS_MAX_CVES):
    """CVE citées par les dépôts GitHub dont le nom ou la description contient `term`
    (les plus étoilés d'abord). Sert à retrouver une vuln par son surnom : RedSun, regreSSHion…"""
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"} if GITHUB_TOKEN else None
    try:
        r = _get(GITHUB_SEARCH_URL, headers=headers, retries=2, params={
            "q": f"{term} in:name,description", "sort": "stars", "order": "desc", "per_page": 50})
    except RuntimeError:
        return []
    ids, needle = [], term.lower()
    for repo in (r.json().get("items", []) if r else []):
        text = f"{repo.get('full_name', '')} {repo.get('description') or ''}"
        if needle not in text.lower():
            continue
        for cve_id in CVE_RE.findall(text):
            if cve_id.upper() not in ids:
                ids.append(cve_id.upper())
        if len(ids) >= limit:
            break
    return ids[:limit]


def _date_ranges(now, days):
    """Plages de 119 jours max (limite de l'API), de la plus récente à la plus ancienne."""
    start, end, out = now - timedelta(days=days), now, []
    while end > start:
        s = max(start, end - timedelta(days=NVD_API_MAX_RANGE))
        out.append({"pubStartDate": s.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000")})
        end = s
    return out


# Correspondance des métriques CVSS entre le format CVE Record 5.x et l'API NVD 2.0
_CVSS_KEYS = (("cvssV4_0", "cvssMetricV40"), ("cvssV3_1", "cvssMetricV31"),
              ("cvssV3_0", "cvssMetricV30"), ("cvssV2_0", "cvssMetricV2"))


def _record_to_nvd(record):
    """Convertit une fiche CVE Program (format 5.x) vers la forme de l'API NVD 2.0,
    pour réutiliser tel quel parse_cve (tags, produits, plages de versions…)."""
    meta = record["cveMetadata"]
    cna = record["containers"]["cna"]

    metrics = {}
    for entry in cna.get("metrics", []) or []:
        for src, dest in _CVSS_KEYS:
            if entry.get(src):
                metrics.setdefault(dest, []).append({"type": "Primary", "cvssData": entry[src]})

    weaknesses = []
    for pt in cna.get("problemTypes", []) or []:
        values = [{"value": d["cweId"]} for d in pt.get("descriptions", []) or [] if d.get("cweId")]
        if values:
            weaknesses.append({"description": values})

    # Les données éditeur (vendor / produit / versions) ont la même forme que le volet
    # « affected » de l'API NVD : on les enveloppe simplement.
    affected = [{"affectedData": [a]} for a in cna.get("affected", []) or []]

    published = (meta.get("datePublished") or "").replace("Z", "")
    return {
        "id": meta["cveId"],
        "published": published,
        "lastModified": (meta.get("dateUpdated") or published).replace("Z", ""),
        "vulnStatus": "Rejected" if meta.get("state") == "REJECTED" else "CVE Program",
        "descriptions": [{"lang": d.get("lang", "en")[:2], "value": d.get("value", "")}
                         for d in cna.get("descriptions", []) or []],
        "metrics": metrics,
        "weaknesses": weaknesses,
        "affected": affected,
        "configurations": [],          # enrichissement CPE : propre à la NVD
        "references": [{"url": r["url"], "tags": r.get("tags", [])}
                       for r in cna.get("references", []) or [] if r.get("url")],
    }


def fetch_cve_record(cve_id):
    """Fiche d'une CVE auprès du CVE Program officiel. Retourne la forme NVD 2.0, ou None."""
    try:
        r = _get(CVE_RECORD_URL.format(cve_id=cve_id), retries=2)
    except RuntimeError:
        log.warning("CVE Program indisponible pour %s", cve_id)
        return None
    if not r:
        return None
    try:
        return _record_to_nvd(r.json())
    except (KeyError, TypeError, ValueError) as e:
        log.warning("Fiche CVE Program inexploitable pour %s : %s", cve_id, e)
        return None


def search_nvd(conn, term, days=SEARCH_DEFAULT_DAYS, aliases=True, exact=False):
    """Récupère auprès de la NVD les CVE correspondant à `term` publiées sur `days` jours,
    les ajoute à la base (conservées PINNED_DAYS jours) et calcule leurs PoC.
    Retourne {"fetched": n, "added": n, "cached": bool}.

    Stratégie : avec une clé NVD, une requête coûte 0,7 s et les réponses par plage de dates
    sont petites et rapides — on découpe systématiquement (mesuré sur « drupal » / 3 ans :
    16 s en plages contre 66 s pour une requête unique, qui dépassait le délai). Sans clé,
    chaque requête coûte 6,2 s d'attente : on tente d'abord une requête sans date, et on ne
    découpe que si elle ne suffit pas.
    Les résultats sont écrits au fil de l'eau pour apparaître pendant la recherche, et une
    plage en échec n'annule pas les autres."""
    term = " ".join(term.split())
    days = max(1, min(int(days), SEARCH_DEFAULT_DAYS))
    key = term.lower()
    row = conn.execute("SELECT days, fetched_at FROM search_cache WHERE term = ?", (key,)).fetchone()
    if row and row["days"] >= days and _utcnow() - datetime.fromisoformat(row["fetched_at"]) < SEARCH_CACHE_TTL:
        return {"fetched": 0, "added": 0, "cached": True}

    now = _utcnow()
    is_id = bool(CVE_RE.fullmatch(term))
    base = {"cveId": term.upper()} if is_id else {"keywordSearch": term}
    if exact and not is_id and " " in term:
        base["keywordExactMatch"] = ""  # expression exacte : « Configuration Manager », pas les 2 mots épars
    cutoff = (now - timedelta(days=days)).isoformat()
    counts = {"fetched": 0, "added": 0, "failed": 0}

    def store(vulns):
        batch = [parse_cve(v["cve"]) for v in vulns
                 if v["cve"].get("vulnStatus") != "Rejected" and (is_id or v["cve"]["published"] >= cutoff)]
        ids = [r[0] for r, _ in batch]
        if not ids:
            return
        known = {r[0] for r in conn.execute(
            "SELECT id FROM cves WHERE id IN (%s)" % ",".join("?" * len(ids)), ids)}
        _write_batch(conn, batch)
        conn.executemany("UPDATE cves SET pinned = 1 WHERE id = ?", [(i,) for i in ids])
        update_pocs(conn, ids)
        rebuild_pocs(conn, ids)
        counts["fetched"] += len(ids)
        counts["added"] += len(set(ids) - known)

    def run(params, label):
        """Toutes les pages d'une requête. Retourne False si la requête a été abandonnée."""
        index = 0
        while True:
            search_progress[key] = label
            data = _nvd_api({**base, **params, "startIndex": index, "resultsPerPage": 2000})
            vulns = data.get("vulnerabilities", [])
            index += len(vulns)
            store(vulns)
            if not vulns or index >= data.get("totalResults", 0):
                return

    def run_ranges(ranges):
        """Chaque plage est tentée isolément : une erreur réseau n'annule pas les autres."""
        for i, r in enumerate(ranges, 1):
            try:
                run(r, f"{i}/{len(ranges)}")
            except RuntimeError:
                counts["failed"] += 1
                log.warning("Plage %d/%d en échec pour « %s », on poursuit", i, len(ranges), term)

    try:
        ranges = [] if is_id else _date_ranges(now, days)
        # Avec une clé, les plages sont nettement plus rapides et évitent les délais dépassés
        prefer_ranges = bool(get_api_key())
        if is_id:
            search_progress[key] = "1/1"
            record = fetch_cve_record(term.upper())   # officiel, immédiat, sans quota
            # Le CVE Program ne publie pas toujours de score CVSS (~10 % des fiches) : on
            # complète alors via la NVD, qui l'enrichit. Si la NVD est indisponible ou
            # limitée, on garde la fiche officielle plutôt que de ne rien afficher.
            if record is None or _pick_cvss(record["metrics"])[0] is None:
                try:
                    vulns = _nvd_api({"cveId": term.upper()}).get("vulnerabilities", [])
                except RuntimeError:
                    vulns = []
                if vulns:
                    record = vulns[0]["cve"]
            if record:
                store([{"cve": record}])
        elif len(ranges) <= 4 or prefer_ranges:
            run_ranges(ranges)
        else:
            # Une requête sans date : si tout tient sur une page, c'est terminé
            data = _nvd_api({**base, "startIndex": 0, "resultsPerPage": 2000})
            store(data.get("vulnerabilities", []))
            if data.get("totalResults", 0) > 2000:
                run_ranges(ranges)
        fetched, added = counts["fetched"], counts["added"]
        if counts["failed"] and not fetched:
            raise RuntimeError("toutes les plages ont échoué")

        # Peu de résultats : le terme est peut-être un surnom (RedSun…) absent de la NVD.
        # On cherche les dépôts GitHub qui le portent et on récupère les CVE qu'ils citent.
        if aliases and not is_id and fetched < ALIAS_THRESHOLD:
            search_progress[key] = "GitHub"
            alias_ids = github_cve_ids(term)
            for cve_id in alias_ids:
                if not conn.execute("SELECT 1 FROM cves WHERE id = ?", (cve_id,)).fetchone():
                    record = fetch_cve_record(cve_id)
                    vulns = ([{"cve": record}] if record
                             else _nvd_api({"cveId": cve_id}).get("vulnerabilities", []))
                    batch = [parse_cve(v["cve"]) for v in vulns
                             if v["cve"].get("vulnStatus") != "Rejected"]
                    if batch:
                        _write_batch(conn, batch)
                        update_pocs(conn, [cve_id])
                        added += 1
            alias_ids = [i for i in alias_ids if conn.execute("SELECT 1 FROM cves WHERE id = ?", (i,)).fetchone()]
            conn.executemany("UPDATE cves SET pinned = 1 WHERE id = ?", [(i,) for i in alias_ids])
            conn.executemany("INSERT OR IGNORE INTO cve_aliases(cve_id, alias) VALUES (?, ?)",
                             [(i, term) for i in alias_ids])
            rebuild_pocs(conn, alias_ids)
            fetched += len(alias_ids)
            if alias_ids:
                log.info("Surnom « %s » -> %s (via GitHub)", term, ", ".join(alias_ids))
    finally:
        search_progress.pop(key, None)

    if not counts["failed"]:
        conn.execute("INSERT OR REPLACE INTO search_cache(term, days, fetched_at) VALUES (?, ?, ?)",
                     (key, days, now.isoformat()))
    conn.commit()
    log.info("Recherche NVD « %s » (%d j) : %d CVE, %d nouvelles%s", term, days, fetched, added,
             f" ({counts['failed']} plage(s) en échec)" if counts["failed"] else "")
    return {"fetched": fetched, "added": added, "cached": False, "partial": bool(counts["failed"])}


# --------------------------------------------------------------------------- Trending

def get_trending(conn):
    """Les TRENDING_SIZE CVE dont les PoC GitHub créés sur TRENDING_DAYS jours sont les plus
    étoilés. Une CVE n'apparaît qu'une fois : ses dépôts sont regroupés sous le plus étoilé.
    Résultat gardé TRENDING_TTL en base ; en cas d'échec GitHub, l'ancien résultat est renvoyé."""
    cached = json.loads(db.get_meta(conn, "trending", "null") or "null")
    if cached and cached.get("v") != TRENDING_CACHE_VERSION:
        cached = None                    # cache d'une version antérieure : on le laisse tomber
    if cached and _utcnow() - datetime.fromisoformat(cached["at"]) < TRENDING_TTL:
        return cached["items"]

    since = (_utcnow() - timedelta(days=TRENDING_DAYS)).strftime("%Y-%m-%d")
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"} if GITHUB_TOKEN else None
    try:
        r = _get(GITHUB_SEARCH_URL, headers=headers, retries=2, params={
            "q": f"CVE- in:name created:>{since}", "sort": "stars", "order": "desc", "per_page": 50})
        repos = r.json().get("items", []) if r else []
    except RuntimeError:
        log.warning("Recherche GitHub trending en échec")
        return cached["items"] if cached else []

    # GitHub renvoie les dépôts triés par étoiles décroissantes : la première occurrence d'une
    # CVE est donc son PoC le plus étoilé, les suivants viennent s'y rattacher.
    items, by_cve = [], {}
    for repo in repos:
        text = f"{repo.get('full_name', '')} {repo.get('description') or ''}"
        cve_ids = list(dict.fromkeys(c.upper() for c in CVE_RE.findall(text)))
        if not cve_ids:
            continue
        poc = {"name": repo["full_name"], "url": repo["html_url"],
               "stars": repo.get("stargazers_count", 0) or 0,
               "description": repo.get("description"),
               "created": (repo.get("created_at") or "")[:10], "cve_ids": cve_ids}
        group = by_cve.get(cve_ids[0])
        if group is not None:
            group["others"].append(poc)          # même CVE : regroupée sous le dépôt principal
            continue
        if len(items) >= TRENDING_SIZE:
            continue                             # on continue à regrouper les CVE déjà listées
        group = {**poc, "cve_id": cve_ids[0], "others": []}
        by_cve[cve_ids[0]] = group
        items.append(group)

    for it in items:                             # total affiché sur la carte
        it["poc_count"] = 1 + len(it["others"])
        it["total_stars"] = it["stars"] + sum(o["stars"] for o in it["others"])
    # On conserve ces dépôts : PoC-in-GitHub en ignore une partie, et leur date de création
    # alimente le filtre « activité des PoC ».
    conn.executemany(
        "INSERT OR REPLACE INTO github_pocs(cve_id, url, name, description, stars, date) VALUES (?,?,?,?,?,?)",
        [(cid, p["url"], p["name"], p["description"], p["stars"], p["created"])
         for it in items for p in (it, *it["others"]) for cid in p["cve_ids"]])
    db.set_meta(conn, "trending", json.dumps(
        {"at": _utcnow().isoformat(), "v": TRENDING_CACHE_VERSION, "items": items}))
    conn.commit()
    known = [r[0] for r in conn.execute(
        "SELECT id FROM cves WHERE id IN (SELECT cve_id FROM github_pocs)")]
    rebuild_pocs(conn, known)
    return items


_prefetch_lock = threading.Lock()


def prefetch_cves(ids):
    """Récupère en arrière-plan (via l'API NVD, au rythme du quota) les CVE absentes de la base."""
    def worker():
        if not _prefetch_lock.acquire(blocking=False):
            return  # un préchargement est déjà en cours
        try:
            with db.connect() as conn:
                for cve_id in ids:
                    if not conn.execute("SELECT 1 FROM cves WHERE id = ?", (cve_id,)).fetchone():
                        try:
                            search_nvd(conn, cve_id)
                        except Exception as e:  # noqa: BLE001
                            log.warning("Préchargement %s en échec : %s", cve_id, e)
        finally:
            _prefetch_lock.release()
    threading.Thread(target=worker, daemon=True).start()


# --------------------------------------------------------------------------- Orchestration

def run_update():
    with status.lock:
        if status.running:
            return False
        status.running, status.error = True, None
    try:
        with db.connect() as conn:
            changed = update_nvd(conn)
            status.set(f"NVD : {len(changed)} CVE insérées/mises à jour")
            changed |= update_pocs(conn)
            update_exploitdb(conn)
            status.set("Calcul des PoC…")
            # + CVE liées à Exploit-DB ou ayant déjà des PoC (leurs sources ont pu changer)
            changed |= {r[0] for r in conn.execute(
                "SELECT id FROM cves WHERE has_poc = 1 OR id IN (SELECT cve_id FROM exploitdb)")}
            rebuild_pocs(conn, changed)
            db.set_meta(conn, "tags_hash", _tags_hash())
            db.set_meta(conn, "last_update", datetime.now().isoformat(timespec="seconds"))
            conn.commit()
        status.set("Mise à jour terminée")
    except Exception as e:  # noqa: BLE001 — on remonte l'erreur à l'interface
        log.exception("Échec de la mise à jour")
        with status.lock:
            status.error = str(e)
            status.message = "Échec de la mise à jour"
    finally:
        with status.lock:
            status.running = False
    return True


def backfill_versions():
    """Rattrapage unique : les CVE stockées avant l'ajout des plages de versions sont relues
    (flux quotidiens + recherches déjà effectuées) pour remplir cve_versions.
    Reprenable : une interruption ne refait que ce qui reste."""
    with db.connect() as conn:
        since = db.get_meta(conn, "versions_backfill_since")
        if not since:
            since = _utcnow().isoformat()
            db.set_meta(conn, "versions_backfill_since", since)
            conn.execute("DELETE FROM meta WHERE key = 'nvd_last_sync' OR key LIKE 'feed_sha:%'")
            conn.commit()
        feeds_done = db.get_meta(conn, "versions_backfill_feeds") == "1"
    if not feeds_done:
        run_update()
        with db.connect() as conn:
            db.set_meta(conn, "versions_backfill_feeds", "1")
            conn.commit()
    with db.connect() as conn:
        # Recherches antérieures au début du rattrapage (celles déjà relues ont un fetched_at plus récent)
        todo = conn.execute("SELECT term, days FROM search_cache WHERE fetched_at < ?", (since,)).fetchall()
        for i, s in enumerate(todo, 1):
            status.set(f"Versions : relecture des recherches {i}/{len(todo)} ({s['term']})", quiet=True)
            conn.execute("DELETE FROM search_cache WHERE term = ?", (s["term"],))  # contourne le cache
            conn.commit()
            try:
                search_nvd(conn, s["term"], s["days"])
            except Exception as e:  # noqa: BLE001
                log.warning("Rattrapage « %s » en échec : %s", s["term"], e)
        db.set_meta(conn, "versions_backfilled", "1")
        conn.commit()
    log.info("Rattrapage des versions terminé (%d recherches relues)", len(todo))


def start_update_thread():
    t = threading.Thread(target=run_update, daemon=True)
    t.start()
    return t
