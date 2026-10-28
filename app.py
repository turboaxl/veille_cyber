import json
import logging
import os
import threading
from datetime import date, datetime, timedelta, timezone

from flask import Flask, abort, jsonify, request, send_from_directory

import db
import magic
import updater
import versions
from tags import TAGS, search_terms, tag_for

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = Flask(__name__, static_folder="static", static_url_path="/static")

SORTS = {
    "published": "published DESC",
    "score": "score IS NULL, score DESC, published DESC",
    "stars": "max_stars DESC, poc_count DESC, published DESC",
}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"}


def _split(arg):
    return [v for v in (request.args.get(arg) or "").split(",") if v]


def _same_product(term_tokens, product):
    """« nginx » correspond à « f5 nginx open source » mais pas à « nginx-proxy-manager »."""
    tokens = set(product.lower().replace("_", " ").split())
    return all(t in tokens for t in term_tokens)


def _component_ids(conn, product, version=None):
    """CVE concernant le produit (mots entiers), et si `version` est donnée, dont une plage
    de versions contient cette version (comparaison faite en Python)."""
    tokens = product.split()
    like = f"%{tokens[0]}%"
    if version:
        vkey = versions.key(version)
        rows = conn.execute("""SELECT cve_id, product, exact, start, start_incl, end, end_incl
                               FROM cve_versions WHERE product LIKE ?""", (like,))
        return {r["cve_id"] for r in rows if _same_product(tokens, r["product"])
                and versions.matches((r["exact"], r["start"], r["start_incl"], r["end"], r["end_incl"]), vkey)}
    ids = {r["cve_id"] for r in conn.execute("SELECT cve_id, product FROM cve_versions WHERE product LIKE ?", (like,))
           if _same_product(tokens, r["product"])}
    for r in conn.execute("SELECT id, products FROM cves WHERE lower(products) LIKE ?", (like,)):
        if any(_same_product(tokens, p) for p in json.loads(r["products"] or "[]")):
            ids.add(r["id"])
    return ids


def _term_clause(term):
    """Clause SQL d'une techno : son tag si elle en porte le nom, sinon l'expression dans le texte."""
    tag = tag_for(term)
    if tag:
        return "id IN (SELECT cve_id FROM cve_tags WHERE tag = ?)", [tag]
    return "search LIKE ?", [f"%{' '.join(term.lower().split())}%"]


def _filters(conn, include_tags=True):
    """Construit la clause WHERE à partir des paramètres de requête."""
    where, params = [], []
    # Magic filter : CVE correspondant à au moins une de ses technos
    magic_terms = magic.get_terms(conn, request.args.get("magic") or "") if request.args.get("magic") else None
    if magic_terms is not None:
        clauses = [_term_clause(t) for t in magic_terms]
        where.append("(" + " OR ".join(c for c, _ in clauses) + ")" if clauses else "0")
        params += [p for _, ps in clauses for p in ps]
    # Composant / version : le produit vaut par défaut le texte recherché
    product = " ".join((request.args.get("product") or "").replace("_", " ").lower().split())
    version = (request.args.get("version") or "").strip()
    if version and not product:
        product = " ".join((request.args.get("q") or "").lower().split())
    if product:
        conn.execute("CREATE TEMP TABLE IF NOT EXISTS _vids(id TEXT PRIMARY KEY)")
        conn.execute("DELETE FROM _vids")
        conn.executemany("INSERT INTO _vids VALUES (?)", [(i,) for i in _component_ids(conn, product, version or None)])
        where.append("id IN (SELECT id FROM _vids)")
    q_tag = tag_for(request.args.get("q") or "")
    if q_tag:
        # Nom de techno tapé (« windows ») : on filtre sur le tag, qui couvre aussi les composants
        # dont la description ne cite pas la techno (ex. Microsoft Defender)
        where.append("id IN (SELECT cve_id FROM cve_tags WHERE tag = ?)")
        params.append(q_tag)
    else:
        for token in (request.args.get("q") or "").lower().split():
            where.append("search LIKE ?")
            params.append(f"%{token}%")
    if request.args.get("poc") == "1":
        where.append("has_poc = 1")
    liked = request.args.get("liked") == "1"
    if liked:
        where.append("id IN (SELECT cve_id FROM likes)")
    days = request.args.get("days", type=int)
    q = (request.args.get("q") or "").strip()
    # La période porte au choix sur la date de publication ou sur celle du PoC le plus récent
    date_field = "poc_date" if request.args.get("date_field") == "poc" else "published"
    # La période est ignorée pour les favoris et pour une recherche par identifiant
    if days and not liked and not updater.CVE_RE.fullmatch(q):
        where.append(f"{date_field} >= ?")
        params.append((datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)).isoformat())
    severities = [s for s in _split("severity") if s in SEVERITIES]
    if severities:
        clause = "severity IN (%s)" % ",".join("?" * len(severities))
        if "NONE" in severities:
            clause = f"({clause} OR severity IS NULL)"
        where.append(clause)
        params += severities
    if include_tags:
        tags = _split("tags")
        if tags:
            sub = "SELECT cve_id FROM cve_tags WHERE tag IN (%s)" % ",".join("?" * len(tags))
            params += tags
            if request.args.get("tag_mode") == "all" and len(tags) > 1:
                sub += " GROUP BY cve_id HAVING COUNT(*) = ?"
                params.append(len(tags))
            where.append(f"id IN ({sub})")
    return (" WHERE " + " AND ".join(where)) if where else "", params


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/cves")
def list_cves():
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(200, max(10, request.args.get("per_page", 50, type=int)))
    order = SORTS.get(request.args.get("sort"), SORTS["published"])

    with db.connect() as conn:
        where, params = _filters(conn)
        total = conn.execute(f"SELECT COUNT(*) FROM cves{where}", params).fetchone()[0]
        rows = conn.execute(
            f"""SELECT id, published, description, score, severity, tags, has_poc, poc_count, max_stars,
                       id IN (SELECT cve_id FROM likes) AS liked
                FROM cves{where} ORDER BY {order} LIMIT ? OFFSET ?""",
            params + [per_page, (page - 1) * per_page]).fetchall()

        # Compteurs par tag (tous filtres appliqués sauf le filtre tag lui-même)
        where_nt, params_nt = _filters(conn, include_tags=False)
        counts = conn.execute(
            f"""SELECT t.tag, COUNT(*) AS n FROM cve_tags t JOIN cves ON cves.id = t.cve_id{where_nt}
                GROUP BY t.tag ORDER BY n DESC, t.tag""", params_nt).fetchall()

    items = [{
        "id": r["id"], "published": r["published"], "score": r["score"], "severity": r["severity"],
        "summary": (r["description"] or "")[:220], "tags": json.loads(r["tags"]),
        "has_poc": bool(r["has_poc"]), "poc_count": r["poc_count"],
        "max_stars": r["max_stars"] if r["max_stars"] >= 0 else None, "liked": bool(r["liked"]),
    } for r in rows]
    # Tous les tags de la taxonomie sont renvoyés (même à 0) pour pouvoir lancer une recherche NVD
    by_tag = {r["tag"]: r["n"] for r in counts}
    tags = sorted(({"tag": t, "count": by_tag.get(t, 0)} for t in TAGS), key=lambda t: (-t["count"], t["tag"].lower()))
    return jsonify(total=total, page=page, per_page=per_page, items=items, tags=tags)


@app.get("/api/cves/<cve_id>")
def get_cve(cve_id):
    cve_id = cve_id.upper()
    if not updater.CVE_RE.fullmatch(cve_id):
        abort(404)
    with db.connect() as conn:
        r = conn.execute("SELECT * FROM cves WHERE id = ?", (cve_id,)).fetchone()
        if not r:
            # CVE absente (ex. ouverte depuis la page trending) : on la récupère auprès de la NVD
            try:
                updater.search_nvd(conn, cve_id)
            except Exception as e:  # noqa: BLE001
                logging.warning("Récupération de %s en échec : %s", cve_id, e)
            r = conn.execute("SELECT * FROM cves WHERE id = ?", (cve_id,)).fetchone()
        liked = conn.execute("SELECT 1 FROM likes WHERE cve_id = ?", (cve_id,)).fetchone() is not None
        aliases = [a[0] for a in conn.execute("SELECT alias FROM cve_aliases WHERE cve_id = ?", (cve_id,))]
        ranges = conn.execute("SELECT product, exact, start, start_incl, end, end_incl FROM cve_versions WHERE cve_id = ?",
                              (cve_id,)).fetchall()
    if not r:
        abort(404)
    pocs = json.loads(r["pocs"])
    poc_urls = {p["url"] for p in pocs}
    articles = [ref for ref in json.loads(r["refs"]) if ref["url"] not in poc_urls]
    return jsonify(
        id=r["id"], published=r["published"], last_modified=r["last_modified"], status=r["status"],
        description=r["description"], score=r["score"], severity=r["severity"],
        cvss_version=r["cvss_version"], vector=r["vector"], cwes=json.loads(r["cwes"]),
        products=json.loads(r["products"]), tags=json.loads(r["tags"]),
        pocs=pocs, articles=articles, liked=liked, aliases=aliases,
        versions=[{"product": r["product"], "range": versions.describe(tuple(r)[1:])} for r in ranges
                  if r["exact"] or r["start"] or r["end"]],
    )


@app.post("/api/likes/<cve_id>")
def set_like(cve_id):
    cve_id = cve_id.upper()
    if not updater.CVE_RE.fullmatch(cve_id):
        abort(400)
    liked = bool((request.get_json(silent=True) or {}).get("liked"))
    with db.connect() as conn:
        if liked:
            conn.execute("INSERT OR IGNORE INTO likes(cve_id, liked_at) VALUES (?, ?)",
                         (cve_id, datetime.now().isoformat(timespec="seconds")))
        else:
            conn.execute("DELETE FROM likes WHERE cve_id = ?", (cve_id,))
        missing = liked and not conn.execute("SELECT 1 FROM cves WHERE id = ?", (cve_id,)).fetchone()
    if missing:
        updater.prefetch_cves([cve_id])  # pour qu'elle apparaisse dans les favoris
    return jsonify(cve_id=cve_id, liked=liked)


@app.get("/api/trending")
def trending():
    with db.connect() as conn:
        items = updater.get_trending(conn)
        ids = list({i["cve_id"] for i in items})
        marks = ",".join("?" * len(ids))
        known = {r["id"]: r for r in conn.execute(
            f"SELECT id, score, severity, description, tags, has_poc FROM cves WHERE id IN ({marks})", ids)} if ids else {}
        likes = {r[0] for r in conn.execute(f"SELECT cve_id FROM likes WHERE cve_id IN ({marks})", ids)} if ids else set()
    missing = [i for i in ids if i not in known]
    if missing:
        updater.prefetch_cves(missing)  # complétées en arrière-plan, l'interface rafraîchit ensuite
    out = []
    for i in items:
        r = known.get(i["cve_id"])
        out.append({**i, "liked": i["cve_id"] in likes, "known": r is not None,
                    "score": r["score"] if r else None, "severity": r["severity"] if r else None,
                    "summary": (r["description"] or "")[:220] if r else None,
                    "tags": json.loads(r["tags"]) if r else []})
    return jsonify(items=out, pending=len(missing), days=updater.TRENDING_DAYS)


def _run_searches(conn, items, days, progress_key=None):
    """Lance les recherches NVD de plusieurs technos (une techno peut valoir plusieurs termes)."""
    total = {"fetched": 0, "added": 0, "cached": True, "partial": False}
    for i, (label, terms, aliases, exact) in enumerate(items, 1):
        if progress_key:
            updater.search_progress[progress_key] = f"{i}/{len(items)} · {label}"
        for t in terms:
            r = updater.search_nvd(conn, t, days, aliases=aliases, exact=exact)
            total["fetched"] += r["fetched"]
            total["added"] += r["added"]
            total["cached"] = total["cached"] and r["cached"]
            total["partial"] = total["partial"] or r.get("partial", False)
    if progress_key:
        updater.search_progress.pop(progress_key, None)
    return total


@app.post("/api/search-nvd")
def search_nvd():
    """Complète la base avec les CVE de la NVD correspondant à un terme ou à un tag."""
    body = request.get_json(silent=True) or {}
    term = (body.get("term") or "").strip()
    # Une techno (tag cliqué, ou nom de tag tapé) est cherchée sous tous ses termes NVD ;
    # un terme libre peut aussi être un surnom (RedSun…) résolu via GitHub.
    tag = body.get("tag") if body.get("tag") in TAGS else tag_for(term)
    terms = search_terms(tag) if tag else [term]
    if not tag and not 3 <= len(term) <= 100:
        return jsonify(error="Terme trop court ou trop long"), 400
    days = body.get("days") or updater.SEARCH_DEFAULT_DAYS
    try:
        with db.connect() as conn:
            total = _run_searches(conn, [(term or tag, terms, not tag, False)], days)
    except Exception as e:  # noqa: BLE001 — erreur réseau / quota NVD remontée à l'interface
        logging.warning("Recherche NVD « %s » en échec : %s", term or tag, e)
        return jsonify(error="NVD indisponible, réessayez dans un instant"), 502
    return jsonify(term=", ".join(terms), **total)


# --------------------------------------------------------------------------- Magic filters

def _magic_name(name):
    name = " ".join((name or "").split())
    if not 1 <= len(name) <= 60:
        abort(400, "Nom invalide")
    return name


@app.get("/api/magic")
def magic_list():
    with db.connect() as conn:
        return jsonify(magic.all_filters(conn))


@app.post("/api/magic")
def magic_create():
    name = _magic_name((request.get_json(silent=True) or {}).get("name"))
    with db.connect() as conn:
        if magic.get_terms(conn, name) is not None:
            return jsonify(error="Un magic filter porte déjà ce nom"), 409
        magic.create(conn, name)
        return jsonify(magic.all_filters(conn))


@app.delete("/api/magic/<path:name>")
def magic_delete(name):
    with db.connect() as conn:
        magic.delete(conn, name)
        return jsonify(magic.all_filters(conn))


@app.post("/api/magic/<path:name>/terms")
def magic_terms(name):
    """Ajoute ({"add": "nginx"}) ou retire ({"remove": "nginx"}) une techno d'un magic filter."""
    body = request.get_json(silent=True) or {}
    with db.connect() as conn:
        terms = magic.get_terms(conn, name)
        if terms is None:
            abort(404)
        add = " ".join((body.get("add") or "").split())
        if add and len(add) <= 100 and add.lower() not in (t.lower() for t in terms):
            terms.append(add)
        if body.get("remove"):
            terms = [t for t in terms if t.lower() != body["remove"].lower()]
        magic.set_terms(conn, name, terms)
        return jsonify(magic.all_filters(conn))


@app.post("/api/magic/<path:name>/search")
def magic_search(name):
    """Recherche NVD de toutes les technos d'un magic filter (expression exacte)."""
    days = (request.get_json(silent=True) or {}).get("days") or updater.SEARCH_DEFAULT_DAYS
    with db.connect() as conn:
        terms = magic.get_terms(conn, name)
    if terms is None:
        abort(404)
    try:
        with db.connect() as conn:
            items = []
            for t in terms:
                tag = tag_for(t)
                items.append((t, search_terms(tag) if tag else [t], False, True))
            total = _run_searches(conn, items, days, progress_key="magic")
    except Exception as e:  # noqa: BLE001
        logging.warning("Magic filter « %s » en échec : %s", name, e)
        updater.search_progress.pop("magic", None)
        return jsonify(error="NVD indisponible, réessayez dans un instant"), 502
    return jsonify(term=name, **total)


# --------------------------------------------------------------------------- Réglages

def _nvd_key_state(conn):
    """État de la clé NVD. La clé complète n'est jamais renvoyée au navigateur."""
    stored = db.get_meta(conn, "nvd_api_key")
    key = updater.get_api_key()
    return {
        "set": bool(key),
        "source": "interface" if stored else ("environnement" if key else None),
        "hint": f"…{key[-4:]}" if key else None,
    }


@app.get("/api/settings")
def get_settings():
    with db.connect() as conn:
        return jsonify(nvd_key=_nvd_key_state(conn))


@app.post("/api/settings/nvd-key")
def set_nvd_key():
    key = ((request.get_json(silent=True) or {}).get("key") or "").strip()
    if not 8 <= len(key) <= 100:
        return jsonify(error="Clé invalide (longueur inattendue)"), 400
    valid = updater.validate_api_key(key)
    if valid is None:
        return jsonify(error="NVD injoignable : clé non vérifiable, réessayez"), 502
    if not valid:
        return jsonify(error="Clé refusée par la NVD"), 400
    with db.connect() as conn:
        db.set_meta(conn, "nvd_api_key", key)
        conn.commit()
        updater.set_api_key(key)
        logging.info("Clé NVD enregistrée (…%s) : recherches accélérées", key[-4:])
        return jsonify(ok=True, nvd_key=_nvd_key_state(conn))


@app.delete("/api/settings/nvd-key")
def delete_nvd_key():
    with db.connect() as conn:
        conn.execute("DELETE FROM meta WHERE key = 'nvd_api_key'")
        conn.commit()
        updater.load_api_key(conn)   # repli éventuel sur la variable d'environnement
        return jsonify(ok=True, nvd_key=_nvd_key_state(conn))


@app.get("/api/status")
def get_status():
    with db.connect() as conn:
        last = db.get_meta(conn, "last_update")
        total = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    return jsonify(**updater.status.as_dict(), last_update=last, total=total,
                   searches=dict(updater.search_progress),
                   window_days=updater.WINDOW_DAYS)


@app.post("/api/update")
def trigger_update():
    if updater.status.as_dict()["running"]:
        return jsonify(started=False, reason="Mise à jour déjà en cours"), 409
    updater.start_update_thread()
    return jsonify(started=True)


def startup():
    db.init()
    with db.connect() as conn:
        # Recalcule les tags uniquement si tags.py a changé depuis le dernier lancement
        updater.load_api_key(conn)
        updater.retag_if_needed(conn)
        magic.seed(conn)
        # Texte de recherche v2 (sans les descriptions de PoC) : recalcul unique de toutes les CVE ;
        # sinon on garde les surnoms (RedSun…) à jour dans le texte de leurs CVE
        if db.get_meta(conn, "search_text_version") != "2":
            logging.info("Recalcul du texte de recherche…")
            updater.rebuild_pocs(conn, [r[0] for r in conn.execute("SELECT id FROM cves")])
            db.set_meta(conn, "search_text_version", "2")
            conn.commit()
        else:
            updater.rebuild_pocs(conn, [r[0] for r in conn.execute("SELECT DISTINCT cve_id FROM cve_aliases")])
        # Date du PoC le plus récent : calcul unique pour les CVE déjà en base
        if db.get_meta(conn, "poc_date_version") != "1":
            logging.info("Calcul des dates de PoC…")
            updater.rebuild_pocs(conn, [r[0] for r in conn.execute(
                """SELECT id FROM cves WHERE has_poc = 1 OR id IN (SELECT cve_id FROM poc_cache)
                   OR id IN (SELECT cve_id FROM exploitdb) OR id IN (SELECT cve_id FROM github_pocs)""")])
            db.set_meta(conn, "poc_date_version", "1")
            conn.commit()
        last = db.get_meta(conn, "last_update")
        backfilled = db.get_meta(conn, "versions_backfilled") == "1"
    if not backfilled:
        logging.info("Rattrapage des plages de versions en arrière-plan")
        threading.Thread(target=updater.backfill_versions, daemon=True).start()
    elif not last or date.fromisoformat(last[:10]) < date.today():
        logging.info("Données absentes ou datant d'avant aujourd'hui : mise à jour en arrière-plan")
        updater.start_update_thread()


if __name__ == "__main__":
    startup()
    host = os.environ.get("VEILLE_HOST", "127.0.0.1")
    port = int(os.environ.get("VEILLE_PORT", "6060"))
    app.run(host=host, port=port, debug=False, threaded=True)
