"""Plages de versions affectées et comparaison de versions.

Deux sources dans une CVE NVD :
  - configurations CPE (analyse NVD) : version exacte dans le CPE, ou bornes
    versionStartIncluding / versionStartExcluding / versionEndIncluding / versionEndExcluding
  - données « affected » déclarées par l'éditeur (CNA) : version, lessThan, lessThanOrEqual
Chaque plage est stockée sous forme de tuple :
    (produit, exacte, début, début_inclus, fin, fin_incluse)
"""
import re

_VERSION_RE = re.compile(r"^v?\d[\w.\-+~:]*$", re.IGNORECASE)
_PREFIX_RE = re.compile(r"^(<=|<|≤|before|prior to|up to|through)\s*(v?\d[\w.\-+~]*)$", re.IGNORECASE)
_ANY = {"", "*", "-", "0", "n/a", "na", "unspecified", "all", "unknown"}


def clean(v):
    """Version exploitable (« 1.24.0 ») ou None (« * », « n/a », texte libre…)."""
    v = (v or "").replace("\\", "").strip()
    if v.lower() in _ANY or not _VERSION_RE.match(v):
        return None
    return v


def key(v):
    """Clé de tri : « 1.24.0rc1 » -> ((0, 1), (0, 24), (1, 'rc'), (0, 1)) ; les .0 finaux sont ignorés."""
    parts = [(0, int(p)) if p.isdigit() else (1, p) for p in re.findall(r"\d+|[a-z]+", v.lower().lstrip("v"))]
    while parts and parts[-1] == (0, 0):
        parts.pop()
    return tuple(parts)


def matches(rng, version_key):
    """La version (déjà passée par key()) est-elle dans la plage (exacte, début, début_inclus, fin, fin_incluse) ?"""
    exact, start, start_incl, end, end_incl = rng
    if exact:
        return key(exact) == version_key
    if not start and not end:
        return False  # aucune information de version : on ne peut pas conclure
    if start:
        s = key(start)
        if version_key < s or (version_key == s and not start_incl):
            return False
    if end:
        e = key(end)
        if version_key > e or (version_key == e and not end_incl):
            return False
    return True


def describe(rng):
    """Texte lisible d'une plage : « 1.0 ≤ v < 1.24.3 », « = 2.4.1 »."""
    exact, start, start_incl, end, end_incl = rng
    if exact:
        return f"= {exact}"
    left = f"{start} {'≤' if start_incl else '<'} " if start else ""
    right = f" {'≤' if end_incl else '<'} {end}" if end else ""
    return f"{left}v{right}" if (left or right) else "version non précisée"


def extract(cve):
    """Toutes les plages de versions affectées d'une CVE (format brut NVD)."""
    out = []
    for conf in cve.get("configurations", []) or []:
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable", True):
                    continue
                parts = m.get("criteria", "").split(":")
                if len(parts) <= 5:
                    continue
                product = f"{parts[3]} {parts[4]}".replace("_", " ").replace("\\", "").lower()
                start = clean(m.get("versionStartIncluding")) or clean(m.get("versionStartExcluding"))
                end = clean(m.get("versionEndIncluding")) or clean(m.get("versionEndExcluding"))
                if start or end:
                    out.append((product, None, start, bool(clean(m.get("versionStartIncluding"))),
                                end, bool(clean(m.get("versionEndIncluding")))))
                elif clean(parts[5]):
                    out.append((product, clean(parts[5]), None, False, None, False))
                else:
                    out.append((product, None, None, False, None, False))

    for aff in cve.get("affected", []) or []:
        for d in aff.get("affectedData", []) or []:
            product = f"{d.get('vendor', '')} {d.get('product', '')}".strip().lower()
            if not product or product in ("n/a n/a", "n/a"):
                continue
            for v in d.get("versions", []) or []:
                if v.get("status") != "affected":
                    continue
                raw = (v.get("version") or "").strip()
                lt, lte = clean(v.get("lessThan")), clean(v.get("lessThanOrEqual"))
                if lt or lte:
                    out.append((product, None, clean(raw), True, lte or lt, bool(lte)))
                    continue
                m = _PREFIX_RE.match(raw)
                if m:  # « < 2.3 », « before 1.4.2 », « up to 4.1.0 »…
                    incl = m.group(1).lower() in ("<=", "≤", "up to", "through")
                    out.append((product, None, None, False, clean(m.group(2)), incl))
                elif clean(raw):
                    out.append((product, clean(raw), None, False, None, False))
    return list(dict.fromkeys(out))
