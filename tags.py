"""Taxonomie des technologies.

Chaque tag est associé à une liste d'expressions régulières (insensibles à la casse)
testées sur : description de la CVE + produits affectés (vendor / product / CPE).
Une CVE peut recevoir plusieurs tags. Modifiez librement cette liste :
les tags sont recalculés au démarrage de l'application.
"""
import re

TAGS = {
    # --- Systèmes d'exploitation ---
    "Windows": [r"\bwindows\b", r"\bwin32k\b", r"microsoft defender", r"malware protection engine",
                r"\bntfs\b", r"\bhyper-v\b"],
    "Linux": [r"\blinux\b"],
    "Ubuntu": [r"\bubuntu\b", r"\bcanonical\b"],
    "Debian": [r"\bdebian\b"],
    "Red Hat": [r"\bred ?hat\b", r"\brhel\b"],
    "SUSE": [r"\bsuse\b", r"\bopensuse\b"],
    "macOS": [r"\bmacos\b", r"\bmac os x\b"],
    "Apple iOS": [r"\bios \d", r"\bipados\b", r"\biphone os\b"],
    "Android": [r"\bandroid\b"],
    "FreeBSD": [r"\bfreebsd\b"],

    # --- Microsoft / Identité ---
    "Active Directory": [r"active directory", r"domain controller", r"\bkerberos\b", r"\bntlm\w*",
                         r"\bnetlogon\b", r"\bad ?cs\b", r"certificate services", r"group policy"],
    "LDAP": [r"\bldap\w*"],
    "Exchange": [r"\bexchange server\b", r"microsoft exchange"],
    "SharePoint": [r"\bsharepoint\b"],
    "Office": [r"microsoft office", r"microsoft word", r"microsoft excel", r"\boutlook\b",
               r"\bpowerpoint\b", r"microsoft 365"],
    "IIS": [r"\biis\b", r"internet information services"],
    "Hyper-V": [r"\bhyper-v\b"],
    "MSSQL": [r"\bsql server\b", r"\bmssql\b"],
    "Azure": [r"\bazure\b", r"\bentra id\b"],
    "RDP": [r"remote desktop", r"\brdp\b"],
    "SMB": [r"\bsmb(v?\d)?\b", r"server message block"],
    "Samba": [r"\bsamba\b"],

    # --- Serveurs web / langages / frameworks ---
    "Apache": [r"\bapache\b"],
    "Tomcat": [r"\btomcat\b"],
    "Nginx": [r"\bnginx\b"],
    "PHP": [r"\bphp\b"],
    "Java": [r"\bjava\b", r"\bjdk\b", r"\bjre\b"],
    "Spring": [r"\bspring (framework|boot|security|cloud)\b", r"\bvmware spring\b"],
    "Node.js": [r"\bnode\.?js\b", r"\bnpm\b"],
    "Python": [r"\bpython\b", r"\bpypi\b"],
    "Django": [r"\bdjango\b"],
    "Ruby on Rails": [r"\brails\b", r"\bruby on rails\b"],
    ".NET": [r"\.net framework", r"\.net core", r"\basp\.net\b", r"\bmicrosoft \.net\b"],

    # --- CMS ---
    "WordPress": [r"\bwordpress\b"],
    "Drupal": [r"\bdrupal\b"],
    "Joomla": [r"\bjoomla\b"],

    # --- DevOps / Cloud ---
    "Docker": [r"\bdocker\b", r"\bcontainerd\b", r"\brunc\b"],
    "Kubernetes": [r"\bkubernetes\b", r"\bk8s\b", r"\bkubelet\b", r"\bhelm\b"],
    "Jenkins": [r"\bjenkins\b"],
    "GitLab": [r"\bgitlab\b"],
    "Atlassian": [r"\batlassian\b", r"\bconfluence\b", r"\bjira\b", r"\bbitbucket\b"],
    "Grafana": [r"\bgrafana\b"],
    "Elastic": [r"\belasticsearch\b", r"\bkibana\b", r"\blogstash\b"],

    # --- Virtualisation / accès distant ---
    "VMware": [r"\bvmware\b", r"\bvcenter\b", r"\besxi\b", r"\bvsphere\b"],
    "Citrix": [r"\bcitrix\b", r"\bnetscaler\b"],
    "Veeam": [r"\bveeam\b"],

    # --- Équipements réseau / sécurité ---
    "Fortinet": [r"\bfortinet\b", r"\bforti\w+"],
    "Palo Alto": [r"palo alto", r"\bpan-os\b", r"\bglobalprotect\b"],
    "Cisco": [r"\bcisco\b"],
    "Juniper": [r"\bjuniper\b", r"\bjunos\b"],
    "Ivanti": [r"\bivanti\b", r"pulse (connect )?secure", r"connect secure"],
    "SonicWall": [r"\bsonicwall\b", r"\bsonicos\b"],
    "F5": [r"\bf5\b", r"\bbig-?ip\b"],
    "Check Point": [r"check ?point"],
    "Zyxel": [r"\bzyxel\b"],
    "D-Link": [r"\bd-?link\b"],
    "TP-Link": [r"\btp-?link\b"],
    "Netgear": [r"\bnetgear\b"],
    "MikroTik": [r"\bmikrotik\b", r"\brouteros\b"],
    "QNAP": [r"\bqnap\b"],
    "Synology": [r"\bsynology\b"],
    "VPN": [r"\bvpn\b"],

    # --- Bases de données / ERP ---
    "MySQL": [r"\bmysql\b", r"\bmariadb\b"],
    "PostgreSQL": [r"\bpostgre(s|sql)\b"],
    "Oracle": [r"\boracle\b"],
    "Redis": [r"\bredis\b"],
    "MongoDB": [r"\bmongodb\b"],
    "SAP": [r"\bsap\b", r"\bnetweaver\b"],

    # --- Navigateurs / clients ---
    "Chrome": [r"\bchrome\b", r"\bchromium\b", r"\bv8\b"],
    "Firefox": [r"\bfirefox\b", r"\bthunderbird\b"],

    # --- Services / libs ---
    "OpenSSH": [r"\bopenssh\b"],
    "OpenSSL": [r"\bopenssl\b"],
    "Zimbra": [r"\bzimbra\b"],
    "Roundcube": [r"\broundcube\b"],
}

# Termes envoyés à la NVD pour une techno (tag cliqué ou nom de tag tapé dans la recherche).
# La recherche NVD ne porte que sur la description : on ajoute les composants qui ne
# mentionnent pas le nom de la techno (ex. Microsoft Defender pour Windows).
SEARCH_TERMS = {
    "Windows": ["Windows", "Microsoft Defender"],
    "Apple iOS": ["iOS"],
    "Exchange": ["Exchange Server"],
    "Office": ["Microsoft Office"],
    "RDP": ["Remote Desktop"],
    "F5": ["BIG-IP"],
    "Elastic": ["Elasticsearch"],
    "Palo Alto": ["PAN-OS", "GlobalProtect"],
    "Spring": ["Spring Framework", "Spring Boot"],
    "Active Directory": ["Active Directory", "Kerberos", "NTLM"],
}


def search_terms(tag: str) -> list[str]:
    return SEARCH_TERMS.get(tag, [tag])


def tag_for(term: str):
    """Tag dont le nom correspond au terme tapé (« windows » -> « Windows »), sinon None."""
    t = term.strip().lower()
    return next((tag for tag in TAGS if tag.lower() == t), None)


# Tags « plateforme » : une techno mainstream est citée dans une foule de descriptions sans être
# le produit vulnérable (« Apache HTTP Server on Windows », « NVIDIA driver for Windows and Linux »,
# « OZOLS on Windows »). Pour ces tags, on n'accepte le match que sur les produits affectés
# (vendor / produit CPE + CNA), pas sur la description. Repli sur la description quand la NVD n'a
# pas encore publié de produit affecté, pour ne pas perdre les CVE toutes récentes.
PRODUCT_SCOPED = {
    "Windows", "Linux", "Ubuntu", "Debian", "Red Hat", "SUSE",
    "macOS", "Apple iOS", "Android", "FreeBSD", "MSSQL",
}

# Éditeur attendu pour certains tags de plateforme. Chaque produit affecté est stocké sous la
# forme « <éditeur> <produit> » : exiger le bon éditeur écarte les produits tiers dont le NOM
# contient la techno (plugin WordPress « Popover Windows », « CrowdStrike Falcon sensor for
# Windows », « Apache Lounge Windows »…). Sert aussi de garde-fou dans le repli sur la
# description, quand la NVD n'a pas encore publié de produit affecté.
PRODUCT_VENDOR = {
    "Windows": r"microsoft",
    "macOS": r"apple",
    "Apple iOS": r"apple",
    "Android": r"google|android",
}

_COMPILED = {tag: [re.compile(p, re.IGNORECASE) for p in pats] for tag, pats in TAGS.items()}
# Dans un produit l'éditeur est en tête ; dans une description il peut être n'importe où.
_VENDOR_IN_PRODUCT = {t: re.compile(rf"^(?:{p})\b", re.IGNORECASE) for t, p in PRODUCT_VENDOR.items()}
_VENDOR_IN_TEXT = {t: re.compile(rf"\b(?:{p})\b", re.IGNORECASE) for t, p in PRODUCT_VENDOR.items()}


def compute_tags(description: str, products=()) -> list[str]:
    """Tags d'une CVE à partir de sa description et de ses produits affectés."""
    description = description or ""
    out = []
    for tag, pats in _COMPILED.items():
        if tag not in PRODUCT_SCOPED:
            ok = any(p.search(f"{description} {' '.join(products)}") for p in pats)
        elif products:
            # Le produit vulnérable lui-même doit correspondre, et venir du bon éditeur
            vendor = _VENDOR_IN_PRODUCT.get(tag)
            ok = any(any(p.search(entry) for p in pats) and (vendor is None or vendor.search(entry))
                     for entry in products)
        else:
            # Aucun produit publié : repli sur la description, en exigeant l'éditeur
            vendor = _VENDOR_IN_TEXT.get(tag)
            ok = any(p.search(description) for p in pats) and (vendor is None or vendor.search(description))
        if ok:
            out.append(tag)
    return out
