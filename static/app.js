"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);
const SEV_LABEL = { CRITICAL: "Critique", HIGH: "Haute", MEDIUM: "Moyenne", LOW: "Basse" };
const PER_PAGE = 50;
const TAGS_COLLAPSED = 12;
const SUMMARY_MAX = 150;
const SIDEBAR = { min: 200, max: 480, default: 260 };
const VIEWS = ["trending", "list", "likes"];

const DEFAULTS = { q: "", poc: false, days: "30", sort: "published", tagMode: "any", product: "", version: "", magic: "", dateField: "published" };
const state = { view: "trending", ...DEFAULTS, severity: new Set(), tags: new Set(), page: 1, depth: "180" };
let tagCounts = [];
let tagsExpanded = false;
let wasUpdating = false;
let statusTimer;
let trendingTimer;
let remoteSeq = 0;
let remoteFadeTimer;

// ------------------------------------------------------------------ utils
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const fmtDate = (iso, opts = { day: "numeric", month: "short" }) => iso
  ? new Date(iso + (iso.length > 10 && !iso.endsWith("Z") ? "Z" : "")).toLocaleDateString("fr-FR", opts) : "";

const safeUrl = (u) => /^https?:\/\//i.test(u) ? u : "#";

function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

// Coupe au dernier mot entier avant `max` caractères et ajoute [...]
function truncate(text, max) {
  text = (text || "").replace(/\s+/g, " ").trim();
  if (text.length <= max) return esc(text);
  const cut = text.slice(0, max);
  const at = cut.lastIndexOf(" ");
  return esc((at > max * 0.6 ? cut.slice(0, at) : cut).replace(/[\s,.;:]+$/, "")) + ' <span class="more">[...]</span>';
}

// Préférences locales (le stockage peut être indisponible : on ignore alors silencieusement)
const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* ignoré */ } },
};

// ------------------------------------------------------------------ cœur (like)
const HEART_PATH = "M12 20.5S3 15 3 8.8C3 6.1 5.1 4 7.7 4c1.8 0 3.4 1 4.3 2.5C12.9 5 14.5 4 16.3 4 18.9 4 21 6.1 21 8.8 21 15 12 20.5 12 20.5z";

const heartBtn = (id, liked) => `
  <button class="heart${liked ? " liked" : ""}" type="button" data-like="${esc(id)}" aria-pressed="${liked}"
          title="${liked ? "Retirer des favoris" : "Ajouter aux favoris"}">
    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="${HEART_PATH}"/></svg>
  </button>`;

// Score CVSS : le chiffre passe en rouge à partir de 8
const CVSS_RED = 8;
const hpBar = (score, severity) => score == null
  ? `<span class="hp"><small>CVSS</small><span class="sev">N/A</span></span>`
  : `<span class="hp"><small>CVSS</small><b class="${score >= CVSS_RED ? "high" : ""}">${score.toFixed(1)}</b><span class="sev">${esc(SEV_LABEL[severity] || "")}</span></span>`;

// ------------------------------------------------------------------ URL <-> état
function readUrl() {
  const p = new URLSearchParams(location.search);
  state.view = VIEWS.includes(p.get("view")) ? p.get("view") : (p.toString() ? "list" : "trending");
  state.q = p.get("q") || "";
  state.poc = p.get("poc") === "1";
  state.days = p.has("days") ? p.get("days") : DEFAULTS.days;
  state.severity = new Set((p.get("severity") || "").split(",").filter(Boolean));
  state.sort = p.get("sort") || DEFAULTS.sort;
  state.tags = new Set((p.get("tags") || "").split(",").filter(Boolean));
  state.tagMode = p.get("tag_mode") === "all" ? "all" : "any";
  state.product = p.get("product") || "";
  state.magic = p.get("magic") || "";
  state.dateField = p.get("date_field") === "poc" ? "poc" : "published";
  state.version = p.get("version") || "";
  state.page = parseInt(p.get("page") || "1", 10);
}

function filterParams() {
  const p = new URLSearchParams();
  if (state.q) p.set("q", state.q);
  if (state.poc) p.set("poc", "1");
  p.set("days", state.days);
  if (state.severity.size) p.set("severity", [...state.severity].join(","));
  if (state.sort !== DEFAULTS.sort) p.set("sort", state.sort);
  if (state.tags.size) p.set("tags", [...state.tags].join(","));
  if (state.tagMode === "all") p.set("tag_mode", "all");
  if (state.product) p.set("product", state.product);
  if (state.magic) p.set("magic", state.magic);
  if (state.dateField === "poc") p.set("date_field", "poc");
  if (state.version) p.set("version", state.version);
  if (state.view === "likes") p.set("liked", "1");
  return p;
}

function writeUrl() {
  if (state.view === "trending") { history.replaceState(null, "", location.pathname); return; }
  const p = filterParams();
  p.delete("liked");
  p.set("view", state.view);
  if (state.page > 1) p.set("page", state.page);
  history.replaceState(null, "", "?" + p);
}

const hasFilters = () => state.q || state.poc || state.days !== DEFAULTS.days || state.severity.size || state.tags.size
  || state.product || state.version || state.magic || state.dateField !== DEFAULTS.dateField;

function syncControls() {
  for (const [sel, val] of [["#search", state.q], ["#f-product", state.product], ["#f-version", state.version]]) {
    if (document.activeElement !== $(sel)) $(sel).value = val;
  }
  $("#f-poc").setAttribute("aria-pressed", String(state.poc));
  $("#f-tag-all").setAttribute("aria-pressed", String(state.tagMode === "all"));
  $("#f-tag-all").hidden = state.tags.size < 2;
  $("#btn-reset").hidden = !hasFilters();
  $$("#f-days button").forEach((b) => b.classList.toggle("active", b.dataset.v === state.days));
  $$("#f-severity .opt").forEach((b) => b.classList.toggle("active", state.severity.has(b.dataset.v)));
  $$("#f-sort .opt").forEach((b) => b.classList.toggle("active", b.dataset.v === state.sort));
  $$("#f-depth .opt").forEach((b) => b.classList.toggle("active", b.dataset.v === state.depth));
  $$("#f-datefield .opt").forEach((b) => b.classList.toggle("active", b.dataset.v === state.dateField));
  $("#depth-label").textContent = DEPTHS[state.depth];
  // Compteurs sur les sections repliables
  const comp = state.tags.size + (state.product ? 1 : 0) + (state.version ? 1 : 0);
  $("#sev-badge").textContent = state.severity.size || "";
  $("#comp-badge").textContent = comp || "";
  $("#magic-badge").textContent = state.magic ? "1" : "";
  renderMagic();
  renderAddMagic();
  $$(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === state.view));
}

// ------------------------------------------------------------------ vues
function setView(view) {
  state.view = view;
  state.page = 1;
  render();
}

function render() {
  clearTimeout(trendingTimer);
  $("#view-trending").hidden = state.view !== "trending";
  $("#view-list").hidden = state.view === "trending";
  writeUrl();
  syncControls();
  if (state.view === "trending") {
    loadTrending();
    loadTags();
  } else {
    loadList();
  }
}

// Toute recherche / tout filtre quitte la page trending pour la liste
function applyFilters() {
  if (state.view === "trending") state.view = "list";
  state.page = 1;
  render();
}

// ------------------------------------------------------------------ liste
async function loadList() {
  const p = filterParams();
  p.set("per_page", PER_PAGE);
  p.set("page", state.page);
  const data = await (await fetch("/api/cves?" + p)).json();
  tagCounts = data.tags;
  renderList(data);
  renderTags();
}

async function loadTags() {
  const p = filterParams();
  p.set("per_page", 10);
  tagCounts = (await (await fetch("/api/cves?" + p)).json()).tags;
  renderTags();
}

function renderList(data) {
  const likes = state.view === "likes";
  $("#list-title").textContent = likes ? "Favoris" : state.magic ? `✦ ${state.magic}` : "Vulnérabilités";
  $("#result-count").textContent = `${data.total.toLocaleString("fr-FR")} résultat${data.total > 1 ? "s" : ""}`;
  $("#list").innerHTML = data.items.length ? data.items.map((v) => `
    <article class="card" tabindex="0" data-id="${esc(v.id)}">
      <div class="card-top">
        <span class="cve-id">${esc(v.id)}</span>
        ${v.has_poc ? `<span class="poc" title="${v.poc_count} exploit(s) public(s)${v.max_stars != null ? ` · ★ ${v.max_stars}` : ""}">POC</span>` : ""}
        ${hpBar(v.score, v.severity)}
        <span class="date">${fmtDate(v.published)}</span>
      </div>
      <p class="summary">${truncate(v.summary, SUMMARY_MAX)}</p>
      ${v.tags.length ? `<div class="tags">${esc(v.tags.join(" · "))}</div>` : ""}
      ${heartBtn(v.id, v.liked)}
    </article>`).join("")
    : `<p class="empty">${likes ? "Aucun favori pour l'instant. Cliquez sur un cœur pour en ajouter." : "Aucune vulnérabilité ne correspond à ces filtres."}</p>`;

  const pages = Math.max(1, Math.ceil(data.total / data.per_page));
  // Saut direct : sur de longues listes, atteindre une page éloignée au clic-à-clic est pénible
  $("#pager").innerHTML = pages > 1 ? `
    <button data-p="1" ${data.page <= 1 ? "disabled" : ""} title="Première page">⏮</button>
    <button data-p="${data.page - 1}" ${data.page <= 1 ? "disabled" : ""}>◀ PRÉC.</button>
    <span class="jump">page
      <input id="page-input" type="number" min="1" max="${pages}" value="${data.page}"
             aria-label="Aller à la page"> / ${pages}</span>
    <button data-p="${data.page + 1}" ${data.page >= pages ? "disabled" : ""}>SUIV. ▶</button>
    <button data-p="${pages}" ${data.page >= pages ? "disabled" : ""} title="Dernière page">⏭</button>` : "";
}

function renderTags() {
  const filter = $("#tag-search").value.trim().toLowerCase();
  // Les tags sélectionnés restent toujours visibles en tête
  const counts = new Map(tagCounts.map((t) => [t.tag, t.count]));
  const selected = [...state.tags].map((t) => ({ tag: t, count: counts.get(t) || 0 }));
  const others = tagCounts.filter((t) => !state.tags.has(t.tag));
  let shown = [...selected, ...others].filter((t) => !filter || t.tag.toLowerCase().includes(filter));
  const total = shown.length;
  if (!tagsExpanded) shown = shown.slice(0, Math.max(TAGS_COLLAPSED, selected.length));

  $("#tag-list").innerHTML = shown.map((t) => `
    <button class="opt${state.tags.has(t.tag) ? " active" : ""}" data-tag="${esc(t.tag)}">
      ${esc(t.tag)}<span class="count">${t.count}</span>
    </button>`).join("") || `<p class="note">Aucun tag</p>`;

  $("#tag-search").hidden = !tagsExpanded;
  const more = $("#tag-more");
  more.hidden = !tagsExpanded && total <= TAGS_COLLAPSED;
  more.textContent = tagsExpanded ? "Réduire" : `Voir les ${total} technos`;
}

// ------------------------------------------------------------------ trending
async function loadTrending(attempt = 0) {
  const list = $("#trending-list");
  if (!attempt) list.innerHTML = `<p class="empty"><span class="spinner"></span>Recherche des PoC sur GitHub…</p>`;
  let data;
  try {
    data = await (await fetch("/api/trending")).json();
  } catch {
    list.innerHTML = `<p class="empty">GitHub ne répond pas. Réessayez plus tard.</p>`;
    return;
  }
  if (state.view !== "trending") return;
  list.innerHTML = data.items.length ? data.items.map((t, i) => `
    <article class="card trend" tabindex="0" data-id="${esc(t.cve_id)}">
      <div class="card-top">
        <span class="rank">${String(i + 1).padStart(2, "0")}</span>
        <span class="repo">${esc(t.name)}</span>
        <span class="stars">★ ${t.stars.toLocaleString("fr-FR")}</span>
        ${t.poc_count > 1 ? `<span class="poc-count">${t.poc_count} PoC</span>` : ""}
      </div>
      <div class="sub">
        <span class="cve-id">${esc(t.cve_ids.join(" · "))}</span>
        ${t.known ? hpBar(t.score, t.severity) : ""}
        ${t.tags.length ? `<span class="tags">${esc(t.tags.join(" · "))}</span>` : ""}
      </div>
      <p class="summary">${truncate(t.description || t.summary || "", SUMMARY_MAX) || '<span class="more">Pas de description.</span>'}</p>
      ${(t.others || []).length ? `<div class="others">Autres PoC :
        ${t.others.slice(0, 4).map((o) => `<a href="${esc(safeUrl(o.url))}" target="_blank" rel="noopener">${esc(o.name)} <span class="stars">★ ${o.stars}</span></a>`).join("")}
        ${t.others.length > 4 ? `<span class="more">+ ${t.others.length - 4}</span>` : ""}</div>` : ""}
      <div class="foot">
        <span>Créé le ${fmtDate(t.created, { day: "numeric", month: "short", year: "numeric" })}</span>
        <a href="${esc(safeUrl(t.url))}" target="_blank" rel="noopener">Voir sur GitHub ▶</a>
      </div>
      ${heartBtn(t.cve_id, t.liked)}
    </article>`).join("")
    : `<p class="empty">Aucun PoC trouvé sur GitHub.</p>`;

  // Les CVE absentes de la base sont récupérées en arrière-plan : on rafraîchit quelques fois
  if (data.pending && attempt < 30) trendingTimer = setTimeout(() => loadTrending(attempt + 1), 8000);
}

// ------------------------------------------------------------------ likes
async function toggleLike(btn) {
  const id = btn.dataset.like;
  const liked = !btn.classList.contains("liked");
  const setAll = (on) => $$(`.heart[data-like="${CSS.escape(id)}"]`).forEach((b) => {
    b.classList.toggle("liked", on);
    b.setAttribute("aria-pressed", String(on));
    b.title = on ? "Retirer des favoris" : "Ajouter aux favoris";
  });
  setAll(liked);
  btn.classList.remove("pop"); void btn.offsetWidth; btn.classList.add("pop");
  try {
    const res = await fetch(`/api/likes/${encodeURIComponent(id)}`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ liked }),
    });
    if (!res.ok) throw new Error();
    if (state.view === "likes" && !liked) loadList();
  } catch {
    setAll(!liked);
  }
}

// ------------------------------------------------------------------ détail
async function openDetail(id) {
  $("#drawer-content").innerHTML = `<p class="note"><span class="spinner"></span>Chargement de ${esc(id)}…</p>`;
  $("#drawer").classList.add("open");
  $("#drawer").setAttribute("aria-hidden", "false");
  $("#drawer-backdrop").hidden = false;
  $("#drawer").scrollTop = 0;

  const res = await fetch("/api/cves/" + encodeURIComponent(id));
  if (!res.ok) {
    $("#drawer-content").innerHTML = `<h2>${esc(id)}</h2><p class="note">Cette CVE est introuvable sur la NVD pour le moment.</p>`;
    return;
  }
  const v = await res.json();
  const hasGithub = v.pocs.some((p) => p.source === "github");

  $("#drawer-content").innerHTML = `
    <div class="head"><h2>${esc(v.id)}</h2>${heartBtn(v.id, v.liked)}</div>
    ${v.aliases.length ? `<div class="aliases">Alias : ${v.aliases.map((a) => `<b>${esc(a)}</b>`).join(", ")}</div>` : ""}
    <div class="meta">
      ${hpBar(v.score, v.severity)}
      <span>Publiée le ${fmtDate(v.published, { day: "numeric", month: "long", year: "numeric" })}</span>
      <a href="https://nvd.nist.gov/vuln/detail/${esc(v.id)}" target="_blank" rel="noopener">NVD ▶</a>
    </div>
    ${v.tags.length ? `<div class="meta tags">${esc(v.tags.join(" · "))}</div>` : ""}

    <h4>DESCRIPTION</h4>
    <p class="description">${esc(v.description)}</p>
    ${v.vector || v.cwes.length ? `<div class="small">${esc(v.vector || "")}${v.vector && v.cwes.length ? " · " : ""}${v.cwes.map((c) =>
      `<a href="https://cwe.mitre.org/data/definitions/${esc(c.slice(4))}.html" target="_blank" rel="noopener">${esc(c)}</a>`).join(", ")}</div>` : ""}

    <h4>EXPLOITS PUBLICS${v.pocs.length ? ` (${v.pocs.length})` : ""}</h4>
    ${v.pocs.length ? `
      ${hasGithub ? `<p class="note warn">PoC non vérifiés : relisez le code avant de l'exécuter.</p>` : ""}
      <ul class="poc-list">${v.pocs.map((p) => `
        <li>
          <a href="${esc(safeUrl(p.url))}" target="_blank" rel="noopener">${esc(p.name || p.url)}</a>
          <span class="stars">${p.stars != null ? `★ ${p.stars}` : esc(p.source)}</span>
          ${p.description ? `<span class="desc">${esc(p.description)}</span>` : ""}
        </li>`).join("")}</ul>`
      : `<p class="note">Aucun code d'exploitation public référencé.</p>`}

    ${v.versions.length ? `<h4>VERSIONS AFFECTÉES</h4>
      <ul class="versions">${v.versions.slice(0, 15).map((r) =>
        `<li><span class="product">${esc(r.product)}</span><code>${esc(r.range)}</code></li>`).join("")}
      ${v.versions.length > 15 ? `<li class="note">+ ${v.versions.length - 15} autres</li>` : ""}</ul>`
    : v.products.length ? `<h4>PRODUITS AFFECTÉS</h4>
      <ul class="products">${v.products.slice(0, 10).map((p) => `<li>${esc(p)}</li>`).join("")}
      ${v.products.length > 10 ? `<li class="note">+ ${v.products.length - 10} autres</li>` : ""}</ul>` : ""}
    ${v.versions.length ? "" : `<p class="note">Pas de plage de versions publiée pour cette CVE.</p>`}

    ${v.articles.length ? `<h4>RÉFÉRENCES (${v.articles.length})</h4>
      <ul class="ref-list">${v.articles.map((r) => `
        <li><a href="${esc(safeUrl(r.url))}" target="_blank" rel="noopener">${esc(r.url)}</a>${(r.tags || []).length ? `<span class="rtag">${esc(r.tags.join(", "))}</span>` : ""}</li>`).join("")}</ul>` : ""}
  `;
}

function closeDetail() {
  $("#drawer").classList.remove("open");
  $("#drawer").setAttribute("aria-hidden", "true");
  $("#drawer-backdrop").hidden = true;
}

// ------------------------------------------------------------------ recherche NVD à la demande
// Seule la barre de recherche interroge la NVD, sur la profondeur choisie dans le menu
// « Recherche sur… » (6 mois par défaut). Les filtres ne font que filtrer ce qui est déjà en base.
const DEPTHS = { 30: "1 mois", 90: "3 mois", 180: "6 mois", 365: "1 an", 730: "2 ans", 1095: "3 ans" };
const DEFAULT_DEPTH = "30";
let remoteProgressTimer;

async function searchRemote(payload, label, url = "/api/search-nvd") {
  const seq = ++remoteSeq;
  const el = $("#remote-status");
  clearTimeout(remoteFadeTimer);
  el.className = "remote";
  const waiting = (extra = "") =>
    `<span class="spinner"></span>NVD : recherche « ${esc(label)} » sur ${DEPTHS[state.depth]}…${extra}`;
  el.innerHTML = waiting();
  // Les résultats arrivent page par page : on affiche la progression et on rafraîchit la liste
  clearInterval(remoteProgressTimer);
  remoteProgressTimer = setInterval(async () => {
    if (seq !== remoteSeq) return;
    try {
      const s = await (await fetch("/api/status")).json();
      const pages = Object.values(s.searches || {})[0];
      const m = (s.searches || {}).magic;
      if (m) el.innerHTML = waiting(` (techno ${esc(m)})`);
      else if (pages === "GitHub") el.innerHTML = waiting(" (recherche du surnom sur GitHub)");
      else if (pages && pages !== "1/1") el.innerHTML = waiting(` (${esc(pages)})`);
      if (state.view !== "trending") loadList();
    } catch { /* ignoré */ }
  }, 4000);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...payload, days: parseInt(state.depth, 10) }),
    });
    const data = await res.json();
    if (seq !== remoteSeq) return;  // une recherche plus récente a pris le relais
    if (!res.ok) {
      el.className = "remote error";
      el.textContent = `${data.error || "Recherche NVD en échec"}`;
      return;
    }
    if (data.cached) { el.textContent = ""; return; }
    const n = data.added, plural = n > 1 ? "s" : "";
    el.className = data.partial ? "remote error" : "remote done";
    // Une recherche partielle affiche quand même ce qui a été récupéré : rien n'est perdu
    el.textContent = data.partial
      ? `NVD partiellement indisponible : ${n} vulnérabilité${plural} ajoutée${plural}, relancez pour compléter`
      : n ? `+ ${n} vulnérabilité${plural} ajoutée${plural} depuis la NVD`
          : "NVD : rien de nouveau";
    if (data.fetched && state.view !== "trending") loadList();
  } catch {
    if (seq === remoteSeq) { el.className = "remote error"; el.textContent = "Recherche NVD en échec"; }
  } finally {
    if (seq === remoteSeq) clearInterval(remoteProgressTimer);  // fin du suivi de progression
  }
  remoteFadeTimer = setTimeout(() => el.classList.add("fade"), 6000);
}

// La profondeur est un paramètre de recherche : la changer relance la recherche en cours
// (magic filter ou texte) et aligne la fenêtre de la liste. Sans recherche active, ce n'est
// qu'une préférence : on ne touche pas à la période de la liste.
function applyDepthChange() {
  if (!state.magic && state.q.length < 3) return;
  state.days = state.depth;
  applyFilters();
  if (state.magic) {
    searchRemote({ days: parseInt(state.depth, 10) }, state.magic,
                 `/api/magic${magicPath(state.magic)}/search`);
  } else {
    searchRemote({ term: state.q }, state.q);
  }
}

// Une nouvelle recherche repart propre : les filtres du menu de gauche sont effacés et la
// profondeur revient à sa valeur par défaut. La barre de recherche est le point d'entrée
// principal : on évite qu'un filtre oublié masque les résultats.
function resetForNewSearch() {
  state.poc = DEFAULTS.poc;
  state.severity.clear();
  state.tags.clear();
  state.product = DEFAULTS.product;
  state.version = DEFAULTS.version;
  state.magic = DEFAULTS.magic;
  state.dateField = DEFAULTS.dateField;
  state.depth = DEFAULT_DEPTH;
  store.set("search-depth", state.depth);
  state.days = state.depth;
}

const remoteSearchQuery = debounce(() => {
  if (state.q.length >= 3) searchRemote({ term: state.q }, state.q);
}, 900);

// ------------------------------------------------------------------ magic filters
// Recherches prédéfinies multi-technos (ex. « Active Directory »), créées et modifiées par l'utilisateur.
let magicFilters = [];
const magicEditing = new Set();   // filtres dont l'édition est dépliée

async function magicApi(path, method = "GET", body) {
  const res = await fetch("/api/magic" + path, {
    method, headers: body ? { "Content-Type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Erreur");
  magicFilters = data;
  syncControls();
  return data;
}
const magicPath = (name) => "/" + encodeURIComponent(name);

function renderMagic() {
  $("#magic-list").innerHTML = magicFilters.map((f) => {
    const open = magicEditing.has(f.name);
    return `
    <div class="magic" data-name="${esc(f.name)}">
      <div class="magic-head">
        <button class="opt magic-run${state.magic === f.name ? " active" : ""}" title="Lancer la recherche sur ses ${f.terms.length} technos">
          ${esc(f.name)}<span class="count">${f.terms.length}</span>
        </button>
        <button class="icon magic-edit${open ? " on" : ""}" title="Modifier les technos" aria-expanded="${open}">✎</button>
      </div>
      ${open ? `
      <div class="magic-body">
        <div class="chips">${f.terms.map((t) => `
          <span class="chip">${esc(t)}<button class="chip-x" data-term="${esc(t)}" title="Retirer ${esc(t)}">×</button></span>`).join("")
          || '<span class="hint">Aucune techno pour l\'instant.</span>'}</div>
        <form class="magic-add" autocomplete="off"><input class="field" name="term" placeholder="+ Ajouter une techno (ex : ADCS, SCCM…)" maxlength="100"></form>
        <button class="link magic-delete" type="button">Supprimer ce magic filter</button>
      </div>` : ""}
    </div>`;
  }).join("") || '<p class="hint">Aucun magic filter.</p>';
}

// Bouton « + Ajouter « nginx » à un magic filter » visible pendant une recherche
function renderAddMagic() {
  const show = !!state.q && state.view !== "trending";
  $("#add-magic").hidden = !show;
  if (!show) return;
  $("#btn-add-magic").textContent = `+ Ajouter « ${state.q} » à un magic filter`;
  $("#f-add-magic").innerHTML = magicFilters.map((f) => {
    const has = f.terms.some((t) => t.toLowerCase() === state.q.toLowerCase());
    return `<button class="opt${has ? " active" : ""}" data-name="${esc(f.name)}" ${has ? "disabled" : ""}>${esc(f.name)}${has ? " (déjà présent)" : ""}</button>`;
  }).join("") + '<button class="opt new" data-new="1">+ Nouveau magic filter…</button>';
}

function runMagic(name) {
  if (state.magic === name) { state.magic = ""; applyFilters(); return; }  // second clic : désactive
  state.magic = name;
  state.q = "";
  state.days = state.depth;  // la liste couvre la période recherchée
  applyFilters();
  searchRemote({ days: parseInt(state.depth, 10) }, name, `/api/magic${magicPath(name)}/search`);
}

function flash(msg, error = false) {
  const el = $("#remote-status");
  clearTimeout(remoteFadeTimer);
  el.className = `remote ${error ? "error" : "done"}`;
  el.textContent = msg;
  remoteFadeTimer = setTimeout(() => el.classList.add("fade"), 4000);
}

function bindMagic() {
  $("#magic-list").addEventListener("click", async (e) => {
    const box = e.target.closest(".magic"); if (!box) return;
    const name = box.dataset.name;
    if (e.target.closest(".magic-run")) runMagic(name);
    else if (e.target.closest(".magic-edit")) {
      magicEditing.has(name) ? magicEditing.delete(name) : magicEditing.add(name);
      renderMagic();
    } else if (e.target.closest(".chip-x")) {
      await magicApi(magicPath(name) + "/terms", "POST", { remove: e.target.closest(".chip-x").dataset.term });
      if (state.magic === name) loadList();
    } else if (e.target.closest(".magic-delete")) {
      if (!confirm(`Supprimer le magic filter « ${name} » ?`)) return;
      if (state.magic === name) state.magic = "";
      await magicApi(magicPath(name), "DELETE");
      applyFilters();
    }
  });
  $("#magic-list").addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = e.target.closest(".magic").dataset.name;
    const term = e.target.term.value.trim(); if (!term) return;
    await magicApi(magicPath(name) + "/terms", "POST", { add: term });
    $(`.magic[data-name="${CSS.escape(name)}"] .magic-add input`)?.focus();
    if (state.magic === name) loadList();
  });
  $("#magic-new").addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = e.target.name.value.trim(); if (!name) return;
    try {
      await magicApi("", "POST", { name });
      e.target.reset();
      magicEditing.add(name);
      renderMagic();
      $(`.magic[data-name="${CSS.escape(name)}"] .magic-add input`)?.focus();
    } catch (err) { flash(err.message, true); }
  });

  $("#btn-add-magic").addEventListener("click", () => setMenu("addmagic", $("#f-add-magic").hidden));
  $("#f-add-magic").addEventListener("click", async (e) => {
    const b = e.target.closest("button"); if (!b || b.disabled) return;
    setMenu("addmagic", false);
    if (b.dataset.new) {  // ouvre le menu sur la création d'un filtre
      e.stopPropagation();  // sinon le clic « hors du menu » le refermerait aussitôt
      setSidebarOpen(true);
      $("#g-magic").open = true;
      $("#magic-new input").focus();
      return;
    }
    await magicApi(magicPath(b.dataset.name) + "/terms", "POST", { add: state.q });
    flash(`« ${state.q} » ajouté à ${b.dataset.name}`);
  });
}

// ------------------------------------------------------------------ clé API NVD
// La clé est stockée côté application ; le navigateur n'en reçoit qu'un indice (4 derniers
// caractères), jamais la valeur complète.
let nvdKey = { set: false, source: null, hint: null };

function renderKey() {
  $("#key-badge").textContent = nvdKey.set ? "✓" : "";
  $("#key-remove").hidden = nvdKey.source !== "interface";
  const el = $("#key-status");
  if (!nvdKey.set) {
    el.textContent = "Aucune clé : recherches limitées à 5 requêtes / 30 s.";
  } else if (nvdKey.source === "environnement") {
    el.textContent = `Clé fournie par l'environnement (${nvdKey.hint}).`;
  } else {
    el.textContent = `Clé active (${nvdKey.hint}).`;
  }
}

async function loadKey() {
  try {
    nvdKey = (await (await fetch("/api/settings")).json()).nvd_key;
    renderKey();
  } catch { /* ignoré */ }
}

function bindKey() {
  $("#key-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const input = $("#key-input");
    const key = input.value.trim();
    if (!key) return;
    const el = $("#key-status");
    el.textContent = "Vérification auprès de la NVD…";
    try {
      const res = await fetch("/api/settings/nvd-key", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key }),
      });
      const data = await res.json();
      if (!res.ok) { el.textContent = data.error || "Clé refusée"; return; }
      nvdKey = data.nvd_key;
      input.value = "";
      renderKey();
      flash("Clé NVD enregistrée : recherches accélérées");
    } catch {
      el.textContent = "Enregistrement impossible";
    }
  });
  $("#key-remove").addEventListener("click", async () => {
    try {
      nvdKey = (await (await fetch("/api/settings/nvd-key", { method: "DELETE" })).json()).nvd_key;
      renderKey();
    } catch { /* ignoré */ }
  });
}

// ------------------------------------------------------------------ menus déroulants (Tri, profondeur)
const MENUS = { sort: ["#btn-sort", "#f-sort"], depth: ["#btn-depth", "#f-depth"], addmagic: ["#btn-add-magic", "#f-add-magic"] };
function setMenu(name, open) {
  for (const [key, [btn, list]] of Object.entries(MENUS)) {
    const on = key === name && open;
    $(list).hidden = !on;
    $(btn).setAttribute("aria-expanded", String(on));
  }
}

// ------------------------------------------------------------------ menu latéral
function setSidebarWidth(w) {
  w = Math.round(Math.min(SIDEBAR.max, Math.max(SIDEBAR.min, w)));
  $("#layout").style.setProperty("--sidebar-w", w + "px");
  return w;
}

function setSidebarOpen(open) {
  $("#layout").classList.toggle("collapsed", !open);
  $("#btn-sidebar").setAttribute("aria-expanded", String(open));
  store.set("sidebar-open", open ? "1" : "0");
}
const toggleSidebar = () => setSidebarOpen($("#layout").classList.contains("collapsed"));

function initSidebar() {
  setSidebarWidth(parseInt(store.get("sidebar-width"), 10) || SIDEBAR.default);
  setSidebarOpen(store.get("sidebar-open") === "1");  // masqué par défaut
  $("#btn-sidebar").addEventListener("click", toggleSidebar);

  const resizer = $("#resizer");
  resizer.addEventListener("pointerdown", (e) => {
    e.preventDefault();
    resizer.setPointerCapture(e.pointerId);
    $("#layout").classList.add("resizing");
    const left = $("#sidebar").getBoundingClientRect().left;
    const move = (ev) => setSidebarWidth(ev.clientX - left);
    const up = (ev) => {
      resizer.removeEventListener("pointermove", move);
      resizer.removeEventListener("pointerup", up);
      $("#layout").classList.remove("resizing");
      store.set("sidebar-width", setSidebarWidth(ev.clientX - left));
    };
    resizer.addEventListener("pointermove", move);
    resizer.addEventListener("pointerup", up);
  });
  resizer.addEventListener("dblclick", () => store.set("sidebar-width", setSidebarWidth(SIDEBAR.default)));
}

// ------------------------------------------------------------------ statut de mise à jour
async function pollStatus() {
  clearTimeout(statusTimer);
  try {
    const s = await (await fetch("/api/status")).json();
    const el = $("#status-text");
    $("#btn-update").disabled = s.running;
    if (s.running) {
      el.innerHTML = `<span class="spinner"></span>${esc(s.message)}`;
    } else if (s.error) {
      el.innerHTML = `<span class="error" title="${esc(s.error)}">Échec de la mise à jour</span>`;
    } else {
      el.textContent = s.last_update
        ? `MAJ ${new Date(s.last_update).toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" })}`
        : "Aucune donnée";
    }
    if (wasUpdating && !s.running && state.view !== "trending") loadList();
    wasUpdating = s.running;
    statusTimer = setTimeout(pollStatus, s.running ? 2000 : 30000);
  } catch {
    statusTimer = setTimeout(pollStatus, 5000);
  }
}

// ------------------------------------------------------------------ événements
function bind() {
  $("#search").addEventListener("input", debounce((e) => {
    const q = e.target.value.trim();
    const changed = q !== state.q;
    state.q = q;
    if (changed && q) resetForNewSearch();
    applyFilters();
    remoteSearchQuery();
  }, 300));
  $("#f-product").addEventListener("input", debounce((e) => {
    state.product = e.target.value.trim();
    applyFilters();
  }, 500));
  $("#f-version").addEventListener("input", debounce((e) => {
    state.version = e.target.value.trim();
    applyFilters();
  }, 400));
  $("#brand").addEventListener("click", () => setView("trending"));
  $$(".nav-item").forEach((b) => b.addEventListener("click", () => setView(b.dataset.view)));

  $("#f-poc").addEventListener("click", () => { state.poc = !state.poc; applyFilters(); });
  $("#f-tag-all").addEventListener("click", () => {
    state.tagMode = state.tagMode === "all" ? "any" : "all"; applyFilters();
  });
  $("#f-datefield").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.dateField = b.dataset.v; applyFilters();
  });
  $("#f-days").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.days = b.dataset.v; applyFilters();
  });
  $("#f-severity").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.severity.has(b.dataset.v) ? state.severity.delete(b.dataset.v) : state.severity.add(b.dataset.v);
    applyFilters();
  });
  $("#btn-sort").addEventListener("click", () => setMenu("sort", $("#f-sort").hidden));
  $("#f-sort").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.sort = b.dataset.v;
    setMenu("sort", false);
    applyFilters();
  });
  $("#btn-depth").addEventListener("click", () => setMenu("depth", $("#f-depth").hidden));
  $("#f-depth").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.depth = b.dataset.v;
    store.set("search-depth", state.depth);
    setMenu("depth", false);
    syncControls();
    applyDepthChange();
  });
  $("#tag-list").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-tag]"); if (!b) return;
    const t = b.dataset.tag;
    state.tags.has(t) ? state.tags.delete(t) : state.tags.add(t);
    applyFilters();
  });
  $("#tag-search").addEventListener("input", renderTags);
  $("#tag-more").addEventListener("click", () => {
    tagsExpanded = !tagsExpanded;
    if (!tagsExpanded) $("#tag-search").value = "";
    renderTags();
    if (tagsExpanded) $("#tag-search").focus();
  });

  $("#btn-reset").addEventListener("click", () => {
    Object.assign(state, DEFAULTS, { severity: new Set(), tags: new Set(), page: 1 });
    render();
  });

  const goToPage = (n) => {
    state.page = Math.max(1, n);
    writeUrl();
    loadList();
    window.scrollTo({ top: 0 });
  };
  $("#pager").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-p]"); if (!b || b.disabled) return;
    goToPage(parseInt(b.dataset.p, 10));
  });
  $("#pager").addEventListener("keydown", (e) => {
    if (e.key !== "Enter" || e.target.id !== "page-input") return;
    e.preventDefault();
    const n = parseInt(e.target.value, 10);
    if (n) goToPage(Math.min(n, parseInt(e.target.max, 10) || n));
  });

  // Cartes (liste + trending + détail) : cœur, lien externe ou ouverture du détail
  document.addEventListener("click", (e) => {
    // Un clic en dehors du menu (et de son bouton / sa poignée) le referme.
    // composedPath() est figé au moment du clic : fiable même si l'élément cliqué est re-rendu.
    const path = e.composedPath();
    if (!$$(".sort-menu").length || ![...$$(".sort-menu")].some((m) => path.includes(m))) setMenu(null, false);
    const inMenu = [$("#sidebar"), $("#btn-sidebar"), $("#resizer")].some((el) => path.includes(el));
    if (!inMenu && !$("#layout").classList.contains("collapsed")) setSidebarOpen(false);

    const heart = e.target.closest(".heart");
    if (heart) { e.stopPropagation(); toggleLike(heart); return; }
    if (e.target.closest("a")) return;
    const card = e.target.closest(".card");
    if (card) openDetail(card.dataset.id);
  });
  $("#drawer-close").addEventListener("click", closeDetail);
  $("#drawer-backdrop").addEventListener("click", closeDetail);
  document.addEventListener("keydown", (e) => {
    const typing = ["INPUT", "TEXTAREA"].includes(document.activeElement.tagName);
    if (e.key === "Escape") { closeDetail(); setMenu(null, false); }
    if (e.key === "Enter" && document.activeElement.classList.contains("card")) openDetail(document.activeElement.dataset.id);
    if (typing) return;
    if (e.key === "/") { e.preventDefault(); $("#search").focus(); }
    if (e.key === "[") toggleSidebar();
  });

  $("#btn-update").addEventListener("click", async () => {
    await fetch("/api/update", { method: "POST" });
    wasUpdating = true;
    pollStatus();
  });
}

readUrl();
$("#g-magic").open = !!state.magic;
state.depth = DEPTHS[store.get("search-depth")] ? store.get("search-depth") : DEFAULT_DEPTH;
// Les sections repliables contenant un filtre actif sont ouvertes au chargement
$("#g-severity").open = state.severity.size > 0;
$("#g-component").open = state.tags.size > 0 || !!state.product || !!state.version;
initSidebar();
bind();
bindMagic();
bindKey();
magicApi("").catch(() => {});
loadKey();
render();
pollStatus();
