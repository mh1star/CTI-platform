/* CTI Security Intelligence Platform — واجهة لوحة المراقبة */

const $ = (sel) => document.querySelector(sel);
const API = window.location.origin;

const FALLBACK_LABELS = {
  IP: "IP", DOMAIN: "نطاق", URL: "رابط", EMAIL: "بريد", CVE: "CVE", CWE: "CWE",
  HASH_SHA256: "SHA256", HASH_SHA1: "SHA1", HASH_MD5: "MD5",
  MALWARE: "برمجية", TECHNIQUE: "تقنية", GROUP: "مجموعة", VULN: "ثغرة",
  FILE_NAME: "ملف", FILE_PATH: "مسار", SOFTWARE: "برنامج", CAMPAIGN: "حملة",
  HASH: "تجزئة", CWE: "CWE",
};
let TYPE_LABELS = { ...FALLBACK_LABELS };
let TYPE_COLORS = {
  IP: "#22d3ee", DOMAIN: "#60a5fa", URL: "#818cf8", EMAIL: "#c084fc",
  CVE: "#f87171", CWE: "#fb923c", MALWARE: "#f472b6", TECHNIQUE: "#4ade80",
  GROUP: "#facc15", VULN: "#fb7185", HASH: "#34d399",
  FILE_NAME: "#a3a3a3", FILE_PATH: "#a3a3a3",
};

const RISK_AR = { low: "منخفض", medium: "متوسط", high: "مرتفع", critical: "حرج" };

/* ---------------- tabs ---------------- */
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll(".tabpage").forEach((p) =>
      p.classList.toggle("active", p.id === `tab-${btn.dataset.tab}`)
    );
  });
});

/* ---------------- status ---------------- */
async function checkStatus() {
  try {
    const r = await fetch(`${API}/health`);
    const d = await r.json();
    const el = $("#apiStatus");
    el.className = "status ok";
    el.innerHTML = `<span class="dot"></span> متصل · النموذج: <b>${d.model}</b>`;
  } catch {
    $("#apiStatus").className = "status bad";
    $("#apiStatus").innerHTML = `<span class="dot"></span> تعذّر الاتصال بالخادم`;
  }
}

/* ---------------- shared helpers ---------------- */
function fmt(x) { return (x === undefined || x === null || isNaN(x)) ? "—" : Number(x).toFixed(4); }

function typeLabel(t) { return TYPE_LABELS[t] || t; }

async function apiFetch(path, opts) {
  const r = await fetch(`${API}${path}`, opts);
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try { const d = await r.json(); msg = d.detail || msg; } catch {}
    throw new Error(msg);
  }
  return r.json();
}

/* ---------------- dashboard ---------------- */
async function loadDashboard() {
  const data = await apiFetch("/api/eval");
  const tk = data.token_level || {};
  const pipe = data.pipeline || {};
  const pipeAll = pipe.ALL || {};
  const macro = tk.macro_avg || {};

  setVal("#kpiMacroF1", fmt(macro.f1));
  setVal("#kpiMacroP", fmt(macro.precision));
  setVal("#kpiMacroR", fmt(macro.recall));
  setVal("#kpiAcc", fmt(tk.accuracy));
  setVal("#kpiPipeF1", fmt(pipeAll.f1));
  $("#trainedAt").textContent = data.trained_at ? `آخر تدريب: ${new Date(data.trained_at).toLocaleString("ar-EG")}` : "";

  renderPipeTable((pipe.per_type || {}), pipeAll);
  renderSpanTable(data.span_level || {});
  renderConfusion(tk.confusion_matrix || {});
  renderModelFacts(data);
}

function setVal(sel, txt) { $(sel) && ($(sel).textContent = txt); }

function rowHTML(fam, m) {
  const f1 = m.f1;
  const bad = f1 < 0.8 && m.support > 0;
  return `<tr${bad ? ' class="drop-row"' : ""}>
    <td>${typeLabel(fam)}${f1 < 0.8 && m.support > 0 ? " ⚠" : ""}</td>
    <td>${fmt(m.precision)}</td><td>${fmt(m.recall)}</td><td>${fmt(m.f1)}</td>
    <td>${m.support || 0}</td></tr>`;
}

function renderPipeTable(perType, all) {
  const tb = $("#pipeTable tbody");
  tb.innerHTML = Object.keys(perType).sort().map((fam) => rowHTML(fam, perType[fam])).join("");
  tb.insertAdjacentHTML("beforeend", `<tr style="border-top:2px solid var(--line2);font-weight:700">
    <td>الإجمالي</td><td>${fmt(all.precision)}</td><td>${fmt(all.recall)}</td><td>${fmt(all.f1)}</td><td>${all.support || 0}</td></tr>`);
}

function renderSpanTable(span) {
  const tb = $("#spanTable tbody");
  tb.innerHTML = Object.keys(span).sort().filter((k) => k !== "ALL").map((k) =>
    `<tr><td>${typeLabel(k)}</td><td>${fmt(span[k].precision)}</td><td>${fmt(span[k].recall)}</td><td>${fmt(span[k].f1)}</td></tr>`
  ).join("");
  if (span.ALL) {
    tb.insertAdjacentHTML("beforeend", `<tr style="border-top:2px solid var(--line2);font-weight:700">
      <td>الإجمالي</td><td>${fmt(span.ALL.precision)}</td><td>${fmt(span.ALL.recall)}</td><td>${fmt(span.ALL.f1)}</td></tr>`);
  }
  const rowNote = document.createElement("div");
}

function renderConfusion(cm) {
  const wrap = $("#confusionMatrix");
  const labels = Object.keys(cm);
  if (!labels.length) { wrap.innerHTML = '<span class="muted">لا توجد بيانات</span>'; return; }
  const max = Math.max(...labels.map((r) => Math.max(...Object.keys(cm[r]).map((c) => cm[r][c]))), 1);
  const short = (l) => l.replace("B-", "B/").replace("I-", "I/");
  let html = `<table class="cm-table" dir="ltr"><thead><tr><th>حقيقي ↓ / متوقع →</th>`;
  labels.forEach((c) => { html += `<th>${short(c)}</th>`; });
  html += "</tr></thead><tbody>";
  labels.forEach((r) => {
    html += `<tr><th>${short(r)}</th>`;
    labels.forEach((c) => {
      const v = cm[r][c] || 0;
      const a = v ? 0.14 + 0.86 * (v / max) : 0;
      const diag = r === c;
      const color = diag ? `rgba(34,211,238,${a})` : `rgba(255,140,90,${a * 0.7})`;
      html += `<td class="cm-cell ${v ? "" : "cm-zero"}" style="background:${v ? color : ""}">${v || ""}</td>`;
    });
    html += "</tr>";
  });
  html += "</tbody></table>";
  wrap.innerHTML = html;
}

function renderModelFacts(data) {
  const facts = $("#modelFacts");
  const d = data.dataset || {};
  const m = data.model || {};
  const rows = [];
  if (m.labels) rows.push(["التسميات", m.labels.join(", ")]);
  if (m.n_labels !== undefined) rows.push(["عدد التسميات", m.n_labels]);
  if (m.vocab_size !== undefined) rows.push(["حجم المفردات", m.vocab_size.toLocaleString("en")]);
  if (m.params !== undefined) rows.push(["عدد المعاملات", m.params.toLocaleString("en")]);
  if (m.engine) rows.push(["المحرك", m.engine]);
  if (m.algorithm) rows.push(["الخوارزمية", m.algorithm]);
  if (m.upgrade_path) rows.push(["مسار الترقية", m.upgrade_path]);
  rows.push(["سجلات التدريب", d.train_records || data.train_records || 0]);
  rows.push(["سجلات الاختبار", d.test_records || data.n_test_records || 0]);
  rows.push(["الرموز", d.tokens !== undefined ? d.tokens.toLocaleString("en") : (data.n_tokens || 0)]);
  if (d.annotated_tokens !== undefined) rows.push(["رموز معنونة", d.annotated_tokens.toLocaleString("en")]);
  rows.push(["زمن التدريب (ث)", data.training_seconds || 0]);
  if (d.source) rows.push(["مصدر البيانات", d.source]);
  facts.innerHTML = rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("");
}

/* ---------------- extraction ---------------- */
$("#loadSample").addEventListener("click", async () => {
  try { const s = await apiFetch("/api/sample"); $("#inputText").value = s.text; $("#fileName").textContent = ""; }
  catch (e) { alert(e.message); }
});

$("#analyzeBtn").addEventListener("click", () => runExtract());
$("#inputText").addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") runExtract();
});

async function runExtract() {
  const text = $("#inputText").value.trim();
  if (!text) { alert("أدخل نصاً أولاً."); return; }
  try {
    const data = await apiFetch("/api/extract", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, enrich: true }),
    });
    renderAnalysis(data);
  } catch (e) { alert(`فشل التحليل: ${e.message}`); }
}

$("#fileInput").addEventListener("change", async (ev) => {
  const file = ev.target.files[0];
  if (!file) return;
  $("#fileName").textContent = file.name;
  const fd = new FormData();
  fd.append("file", file);
  try {
    const data = await apiFetch("/api/analyze/file", { method: "POST", body: fd });
    renderAnalysis(data);
  } catch (e) { alert(`فشل تحليل الملف: ${e.message}`); }
});

function renderAnalysis(data) {
  $("#resultBox").classList.remove("hidden");
  renderSummary(data.summary || {}, data.text_len);
  renderEntities(data.entities || []);
  renderGraph(data.graph || { nodes: [], edges: [] });
  renderMitreChips(data.summary || {});
  renderStix(data.stix || null);
  $("#stixBtn").classList.remove("hidden");
}

function renderSummary(s, textLen) {
  const strip = $("#summaryStrip");
  const lvl = s.risk_level || "low";
  const byType = Object.entries(s.by_type || {}).map(([t, n]) => `${typeLabel(t)} ×${n}`).join(" · ");
  strip.innerHTML = `
    <span class="risk-badge risk-${lvl}">مستوى الخطر: ${RISK_AR[lvl] || lvl}</span>
    <span class="stat-chip">عدد الكيانات: <b>${s.total_entities || 0}</b></span>
    <span class="stat-chip">طول النص: <b>${textLen || 0}</b></span>
    <span class="stat-chip">ثقة عالية: <b>${s.high_confidence || 0}</b></span>
    <span class="stat-chip">تقنيات MITRE: <b>${(s.mitre_techniques || []).length}</b></span>
    <span class="stat-chip" style="flex:1;min-width:160px"><b style="color:var(--text);font-family:inherit">${byType || "لا كيانات"}</b></span>`;
}

function repClass(v) { return v === "malicious" ? "malicious" : v === "suspicious" ? "suspicious" : v === "neutral" ? "neutral" : "not_found"; }
const REP_AR = { malicious: "خبيث", suspicious: "مشبوه", neutral: "سليم", not_found: "غير معروف" };

function renderEntities(ents) {
  const list = $("#entityList");
  if (!ents.length) { list.innerHTML = '<span class="muted">لم تُكتشف أي كيانات.</span>'; return; }
  list.innerHTML = ents.map((e) => {
    const color = TYPE_COLORS[e.type] || "#94a3b8";
    const reps = (e.reputation || []).slice(0, 3).map((r) =>
      `<span class="rep-badge rep-${repClass(r.verdict)}" title="${r.detail || ""}">${REP_AR[r.verdict] || r.verdict}</span>`).join(" ");
    const mitre = (e.mitre || []).length
      ? `<span class="muted" style="font-family:var(--mono);font-size:10.5px">${e.mitre.map((m) => m.id).join(", ")}</span>` : "";
    return `<div class="entity-card">
      <span class="etype" style="background:${color}22;color:${color};border:1px solid ${color}55">${typeLabel(e.type)}</span>
      <span class="evalue">${e.value}</span>
      ${reps}${mitre}
      <span class="econf">${(e.confidence * 100).toFixed(0)}%</span>
    </div>`;
  }).join("");
}

function renderMitreChips(s) {
  const chips = $("#mitreChips");
  const list = (s.mitre_techniques || []).filter((m) => m && m.id);
  chips.innerHTML = list.length
    ? list.map((m) => `<span class="chip">${m.id}<span class="tk">${m.name || ""}</span></span>`).join("")
    : '<span class="muted">لا تقنيات معرّفة (جرّب نصوصاً تحتوي "process injection" أو "phishing").</span>';
}

function renderStix(bundle) {
  const wrap = $("#stixPanel");
  const pre = $("#stixJson");
  if (bundle) {
    wrap.classList.remove("hidden");
    pre.textContent = JSON.stringify(bundle, null, 2);
  } else {
    wrap.classList.add("hidden");
  }
}

$("#stixBtn").addEventListener("click", () => {
  const wrap = $("#stixPanel");
  if (wrap.classList.contains("hidden")) return;
  downloadBlob($("#stixJson").textContent, "stix-bundle.json", "application/ld+json");
});

function downloadBlob(content, name, type) {
  const blob = new Blob([content], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = name; a.click();
  URL.revokeObjectURL(a.href);
}

/* ---------------- knowledge graph (SVG force layout) ---------------- */
function renderGraph(graph) {
  const svg = $("#graphSvg");
  const W = 760, H = 520;
  const nodes = (graph.nodes || []).map((n, i) => ({
    ...n, x: W / 2 + (Math.random() - 0.5) * 200, y: H / 2 + (Math.random() - 0.5) * 160, vx: 0, vy: 0,
  }));
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const edges = (graph.edges || []).filter((e) => byId.has(e.source) && byId.has(e.target));

  const REP = 4200, SPR_TAU = 0.08, CMX_TAU = 0.02, DAMP = 0.82, ITER = 160;
  for (let it = 0; it < ITER; it++) {
    for (const a of nodes) {
      a.vx *= DAMP; a.vy *= DAMP;
      for (const b of nodes) {
        if (a === b) continue;
        let dx = a.x - b.x, dy = a.y - b.y;
        let d2 = dx * dx + dy * dy;
        if (d2 === 0) { dx += 0.01; d2 = dx * dx + dy * dy; }
        const f = REP / d2;
        a.vx += (dx / Math.sqrt(d2)) * f;
        a.vy += (dy / Math.sqrt(d2)) * f;
      }
      a.vx += (W / 2 - a.x) * CMX_TAU + (a.edgeRepel || 0);
      a.vy += (H / 2 - a.y) * CMX_TAU;
    }
    for (const e of edges) {
      const a = byId.get(e.source), b = byId.get(e.target);
      const dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const ideal = Math.min(150, 90 + nodes.length * 6);
      const f = (d - ideal) * SPR_TAU;
      a.vx += (dx / d) * f; a.vy += (dy / d) * f;
      b.vx -= (dx / d) * f; b.vy -= (dy / d) * f;
    }
    for (const n of nodes) {
      n.x = Math.min(W - 24, Math.max(24, n.x + n.vx));
      n.y = Math.min(H - 24, Math.max(24, n.y + n.vy));
    }
  }

  const N = nodes.length;
  const R = N > 12 ? 12 : N > 5 ? 15 : 18;
  const font = N > 12 ? 9 : 11;
  let html = `<defs>
    <marker id="arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
      <path d="M0,0 L8,4 L0,8 z" fill="#2a3d63"/></marker>
    <radialGradient id="glow" cx="50%" cy="42%" r="60%">
      <stop offset="0%" stop-color="#ffffff" stop-opacity=".5"/><stop offset="100%" stop-color="transparent"/>
    </radialGradient></defs>`;
  edges.forEach((e) => {
    const a = byId.get(e.source), b = byId.get(e.target);
    const rel = e.relation === "co-occur" ? "#2a3d63" : e.relation === "exploits" ? "#facc1555" : e.relation === "maps_to" ? "#4ade8066" : "#818cf866";
    html += `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${rel}" stroke-width="${e.relation === "co-occur" ? 1 : 1.6}" marker-end="url(#arrow)"><title>${e.relation}</title></line>`;
  });
  nodes.forEach((n) => {
    html += `<g class="gnode" data-id="${n.id}">
      <circle cx="${n.x}" cy="${n.y}" r="${R + 7}" fill="url(#glow)" opacity=".35"/>
      <circle cx="${n.x}" cy="${n.y}" r="${R}" fill="${n.color}" stroke="#ffffff" stroke-opacity=".35" stroke-width="1.2"/>
      <text x="${n.x}" y="${n.y - R - 6}" text-anchor="middle" fill="#e8f0fb" font-size="${font}" font-family="Cascadia Code,Consolas,monospace">${typeLabel(n.type)}</text>
      <text x="${n.x}" y="${n.y + 4}" text-anchor="middle" fill="#05070c" font-size="${font + 1}" font-weight="700" font-family="Cascadia Code,Consolas,monospace">${truncate(n.label, 14)}</text>
      <title>${n.type}: ${n.label}</title>
    </g>`;
  });
  svg.innerHTML = html;
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  if (nodes.length) svg.style.filter = "drop-shadow(0 0 10px rgba(34,211,238,.10))";
  renderLegend();
}

function truncate(s, n) { return s.length > n ? s.slice(0, n - 1) + "…" : s; }

function renderLegend() {
  const types = Object.keys(TYPE_LABELS).filter((t) => TYPE_COLORS[t]);
  $("#legend").innerHTML = types.map((t) =>
    `<span><i style="background:${TYPE_COLORS[t]}"></i>${typeLabel(t)}</span>`).join("");
}

/* ---------------- MITRE explorer ---------------- */
let mitreTimer = null;
$("#mitreSearch").addEventListener("input", () => {
  clearTimeout(mitreTimer);
  mitreTimer = setTimeout(() => searchMitre($("#mitreSearch").value.trim()), 250);
});

async function searchMitre(q) {
  try {
    const d = await apiFetch(`/api/mitre/techniques?q=${encodeURIComponent(q)}&limit=80`);
    const tb = $("#mitreTable tbody");
    tb.innerHTML = d.results.length
      ? d.results.map((t) => `<tr><td style="color:var(--accent)">${t.id}</td><td style="text-align:right">${t.name}</td>
          <td style="text-align:right">${(t.tactics || []).join(" · ") || "—"}</td></tr>`).join("")
      : '<tr><td colspan="3" class="muted">لا نتائج.</td></tr>';
  } catch (e) { /* ignore typing bursts */ }
}

/* ---------------- enrichment ---------------- */
$("#enrichBtn").addEventListener("click", () => {
  runEnrichment();
});
$("#enrichValue").addEventListener("keydown", (e) => { if (e.key === "Enter") runEnrichment(); });

async function runEnrichment() {
  const type = ($("#enrichType").value || "IP").trim().toUpperCase().replace(/-/g, "_");
  const value = $("#enrichValue").value.trim();
  if (!value) { alert("أدخل قيمة للفحص."); return; }
  let typ = type;
  if (type === "HASH") typ = value.length === 64 ? "HASH_SHA256" : value.length === 40 ? "HASH_SHA1" : value.length === 32 ? "HASH_MD5" : type;
  try {
    const d = await apiFetch("/api/enrichment/reputation", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type: typ, value }),
    });
    renderEnrichment(d);
  } catch (e) { alert(e.message); }
}

function renderEnrichment(d) {
  const box = $("#enrichResult");
  const provs = d.providers || [];
  if (!provs.length) { box.innerHTML = '<span class="muted">لا نتائج من أي مزوّد.</span>'; return; }
  const best = provs.reduce((a, b) => (b.score || 0) > (a.score || 0) ? b : a, provs[0]);
  box.innerHTML = `
    <div class="summary-strip">
      <span class="risk-badge risk-${best.verdict === "malicious" ? "high" : best.verdict === "suspicious" ? "medium" : "low"}">${REP_AR[best.verdict] || best.verdict}</span>
      <span class="stat-chip">${typeLabel(d.type)}: <b>${d.value}</b></span>
    </div>
    <div class="entity-list">${provs.map((p) => `
      <div class="entity-card">
        <span class="etype" style="background:#22d3ee22;color:#22d3ee">${p.provider}</span>
        <span class="evalue">${p.detail || ""}</span>
        <span class="rep-badge rep-${repClass(p.verdict)}">${REP_AR[p.verdict] || p.verdict}</span>
        <span class="econf">${p.score}/99</span>
      </div>`).join("")}
    </div>`;
}

/* ---------------- init ---------------- */
(async function init() {
  checkStatus();
  try {
    const ent = await apiFetch("/api/entities");
    if (ent.types) TYPE_LABELS = { ...FALLBACK_LABELS, ...ent.types };
    if (ent.colors) TYPE_COLORS = { ...TYPE_COLORS, ...ent.colors };
  } catch {}
  loadDashboard().catch((e) => console.error("dashboard:", e));
  searchMitre("");
})();