/* RedOps GUI — vanilla SPA on the RedOps REST API. No build step. */
const LS = localStorage;
const S = {
  token: LS.getItem("ro_token") || "",
  user: LS.getItem("ro_user") || "",
  role: LS.getItem("ro_role") || "",
  project: LS.getItem("ro_project") || "",
  projects: [],
};
function save() {
  LS.setItem("ro_token", S.token); LS.setItem("ro_user", S.user);
  LS.setItem("ro_role", S.role); LS.setItem("ro_project", S.project);
}
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function toast(msg, ms = 4200) {
  const d = document.createElement("div");
  d.className = "toast"; d.textContent = msg;
  $("#toast").appendChild(d); setTimeout(() => d.remove(), ms);
}
function confirmDo(msg) { return window.confirm(msg); }
async function api(method, path, body) {
  const h = {"Content-Type": "application/json"};
  if (S.token) h.Authorization = "Bearer " + S.token;
  const r = await fetch(path, {method, headers: h, body: body ? JSON.stringify(body) : undefined});
  if (r.status === 401) { logout(); throw new Error("session expired"); }
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error((data && data.error) || ("HTTP " + r.status));
  return data;
}
async function download(method, path, filename) {
  const r = await fetch(path, {method, headers: {Authorization: "Bearer " + S.token}});
  if (!r.ok) { toast("download failed"); return; }
  const blob = await r.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = filename; a.click();
}
function logout() {
  S.token = ""; S.user = ""; S.role = ""; save();
  location.hash = "#/login"; render();
}
const NAV = [
  ["overview", "◎", "Overview"], ["findings", "⚑", "Findings"],
  ["paths", "⑂", "Attack paths"], ["attack", "◈", "ATT&CK"],
  ["graph", "⬡", "Graph"], ["ops", "⚙", "Operations"],
  ["timeline", "◷", "Timeline"], ["evidence", "⬣", "Evidence"],
  ["reports", "⎙", "Reports"], ["projects", "▤", "Projects"],
];
function drawNav(route) {
  $("#nav").innerHTML = NAV.map(([k, ic, label]) =>
    `<a href="#/${k}" class="${route === k ? "active" : ""}">${ic} <span>${label}</span></a>`).join("");
  $("#logoutBtn").classList.toggle("hidden", !S.token);
  $("#userbox").textContent = S.user ? `${S.user} (${S.role})` : "";
  const sel = $("#projectSel");
  sel.classList.toggle("hidden", !S.projects.length);
  sel.innerHTML = S.projects.map((p) =>
    `<option value="${p.id}" ${p.id === S.project ? "selected" : ""}>${esc(p.name)}</option>`).join("");
}
async function refreshProjects() {
  try { S.projects = await api("GET", "/api/v1/projects"); }
  catch { S.projects = []; }
  if (S.projects.length && !S.projects.find((p) => p.id === S.project)) S.project = S.projects[0].id;
  save();
}
function pname() {
  const p = S.projects.find((p) => p.id === S.project);
  return p ? esc(p.name) : "—";
}
const canWrite = () => S.role === "admin" || S.role === "operator";
const SEVC = {critical: "#7f1d1d", high: "#c2410c", medium: "#a16207", low: "#1d4ed8", info: "#475569"};

/* ---------- shared widgets ---------- */
function donut(sevCounts) {
  const total = Object.values(sevCounts).reduce((a, b) => a + b, 0) || 1;
  let off = 25, circles = "";
  for (const [sev, n] of Object.entries(sevCounts)) {
    if (!n) continue;
    const frac = (n / total) * 100;
    circles += `<circle cx="60" cy="60" r="46" fill="none" stroke="${SEVC[sev] || "#555"}" stroke-width="18" stroke-dasharray="${frac} ${100 - frac}" stroke-dashoffset="${off}" transform="rotate(0 60 60)"/>`;
    off -= frac;
  }
  const legend = Object.entries(sevCounts).map(([s, n]) =>
    `<span class="chip"><i class="dot" style="background:${SEVC[s]}"></i>${s} ${n}</span>`).join("");
  return `<div class="donut-wrap"><svg viewBox="0 0 120 120" class="donut">${circles}
    <text x="60" y="66" text-anchor="middle" class="donut-n">${total}</text></svg>
    <div class="chips">${legend}</div></div>`;
}
function hbar(label, val, max, color) {
  const pct = max ? Math.round((val / max) * 100) : 0;
  return `<div class="hbar"><span>${esc(label)}</span><div class="track"><div class="fill" style="width:${pct}%;background:${color}"></div></div><b>${val}</b></div>`;
}
function insightCards(list) {
  if (!list.length) return `<p class="muted">All clear — no open insights.</p>`;
  return list.map((i) => `<a class="insight ${esc(i.level)}" href="${esc(i.link)}">
    <b>${esc(i.title)}</b><span>${esc(i.detail)}</span></a>`).join("");
}

/* ---------- views ---------- */
async function vLogin() {
  return `<div class="login-wrap"><h1>◈ RedOps</h1>
  <p class="muted">First registered user becomes <b>admin</b> — there are no default credentials by design.</p>
  <div class="tabs"><button class="btn ghost sm" id="tabLogin">Log in</button>
  <button class="btn ghost sm" id="tabReg">Register</button></div>
  <div class="form"><label>Username<input id="u" autocomplete="username"></label>
  <label>Password<input id="p" type="password" autocomplete="current-password"></label></div>
  <button class="btn" id="go">Log in</button> <span id="lerr" class="muted"></span></div>`;
}
function bindLogin() {
  let mode = "login";
  const go = $("#go");
  $("#tabLogin").onclick = () => { mode = "login"; go.textContent = "Log in"; };
  $("#tabReg").onclick = () => { mode = "register"; go.textContent = "Register"; };
  const submit = async () => {
    const u = $("#u").value.trim(), p = $("#p").value;
    try {
      if (mode === "register") await api("POST", "/api/v1/auth/register", {username: u, password: p});
      const r = await api("POST", "/api/v1/auth/login", {username: u, password: p});
      S.token = r.token; S.role = r.role; S.user = u; save();
      await refreshProjects(); location.hash = "#/overview";
    } catch (e) { $("#lerr").textContent = e.message; }
  };
  go.onclick = submit;
  $("#p").addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
}
async function vProjects() {
  const rows = S.projects.map((p) =>
    `<tr><td><a href="#/overview" data-p="${p.id}">${esc(p.name)}</a></td><td class="muted">${esc(p.id.slice(0, 8))}</td><td>${esc(p.description || "")}</td></tr>`).join("");
  return `<h1>Projects</h1>
  ${canWrite() ? `<div class="panel"><h3>New assessment project</h3>
  <div class="form"><label>Name<input id="pn"></label><label>Description<input id="pd"></label>
  <label>Scope (CIDR/IP/domain)<input id="ps" placeholder="10.10.10.0/24"></label>
  <button class="btn" id="pc">Create</button></div></div>` : ""}
  <div class="panel"><div class="table-scroll"><table><tr><th>Name</th><th>ID</th><th>Description</th></tr>${rows || '<tr><td colspan="3" class="muted">None yet.</td></tr>'}</table></div></div>`;
}
function bindProjects() {
  document.querySelectorAll("[data-p]").forEach((a) => a.onclick = () => { S.project = a.dataset.p; save(); });
  const b = $("#pc"); if (!b) return;
  b.onclick = async () => {
    try {
      const p = await api("POST", "/api/v1/projects", {name: $("#pn").value.trim(), description: $("#pd").value.trim()});
      const sc = $("#ps").value.trim();
      if (sc) await api("POST", `/api/v1/projects/${p.id}/scope`, {value: sc});
      S.project = p.id; await refreshProjects(); render();
    } catch (e) { toast(e.message); }
  };
}
async function overviewData() {
  const id = S.project;
  const [hosts, services, findings, paths, cov, ev, tl, ins] = await Promise.all([
    api("GET", `/api/v1/projects/${id}/hosts`), api("GET", `/api/v1/projects/${id}/services`),
    api("GET", `/api/v1/projects/${id}/findings`), api("GET", `/api/v1/projects/${id}/attack-paths`),
    api("GET", `/api/v1/projects/${id}/techniques`), api("GET", `/api/v1/projects/${id}/evidence/verify`),
    api("GET", `/api/v1/projects/${id}/timeline`), api("GET", `/api/v1/projects/${id}/insights`),
  ]);
  return {hosts, services, findings, paths, cov, ev, tl, ins};
}
async function vOverview() {
  const d = await overviewData();
  const sev = {critical: 0, high: 0, medium: 0, low: 0, info: 0};
  d.findings.forEach((f) => { if (sev[f.severity] !== undefined) sev[f.severity]++; });
  const st = {open: 0, acknowledged: 0, resolved: 0, false_positive: 0};
  d.findings.forEach((f) => { if (st[f.status] !== undefined) st[f.status]++; });
  const maxF = Math.max(1, ...Object.values(st));
  const buckets = [0, 0, 0, 0];
  d.paths.forEach((p) => { buckets[p.risk >= 75 ? 0 : p.risk >= 50 ? 1 : p.risk >= 25 ? 2 : 3]++; });
  const maxB = Math.max(1, ...buckets);
  return `<h1>${pname()} <span class="muted sm">security overview</span></h1>
  <div class="panel"><h3>✦ Insights — what needs you now</h3><div class="insights">${insightCards(d.ins)}</div></div>
  <div class="grid2">
    <div class="panel"><h3>Findings by severity</h3>${donut(sev)}
      <h3>Triage funnel</h3>
      ${hbar("open", st.open, maxF, "#475569")}${hbar("acknowledged", st.acknowledged, maxF, "#a16207")}
      ${hbar("resolved", st.resolved, maxF, "#30a46c")}${hbar("false positive", st.false_positive, maxF, "#222")}</div>
    <div class="panel"><h3>Attack-path risk</h3>
      ${hbar("75–100 critical", buckets[0], maxB, "#7f1d1d")}${hbar("50–74 high", buckets[1], maxB, "#c2410c")}
      ${hbar("25–49 medium", buckets[2], maxB, "#a16207")}${hbar("0–24 low", buckets[3], maxB, "#1d4ed8")}
      <h3>Coverage</h3>${hbar(`ATT&CK ${d.cov.seen}/${d.cov.total}`, d.cov.seen, d.cov.total || 1, "#e5484d")}
      <h3>Evidence</h3><p>${d.ev.checked} records — chain <b>${d.ev.ok ? "OK" : "BROKEN"}</b></p>
      <p class="muted">${d.hosts.length} hosts · ${d.services.length} services · ${d.paths.length} paths</p></div>
  </div>
  <div class="grid2"><div class="panel"><h3>Top findings</h3>${findRows(d.findings.slice(0, 5))}</div>
  <div class="panel"><h3>Top attack paths</h3>${pathRows(d.paths.slice(0, 5))}</div></div>
  <div class="panel"><h3>Recent activity</h3>${tlRows(d.tl.slice(-8).reverse())}</div>`;
}
function findRows(list) {
  if (!list.length) return `<p class="muted">None. <a href="#/ops">Queue recon</a> to start discovery.</p>`;
  return `<div class="table-scroll"><table><tr><th>Severity</th><th>Title</th><th>Target</th><th>State</th></tr>` + list.map((f) =>
    `<tr><td><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span></td><td>${esc(f.title)}</td>
     <td><code>${esc(f.target)}</code></td><td><span class="badge st-${esc(f.status)}">${esc(f.status)}</span> <span class="muted">${esc(f.confidence)}</span></td></tr>`).join("") + `</table></div>`;
}
function pathRows(list) {
  if (!list.length) return `<p class="muted">None — <a href="#/ops">run discovery</a>, then generate paths.</p>`;
  return `<div class="table-scroll"><table><tr><th>Risk</th><th>Objective</th><th>Conf</th></tr>` + list.map((p) =>
    `<tr><td><b>${p.risk}</b></td><td>${esc(p.objective || p.id.slice(0, 8))}</td><td class="muted">${esc(p.confidence)}</td></tr>`).join("") + `</table></div>`;
}
function tlRows(list) {
  if (!list.length) return `<p class="muted">No events.</p>`;
  return `<div class="table-scroll"><table>` + list.map((e) =>
    `<tr><td class="muted">${esc((e.timestamp || "").slice(11, 19))}</td><td><code>${esc(e.kind)}</code></td><td>${esc(e.message)}</td></tr>`).join("") + `</table></div>`;
}
const F = {q: "", sev: new Set(), status: ""};
async function vFindings() {
  const id = S.project;
  const list = await api("GET", `/api/v1/projects/${id}/findings`);
  const chips = ["critical", "high", "medium", "low", "info"].map((s) =>
    `<button class="chip tog ${F.sev.has(s) ? "on" : ""}" data-sev="${s}">${s}</button>`).join("");
  const rows = list.filter((f) => {
    if (F.sev.size && !F.sev.has(f.severity)) return false;
    if (F.status && f.status !== F.status) return false;
    if (F.q && !(f.title + " " + f.target + " " + (f.cwe || "")).toLowerCase().includes(F.q)) return false;
    return true;
  }).map((f) => `<tr><td><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span></td>
    <td>${esc(f.title)}<br><span class="muted">${esc(f.cwe || "")} ${esc(f.attack_technique || "")}</span></td>
    <td><code>${esc(f.target)}</code></td>
    <td><span class="badge st-${esc(f.status)}">${esc(f.status)}</span> <span class="muted">${esc(f.confidence)}</span></td>
    <td>${canWrite() ? `<button class="btn ghost sm" data-val="${f.id}">Validate</button>
      <button class="btn ghost sm" data-ack="${f.id}">Ack</button>` : ""}</td></tr>`).join("");
  return `<h1>${pname()} <span class="muted sm">findings (${list.length})</span></h1>
  <div class="panel"><div class="form">
    <label>Search <small class="muted">(/)</small><input id="fq" value="${esc(F.q)}" placeholder="title, target, CWE…"></label>
    <label>Status<select id="fstatus"><option value="">all</option>
      ${["open", "acknowledged", "resolved", "false_positive"].map((s) => `<option ${F.status === s ? "selected" : ""}>${s}</option>`).join("")}</select></label>
    <div class="chips">${chips}</div>
    ${canWrite() ? `<button class="btn sm" id="fraise">Raise from enum results</button>` : ""}</div></div>
  <div class="panel"><div class="table-scroll"><table><tr><th>Severity</th><th>Finding</th><th>Target</th><th>State</th><th></th></tr>
  ${rows || '<tr><td colspan="5" class="muted">No matches — clear filters or run discovery.</td></tr>'}</table></div></div>`;
}
function bindFindings() {
  const q = $("#fq");
  if (q) {
    q.addEventListener("input", () => { F.q = q.value.toLowerCase(); render(); $("#fq")?.focus();
      const el = $("#fq"); if (el) { el.setSelectionRange(el.value.length, el.value.length); } });
  }
  document.querySelectorAll("[data-sev]").forEach((c) => c.onclick = () => {
    F.sev.has(c.dataset.sev) ? F.sev.delete(c.dataset.sev) : F.sev.add(c.dataset.sev); render();
  });
  const st = $("#fstatus"); if (st) st.onchange = () => { F.status = st.value; render(); };
  const b = $("#fraise"); if (b) b.onclick = async () => {
    try { const r = await api("POST", `/api/v1/projects/${S.project}/findings/raise`, {}); toast(`Raised ${r.raised} new findings`); render(); }
    catch (e) { toast(e.message); }
  };
  document.querySelectorAll("[data-val]").forEach((x) => x.onclick = async () => {
    try {
      const r = await api("POST", `/api/v1/projects/${S.project}/findings/${x.dataset.val}/validate`, {});
      toast(`promoted=${r.promoted}`); render();
    } catch (e) { toast(e.message); }
  });
  document.querySelectorAll("[data-ack]").forEach((x) => x.onclick = async () => {
    try { await api("PATCH", `/api/v1/projects/${S.project}/findings/${x.dataset.ack}`, {status: "acknowledged"}); render(); }
    catch (e) { toast(e.message); }
  });
}
let P_MIN = 0;
async function vPaths() {
  const id = S.project;
  const list = await api("GET", `/api/v1/projects/${id}/attack-paths?min_risk=${P_MIN}`);
  const rows = list.map((p) => {
    let nodes = []; try { nodes = JSON.parse(p.nodes_json); } catch { /* stored raw */ }
    const steps = nodes.map((n) => esc(n.label || n.id)).join(" → ");
    return `<tr><td><b>${p.risk}</b></td><td>${esc(p.objective || "")}<br><span class="muted">${steps}</span></td>
    <td class="muted">${esc(p.confidence)}${p.techniques ? "<br>" + esc(p.techniques) : ""}</td>
    <td>${canWrite() ? `<button class="btn ghost sm" data-conf="${p.id}">Confirm</button>` : ""}</td></tr>`;
  }).join("");
  return `<h1>${pname()} <span class="muted sm">attack paths (${list.length})</span></h1>
  <div class="panel"><div class="form">
    <label>Min risk<input id="pmin" type="number" min="0" max="100" value="${P_MIN}"></label>
    ${canWrite() ? `<button class="btn sm" id="pgen">Generate paths</button>` : ""}
    <span class="muted">BFS over the current graph. Engine labels observed/potential only.</span></div></div>
  <div class="panel"><div class="table-scroll"><table><tr><th>Risk</th><th>Chain</th><th>State</th><th></th></tr>
  ${rows || '<tr><td colspan="4" class="muted">None at this threshold.</td></tr>'}</table></div></div>`;
}
function bindPaths() {
  const m = $("#pmin"); if (m) m.onchange = () => { P_MIN = +m.value || 0; render(); };
  const b = $("#pgen"); if (b) b.onclick = async () => {
    if (!confirmDo("Regenerate all attack paths? This replaces the current set.")) return;
    try { const r = await api("POST", `/api/v1/projects/${S.project}/attack-paths/generate`, {}); toast(`Generated ${r.generated} paths`); render(); }
    catch (e) { toast(e.message); }
  };
  document.querySelectorAll("[data-conf]").forEach((x) => x.onclick = async () => {
    try { await api("POST", `/api/v1/projects/${S.project}/attack-paths/${x.dataset.conf}/confirm`, {confidence: "validated"}); render(); }
    catch (e) { toast(e.message); }
  });
}
let A_Q = "";
async function vAttack() {
  const [cov, all] = await Promise.all([
    api("GET", `/api/v1/projects/${S.project}/techniques`),
    api("GET", "/api/v1/mitre/techniques"),
  ]);
  const hit = {};
  cov.tactics.forEach((t) => t.techniques.forEach((h) => { hit[h.id] = h; }));
  const byTac = {};
  all.forEach((t) => { (byTac[t.tactic] = byTac[t.tactic] || []).push(t); });
  const q = A_Q.toLowerCase();
  const cols = Object.keys(byTac).filter((t) => !q || t.toLowerCase().includes(q) ||
    byTac[t].some((x) => x.id.toLowerCase().includes(q) || x.name.toLowerCase().includes(q)));
  const grid = cols.map((t) => {
    const cells = byTac[t].filter((x) => !q || x.id.toLowerCase().includes(q) || x.name.toLowerCase().includes(q) || t.toLowerCase().includes(q));
    if (!cells.length) return "";
    return `<div class="mcol"><h4>${esc(t)}</h4>` + cells.map((x) => {
      const h = hit[x.id];
      const bg = h ? scoreBG(h.count) : "#1a2233";
      const title = h ? `${esc(x.name)} · ×${h.count} [${h.sources.join(",")}]` : `${esc(x.name)} · blind spot`;
      return `<div class="cell" style="background:${bg}" title="${title}">${esc(x.id)}</div>`;
    }).join("") + `</div>`;
  }).join("");
  return `<h1>${pname()} <span class="muted sm">ATT&CK matrix ${cov.seen}/${cov.total}</span></h1>
  <div class="panel"><div class="form">
    <label>Search<input id="aq" value="${esc(A_Q)}" placeholder="T1046, discovery…"></label>
    <button class="btn ghost sm" id="layerdl">Navigator layer JSON</button>
    <span class="muted">Red = observed (darker = more evidence) · dark = blind spot. Hover for detail.</span></div></div>
  <div class="matrix">${grid || '<p class="muted">No matches.</p>'}</div>`;
}
function scoreBG(count) {
  const f = Math.min(1, count / 8);
  const g = Math.round(200 - f * 160), b = Math.round(200 - f * 165);
  return `rgb(229,${g},${b})`;
}
function bindAttack() {
  const q = $("#aq");
  if (q) q.addEventListener("input", () => { A_Q = q.value; render(); const el = $("#aq");
    if (el) { el.focus(); el.setSelectionRange(el.value.length, el.value.length); } });
  const b = $("#layerdl"); if (b) b.onclick = () => download("GET", `/api/v1/projects/${S.project}/techniques/layer`, "redops-layer.json");
}
const GZ = {x: 0, y: 0, k: 1};
async function vGraph() {
  const g = await api("GET", `/api/v1/projects/${S.project}/graph`);
  const cols = ["Target", "Host", "Service", "Finding", "Technique", "Project", "User", "Role", "Policy"];
  const byKind = {};
  g.nodes.forEach((n) => { (byKind[n.kind] = byKind[n.kind] || []).push(n); });
  const W = 150, H = 44, GAP = 12, X0 = 20;
  let svg = "";
  const pos = {};
  cols.forEach((k, ci) => {
    ((byKind[k] || []).slice(0, 14)).forEach((n, i) => {
      const x = X0 + ci * (W + 40), yy = 20 + i * (H + GAP);
      pos[n.id] = [x, yy];
      const label = n.kind === "Host" ? n.props.ip : n.kind === "Service" ? `${n.props.host}:${n.props.port}`
        : n.kind === "Finding" ? (n.props.title || "").slice(0, 22) : n.kind === "Technique" ? n.props.technique_id
        : (n.props.value || n.props.name || n.id.slice(0, 12));
      svg += `<g class="node" data-nid="${esc(n.id)}"><rect x="${x}" y="${yy}" width="${W}" height="${H}" rx="8"/>` +
        `<text x="${x + 8}" y="${yy + 18}">${esc(n.kind)}</text>` +
        `<text x="${x + 8}" y="${yy + 34}" opacity=".75">${esc(label || "")}</text></g>`;
    });
  });
  g.edges.slice(0, 150).forEach((e) => {
    const a = pos[e.from], b = pos[e.to];
    if (!a || !b) return;
    svg += `<line x1="${a[0] + W}" y1="${a[1] + H / 2}" x2="${b[0]}" y2="${b[1] + H / 2}" class="edge"><title>${esc(e.type)}: ${esc(e.reason)}</title></line>`;
  });
  const width = X0 * 2 + cols.length * (W + 40);
  return `<h1>${pname()} <span class="muted sm">graph (${g.nodes.length} nodes, ${g.edges.length} edges)</span></h1>
  <div class="panel"><div class="form">
    <button class="btn ghost sm" id="cydl">Download Cypher</button>
    <button class="btn ghost sm" id="gzreset">Reset view</button>
    <span class="muted">Drag to pan · scroll to zoom · click a node to inspect · full sync in CLI.</span></div>
    <div id="inspect" class="muted">Click any node for details.</div></div>
  <svg class="graph" id="gsvg" viewBox="0 0 ${width} 760"><g id="gz" transform="translate(${GZ.x} ${GZ.y}) scale(${GZ.k})">${svg}</g></svg>
  <script type="application/json" id="gdata">${esc(JSON.stringify({nodes: g.nodes, edges: g.edges}))}</script>`;
}
function bindGraph() {
  const svg = $("#gsvg"); if (!svg) return;
  const gz = $("#gz");
  const apply = () => gz.setAttribute("transform", `translate(${GZ.x} ${GZ.y}) scale(${GZ.k})`);
  let drag = null;
  svg.addEventListener("pointerdown", (e) => { drag = [e.clientX, e.clientY, GZ.x, GZ.y]; svg.setPointerCapture(e.pointerId); });
  svg.addEventListener("pointermove", (e) => {
    if (!drag) return;
    GZ.x = drag[2] + (e.clientX - drag[0]) / GZ.k; GZ.y = drag[3] + (e.clientY - drag[1]) / GZ.k; apply();
  });
  svg.addEventListener("pointerup", () => { drag = null; });
  svg.addEventListener("wheel", (e) => { e.preventDefault(); GZ.k = Math.min(3, Math.max(0.4, GZ.k * (e.deltaY < 0 ? 1.1 : 0.9))); apply(); }, {passive: false});
  $("#gzreset").onclick = () => { GZ.x = 0; GZ.y = 0; GZ.k = 1; apply(); };
  $("#cydl").onclick = () => download("GET", `/api/v1/projects/${S.project}/graph/cypher`, "redops-graph.cypher");
  let data = {nodes: [], edges: []};
  try { data = JSON.parse($("#gdata").textContent); } catch { /* ignore */ }
  svg.querySelectorAll(".node").forEach((el) => el.addEventListener("click", () => {
    const n = data.nodes.find((x) => x.id === el.dataset.nid);
    if (!n) return;
    const rel = data.edges.filter((e) => e.from === n.id || e.to === n.id);
    $("#inspect").innerHTML = `<b>${esc(n.kind)}</b> <code>${esc(n.id)}</code><br>` +
      Object.entries(n.props || {}).map(([k, v]) => `${esc(k)}: ${esc(v)}`).join(" · ") +
      `<br><span class="muted">${rel.length} relationship(s): ` +
      rel.map((e) => esc(e.type)).join(", ") + `</span>`;
  }));
}
async function vOps() {
  const id = S.project;
  const [jobs, ejobs, validators, scats, runs] = await Promise.all([
    api("GET", `/api/v1/projects/${id}/recon`), api("GET", `/api/v1/projects/${id}/enumerate`),
    api("GET", `/api/v1/validators`), api("GET", `/api/v1/scenarios`),
    api("GET", `/api/v1/projects/${id}/scenarios/runs`),
  ]);
  let cpaths = [];
  try { cpaths = await api("GET", `/api/v1/projects/${id}/cloud/paths`); } catch { /* no import */ }
  const jobRows = jobs.map((j) => `<tr><td>${esc(j.tool)}</td><td><code>${esc(j.target)}</code></td><td>${esc(j.status)}</td><td class="muted">${esc(j.output_ref || j.error || "")}</td></tr>`).join("");
  const enumRows = ejobs.map((j) => `<tr><td>${esc(j.module)}</td><td><code>${esc(j.host_ip)}:${j.port}</code></td><td>${esc(j.status)}</td></tr>`).join("");
  const runRows = runs.map((r) => `<tr><td>${esc(r.scenario)}</td><td><code>${esc(r.target)}</code></td><td>${esc(r.status)}</td><td class="muted">${esc((r.output_ref || "").slice(0, 80))}</td></tr>`).join("");
  const cpathRows = cpaths.map((p) => `<tr><td><b>${p.risk}</b></td><td>${esc(p.objective)}</td><td class="muted">${esc(p.chain.join(" → "))}</td></tr>`).join("");
  return `<h1>${pname()} <span class="muted sm">operations</span></h1>
  ${canWrite() ? `
  <div class="grid2">
  <div class="panel"><h3>Recon (scope-gated)</h3>
    <div class="form"><label>Tool<select id="rtool"><option>nmap</option><option>httpx</option><option>dnsx</option><option>subfinder</option></select></label>
    <label>Target<input id="rtarget" placeholder="10.10.10.10"></label><button class="btn sm" id="rgo">Queue</button></div>
    <p class="muted">Runs via <code>redops worker</code>. Out-of-scope → 403 + audit.</p></div>
  <div class="panel"><h3>Enumerate (read-only)</h3>
    <div class="form"><label>Host<input id="ehost" placeholder="10.10.10.10"></label>
    <label>Port<input id="eport" placeholder="80"></label>
    <label>Module<select id="emod"><option value="">auto</option><option>http</option><option>ssh-banner</option><option>dns</option><option>tcp-banner</option></select></label>
    <button class="btn sm" id="ego">Queue</button></div></div>
  </div>
  <div class="panel"><h3>Scenarios</h3>
    <div class="form"><label>Playbook<select id="scn">${scats.map((s) => `<option value="${esc(s.name)}">${esc(s.name)}</option>`).join("")}</select></label>
    <label>Target<input id="sct" placeholder="10.10.10.10"></label><button class="btn sm" id="scgo">Run (async)</button></div>
    <p class="muted">Read-only playbooks with detection hints. Polls appear below.</p></div>
  <div class="panel"><h3>Cloud IAM import</h3>
    <div class="form"><label>JSON<textarea id="cij" rows="4" cols="50" placeholder='{"users":[],"roles":[],"policies":[]}'></textarea></label>
    <button class="btn sm" id="cigo">Import</button></div>
    <p class="muted">Offline analysis — RedOps never calls AWS. See <code>lab/cloud-iam-example.json</code>.</p></div>` : ""}
  <div class="panel"><h3>Recon jobs (${jobs.length})</h3><div class="table-scroll"><table><tr><th>Tool</th><th>Target</th><th>Status</th><th>Detail</th></tr>${jobRows || '<tr><td colspan="4" class="muted">None.</td></tr>'}</table></div></div>
  <div class="panel"><h3>Enum jobs (${ejobs.length})</h3><div class="table-scroll"><table><tr><th>Module</th><th>Service</th><th>Status</th></tr>${enumRows || '<tr><td colspan="3" class="muted">None.</td></tr>'}</table></div></div>
  <div class="panel"><h3>Cloud privilege paths (${cpaths.length})</h3><div class="table-scroll"><table><tr><th>Risk</th><th>Objective</th><th>Chain</th></tr>${cpathRows || '<tr><td colspan="3" class="muted">No import yet.</td></tr>'}</table></div></div>
  <div class="panel"><h3>Scenario runs (${runs.length})</h3><div class="table-scroll"><table><tr><th>Scenario</th><th>Target</th><th>Status</th><th>Detail</th></tr>${runRows || '<tr><td colspan="4" class="muted">None.</td></tr>'}</table></div></div>
  <div class="panel"><h3>Validators (${validators.length})</h3><div class="chips">${validators.map((v) => `<span class="chip" title="${esc(v.description)}">${esc(v.name)}</span>`).join("")}</div></div>`;
}
function bindOps() {
  const q = async (path, body, msg) => { try { await api("POST", path, body); toast(msg); render(); } catch (e) { toast(e.message); } };
  const r = $("#rgo"); if (!r) return;
  r.onclick = () => q(`/api/v1/projects/${S.project}/recon`, {tool: $("#rtool").value, target: $("#rtarget").value.trim()}, "Recon queued — start redops worker");
  $("#ego").onclick = () => q(`/api/v1/projects/${S.project}/enumerate`, {host: $("#ehost").value.trim(), port: +$("#eport").value, module: $("#emod").value || undefined}, "Enum queued");
  $("#scgo").onclick = () => {
    if (!confirmDo("Run scenario? It executes read-only scans against the target.")) return;
    q(`/api/v1/projects/${S.project}/scenarios/${$("#scn").value}/run`, {target: $("#sct").value.trim()}, "Scenario running in background");
  };
  $("#cigo").onclick = async () => {
    try {
      const res = await fetch(`/api/v1/projects/${S.project}/cloud/import`, {method: "POST", headers: {Authorization: "Bearer " + S.token, "Content-Type": "application/json"}, body: $("#cij").value});
      if (!res.ok) throw new Error((await res.json()).error || res.status);
      toast("Cloud import stored"); render();
    } catch (e) { toast(e.message); }
  };
}
async function vTimeline() {
  const tl = await api("GET", `/api/v1/projects/${S.project}/timeline`);
  return `<h1>${pname()} <span class="muted sm">timeline (${tl.length})</span></h1><div class="panel">${tlRows(tl.slice().reverse())}</div>`;
}
async function vEvidence() {
  const id = S.project;
  const [list, ver] = await Promise.all([
    api("GET", `/api/v1/projects/${id}/evidence`), api("GET", `/api/v1/projects/${id}/evidence/verify`),
  ]);
  const rows = list.map((e) => `<tr><td class="muted">${esc(e.id.slice(0, 8))}</td><td><code>${esc(e.action)}</code></td>
  <td><code>${esc(e.target)}</code></td><td>${esc(e.operator)}</td><td class="muted">${esc((e.hash || "").slice(0, 12))}</td></tr>`).join("");
  return `<h1>${pname()} <span class="muted sm">evidence (${list.length}, chain ${ver.ok ? "OK" : "BROKEN"})</span></h1>
  <div class="panel"><div class="table-scroll"><table><tr><th>ID</th><th>Action</th><th>Target</th><th>Operator</th><th>Hash</th></tr>
  ${rows || '<tr><td colspan="5" class="muted">None — run recon/enum/validation first.</td></tr>'}</table></div></div>`;
}
async function vReports() {
  const id = S.project;
  return `<h1>${pname()} <span class="muted sm">reports</span></h1>
  <div class="panel"><p class="muted">Generated on demand from current data.</p>
  <div class="form">${["markdown", "html", "pdf"].map((f) => `<button class="btn sm" data-rep="${f}">${f.toUpperCase()}</button>`).join("")}</div></div>`;
}
function bindReports() {
  document.querySelectorAll("[data-rep]").forEach((b) => b.onclick = () => download("POST", `/api/v1/projects/${S.project}/report?format=${b.dataset.rep}`, `redops-report.${b.dataset.rep === "markdown" ? "md" : b.dataset.rep}`));
}

/* ---------- router ---------- */
const ROUTES = {login: [vLogin, bindLogin], projects: [vProjects, bindProjects], overview: [vOverview, null],
  findings: [vFindings, bindFindings], paths: [vPaths, bindPaths], attack: [vAttack, bindAttack],
  graph: [vGraph, bindGraph], ops: [vOps, bindOps], timeline: [vTimeline, null],
  evidence: [vEvidence, null], reports: [vReports, bindReports]};
async function render() {
  let route = (location.hash || "#/login").replace("#/", "");
  if (!S.token && route !== "login") route = "login";
  if (S.token && !S.project && route !== "projects" && route !== "login") {
    await refreshProjects();
    if (!S.project) route = "projects";
  }
  drawNav(route);
  $("#view").innerHTML = `<p class="muted">Loading…</p>`;
  const [view, bind] = ROUTES[route] || ROUTES.overview;
  try {
    $("#view").innerHTML = await view();
    if (bind) bind();
  } catch (e) { $("#view").innerHTML = `<p class="muted">Error: ${esc(e.message)}</p>`; }
  const conn = $("#conn");
  try { await fetch("/healthz"); conn.textContent = "● api"; conn.classList.remove("bad"); }
  catch { conn.textContent = "● api down"; conn.classList.add("bad"); }
}
window.addEventListener("hashchange", render);
$("#projectSel").addEventListener("change", (e) => { S.project = e.target.value; save(); render(); });
$("#logoutBtn").onclick = logout;
document.addEventListener("keydown", (e) => {
  if (e.key !== "/" || ["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement?.tagName)) return;
  e.preventDefault();
  if ((location.hash || "").startsWith("#/attack")) {
    const el = $("#aq"); if (el) el.focus();
  } else {
    if ((location.hash || "") !== "#/findings") location.hash = "#/findings";
    setTimeout(() => { const el = $("#fq"); if (el) el.focus(); }, 80);
  }
});
(async function init() {
  if (S.token) await refreshProjects();
  if (!location.hash) location.hash = S.token ? "#/overview" : "#/login";
  render();
})();
