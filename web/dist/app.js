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
  go.onclick = async () => {
    const u = $("#u").value.trim(), p = $("#p").value;
    try {
      if (mode === "register") await api("POST", "/api/v1/auth/register", {username: u, password: p});
      const r = await api("POST", "/api/v1/auth/login", {username: u, password: p});
      S.token = r.token; S.role = r.role; S.user = u; save();
      await refreshProjects(); location.hash = "#/overview";
    } catch (e) { $("#lerr").textContent = e.message; }
  };
}
async function vProjects() {
  const rows = S.projects.map((p) =>
    `<tr><td><a href="#/overview" data-p="${p.id}">${esc(p.name)}</a></td><td class="muted">${esc(p.id.slice(0, 8))}</td><td>${esc(p.description || "")}</td></tr>`).join("");
  return `<h1>Projects</h1>
  <div class="panel"><h3>New assessment project</h3>
  <div class="form"><label>Name<input id="pn"></label><label>Description<input id="pd"></label>
  <label>Scope (CIDR/IP/domain)<input id="ps" placeholder="10.10.10.0/24"></label>
  <button class="btn" id="pc">Create</button></div></div>
  <div class="panel"><table><tr><th>Name</th><th>ID</th><th>Description</th></tr>${rows || '<tr><td colspan="3" class="muted">None yet.</td></tr>'}</table></div>`;
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
  const [hosts, services, findings, paths, cov, ev, tl] = await Promise.all([
    api("GET", `/api/v1/projects/${id}/hosts`), api("GET", `/api/v1/projects/${id}/services`),
    api("GET", `/api/v1/projects/${id}/findings`), api("GET", `/api/v1/projects/${id}/attack-paths`),
    api("GET", `/api/v1/projects/${id}/techniques`), api("GET", `/api/v1/projects/${id}/evidence/verify`),
    api("GET", `/api/v1/projects/${id}/timeline`),
  ]);
  return {hosts, services, findings, paths, cov, ev, tl};
}
async function vOverview() {
  const d = await overviewData();
  const sev = (s) => d.findings.filter((f) => f.severity === s).length;
  const val = d.findings.filter((f) => f.confidence === "validated" || f.confidence === "confirmed").length;
  return `<h1>${pname()} <span class="muted sm">overview</span></h1>
  <div class="cards">
    <div class="card"><div class="n">${d.hosts.length}</div><div class="l">Hosts</div></div>
    <div class="card"><div class="n">${d.services.length}</div><div class="l">Services</div></div>
    <div class="card"><div class="n">${d.findings.length}</div><div class="l">Findings</div></div>
    <div class="card"><div class="n">${sev("critical") + sev("high")}</div><div class="l">Crit + High</div></div>
    <div class="card"><div class="n">${val}</div><div class="l">Validated</div></div>
    <div class="card"><div class="n">${d.paths.length}</div><div class="l">Attack paths</div></div>
    <div class="card"><div class="n">${d.cov.seen}/${d.cov.total}</div><div class="l">Techniques</div></div>
    <div class="card"><div class="n">${d.ev.checked}</div><div class="l">Evidence (${d.ev.ok ? "chain OK" : "BROKEN"})</div></div>
  </div>
  <div class="grid2"><div class="panel"><h3>Top findings</h3>${findRows(d.findings.slice(0, 5))}</div>
  <div class="panel"><h3>Top attack paths</h3>${pathRows(d.paths.slice(0, 5))}</div></div>
  <div class="panel"><h3>Recent timeline</h3>${tlRows(d.tl.slice(-8).reverse())}</div>`;
}
function findRows(list) {
  if (!list.length) return `<p class="muted">None.</p>`;
  return `<table><tr><th>Severity</th><th>Title</th><th>Target</th><th>State</th></tr>` + list.map((f) =>
    `<tr><td><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span></td><td>${esc(f.title)}</td>
     <td><code>${esc(f.target)}</code></td><td><span class="badge st-${esc(f.status)}">${esc(f.status)}</span> <span class="muted">${esc(f.confidence)}</span></td></tr>`).join("") + `</table>`;
}
function pathRows(list) {
  if (!list.length) return `<p class="muted">None — run <code>paths generate</code> in Operations or CLI.</p>`;
  return `<table><tr><th>Risk</th><th>Objective</th><th>Conf</th></tr>` + list.map((p) =>
    `<tr><td><b>${p.risk}</b></td><td>${esc(p.objective || p.id.slice(0, 8))}</td><td class="muted">${esc(p.confidence)}</td></tr>`).join("") + `</table>`;
}
function tlRows(list) {
  if (!list.length) return `<p class="muted">No events.</p>`;
  return `<table>` + list.map((e) =>
    `<tr><td class="muted">${esc((e.timestamp || "").slice(11, 19))}</td><td><code>${esc(e.kind)}</code></td><td>${esc(e.message)}</td></tr>`).join("") + `</table>`;
}
async function vFindings() {
  const id = S.project;
  const list = await api("GET", `/api/v1/projects/${id}/findings`);
  const rows = list.map((f) => `<tr><td><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span></td>
    <td>${esc(f.title)}<br><span class="muted">${esc(f.cwe || "")} ${esc(f.attack_technique || "")}</span></td>
    <td><code>${esc(f.target)}</code></td>
    <td><span class="badge st-${esc(f.status)}">${esc(f.status)}</span> <span class="muted">${esc(f.confidence)}</span></td>
    <td>${canWrite() ? `<button class="btn ghost sm" data-val="${f.id}">Validate</button>
      <button class="btn ghost sm" data-ack="${f.id}">Ack</button>` : ""}</td></tr>`).join("");
  return `<h1>${pname()} <span class="muted sm">findings (${list.length})</span></h1>
  ${canWrite() ? `<div class="panel"><div class="form">
    <button class="btn sm" id="fraise">Raise from enum results</button>
    <span class="muted">Auto-detect with the rule catalog (idempotent).</span></div></div>` : ""}
  <div class="panel"><table><tr><th>Severity</th><th>Finding</th><th>Target</th><th>State</th><th></th></tr>
  ${rows || '<tr><td colspan="5" class="muted">None.</td></tr>'}</table></div>`;
}
function bindFindings() {
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
async function vPaths() {
  const id = S.project;
  const list = await api("GET", `/api/v1/projects/${id}/attack-paths`);
  const rows = list.map((p) => {
    let nodes = []; try { nodes = JSON.parse(p.nodes_json); } catch { /* stored raw */ }
    const steps = nodes.map((n) => esc(n.label || n.id)).join(" → ");
    return `<tr><td><b>${p.risk}</b></td><td>${esc(p.objective || "")}<br><span class="muted">${steps}</span></td>
    <td class="muted">${esc(p.confidence)}${p.techniques ? "<br>" + esc(p.techniques) : ""}</td>
    <td>${canWrite() ? `<button class="btn ghost sm" data-conf="${p.id}">Confirm</button>` : ""}</td></tr>`;
  }).join("");
  return `<h1>${pname()} <span class="muted sm">attack paths (${list.length})</span></h1>
  ${canWrite() ? `<div class="panel"><div class="form"><button class="btn sm" id="pgen">Generate paths</button>
  <span class="muted">BFS over the current graph. Engine labels observed/potential only.</span></div></div>` : ""}
  <div class="panel"><table><tr><th>Risk</th><th>Chain</th><th>State</th><th></th></tr>
  ${rows || '<tr><td colspan="4" class="muted">None.</td></tr>'}</table></div>`;
}
function bindPaths() {
  const b = $("#pgen"); if (b) b.onclick = async () => {
    try { const r = await api("POST", `/api/v1/projects/${S.project}/attack-paths/generate`, {}); toast(`Generated ${r.generated} paths`); render(); }
    catch (e) { toast(e.message); }
  };
  document.querySelectorAll("[data-conf]").forEach((x) => x.onclick = async () => {
    try { await api("POST", `/api/v1/projects/${S.project}/attack-paths/${x.dataset.conf}/confirm`, {confidence: "validated"}); render(); }
    catch (e) { toast(e.message); }
  });
}
async function vAttack() {
  const cov = await api("GET", `/api/v1/projects/${S.project}/techniques`);
  const rows = cov.tactics.map((t) => `<div class="panel tac"><h3>${esc(t.tactic)} (${t.seen}/${t.total})</h3>
    <div class="chips">${t.techniques.map((h) => `<span class="chip hit" title="×${h.count} [${h.sources.join(",")}]">${esc(h.id)}</span>`).join("") || '<span class="muted">—</span>'}</div></div>`).join("");
  return `<h1>${pname()} <span class="muted sm">ATT&CK ${cov.seen}/${cov.total}</span></h1>${rows}`;
}
async function vGraph() {
  const g = await api("GET", `/api/v1/projects/${S.project}/graph`);
  const cols = ["Target", "Host", "Service", "Finding", "Technique", "Project", "User", "Role", "Policy"];
  const byKind = {};
  g.nodes.forEach((n) => { (byKind[n.kind] = byKind[n.kind] || []).push(n); });
  const W = 150, H = 44, GAP = 12, X0 = 20;
  let svg = "", y = 20;
  const pos = {};
  cols.forEach((k, ci) => {
    const ns = (byKind[k] || []).slice(0, 14);
    ns.forEach((n, i) => {
      const x = X0 + ci * (W + 40), yy = y + i * (H + GAP);
      pos[n.id] = [x, yy];
      const label = n.kind === "Host" ? n.props.ip : n.kind === "Service" ? `${n.props.host}:${n.props.port}`
        : n.kind === "Finding" ? (n.props.title || "").slice(0, 22) : n.kind === "Technique" ? n.props.technique_id
        : (n.props.value || n.props.name || n.id.slice(0, 12));
      svg += `<rect x="${x}" y="${yy}" width="${W}" height="${H}" rx="8" fill="#151d2b" stroke="#e5484d" stroke-opacity=".55"/>` +
        `<text x="${x + 8}" y="${yy + 18}">${esc(n.kind)}</text>` +
        `<text x="${x + 8}" y="${yy + 34}" opacity=".75">${esc(label || "")}</text>`;
    });
    y = 20;
  });
  g.edges.slice(0, 120).forEach((e) => {
    const a = pos[e.from], b = pos[e.to];
    if (!a || !b) return;
    svg += `<line x1="${a[0] + W}" y1="${a[1] + H / 2}" x2="${b[0]}" y2="${b[1] + H / 2}" stroke="#3e63dd" stroke-opacity=".6"/>`;
  });
  const width = X0 * 2 + cols.length * (W + 40);
  return `<h1>${pname()} <span class="muted sm">graph (${g.nodes.length} nodes, ${g.edges.length} edges)</span></h1>
  <div class="panel"><button class="btn ghost sm" id="cydl">Download Cypher</button>
  <span class="muted">Full graph with Neo4j sync lives in the CLI: <code>redops graph sync</code>.</span></div>
  <svg class="graph" viewBox="0 0 ${width} 760">${svg}</svg>`;
}
function bindGraph() {
  const b = $("#cydl"); if (!b) return;
  b.onclick = async () => {
    const r = await fetch(`/api/v1/projects/${S.project}/graph/cypher`, {headers: {Authorization: "Bearer " + S.token}});
    if (!r.ok) { toast("cypher download failed"); return; }
    const blob = await r.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = "redops-graph.cypher"; a.click();
  };
}
async function vOps() {
  const id = S.project;
  const [jobs, ejobs, validators, scats, runs] = await Promise.all([
    api("GET", `/api/v1/projects/${id}/recon`), api("GET", `/api/v1/projects/${id}/enumerate`),
    api("GET", `/api/v1/validators`), api("GET", `/api/v1/scenarios`),
    api("GET", `/api/v1/projects/${id}/scenarios/runs`),
  ]);
  const jobRows = jobs.map((j) => `<tr><td>${esc(j.tool)}</td><td><code>${esc(j.target)}</code></td><td>${esc(j.status)}</td><td class="muted">${esc(j.output_ref || j.error || "")}</td></tr>`).join("");
  const enumRows = ejobs.map((j) => `<tr><td>${esc(j.module)}</td><td><code>${esc(j.host_ip)}:${j.port}</code></td><td>${esc(j.status)}</td></tr>`).join("");
  const runRows = runs.map((r) => `<tr><td>${esc(r.scenario)}</td><td><code>${esc(r.target)}</code></td><td>${esc(r.status)}</td><td class="muted">${esc((r.output_ref || "").slice(0, 80))}</td></tr>`).join("");
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
  <div class="panel"><h3>Recon jobs (${jobs.length})</h3><table><tr><th>Tool</th><th>Target</th><th>Status</th><th>Detail</th></tr>${jobRows || '<tr><td colspan="4" class="muted">None.</td></tr>'}</table></div>
  <div class="panel"><h3>Enum jobs (${ejobs.length})</h3><table><tr><th>Module</th><th>Service</th><th>Status</th></tr>${enumRows || '<tr><td colspan="3" class="muted">None.</td></tr>'}</table></div>
  <div class="panel"><h3>Scenario runs (${runs.length})</h3><table><tr><th>Scenario</th><th>Target</th><th>Status</th><th>Detail</th></tr>${runRows || '<tr><td colspan="4" class="muted">None.</td></tr>'}</table></div>
  <div class="panel"><h3>Validators (${validators.length})</h3><div class="chips">${validators.map((v) => `<span class="chip" title="${esc(v.description)}">${esc(v.name)}</span>`).join("")}</div></div>`;
}
function bindOps() {
  const q = async (path, body, msg) => { try { await api("POST", path, body); toast(msg); render(); } catch (e) { toast(e.message); } };
  const r = $("#rgo"); if (!r) return;
  r.onclick = () => q(`/api/v1/projects/${S.project}/recon`, {tool: $("#rtool").value, target: $("#rtarget").value.trim()}, "Recon queued — start redops worker");
  $("#ego").onclick = () => q(`/api/v1/projects/${S.project}/enumerate`, {host: $("#ehost").value.trim(), port: +$("#eport").value, module: $("#emod").value || undefined}, "Enum queued");
  $("#scgo").onclick = () => q(`/api/v1/projects/${S.project}/scenarios/${$("#scn").value}/run`, {target: $("#sct").value.trim()}, "Scenario running in background");
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
  <div class="panel"><table><tr><th>ID</th><th>Action</th><th>Target</th><th>Operator</th><th>Hash</th></tr>
  ${rows || '<tr><td colspan="5" class="muted">None — run recon/enum/validation first.</td></tr>'}</table></div>`;
}
async function vReports() {
  const id = S.project;
  return `<h1>${pname()} <span class="muted sm">reports</span></h1>
  <div class="panel"><p class="muted">Generated on demand from current data.</p>
  <div class="form">${["markdown", "html", "pdf"].map((f) => `<button class="btn sm" data-rep="${f}">${f.toUpperCase()}</button>`).join("")}</div></div>`;
}
function bindReports() {
  document.querySelectorAll("[data-rep]").forEach((b) => b.onclick = async () => {
    const f = b.dataset.rep;
    const r = await fetch(`/api/v1/projects/${S.project}/report?format=${f}`, {method: "POST", headers: {Authorization: "Bearer " + S.token}});
    if (!r.ok) { toast("report failed"); return; }
    const blob = await r.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = `redops-report.${f === "markdown" ? "md" : f}`; a.click();
  });
}

/* ---------- router ---------- */
const ROUTES = {login: [vLogin, bindLogin], projects: [vProjects, bindProjects], overview: [vOverview, null],
  findings: [vFindings, bindFindings], paths: [vPaths, bindPaths], attack: [vAttack, null],
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
(async function init() {
  if (S.token) await refreshProjects();
  if (!location.hash) location.hash = S.token ? "#/overview" : "#/login";
  render();
})();
