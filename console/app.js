const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const api = async (path, method = "GET") => {
  const r = await fetch(path, { method });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText);
  return r.json();
};
let INV = null, PLAN = null, WAVES = [], BUSY = null, UI_VERSION = null;

// ---------------------------------------------------------------- live bar
async function poll() {
  try {
    const s = await api("/api/status");
    // Dev auto-reload: any change under console/ bumps ui_version and the page reloads itself.
    if (UI_VERSION && s.ui_version !== UI_VERSION) return location.reload();
    UI_VERSION = s.ui_version;
    $("#chips").innerHTML = [
      ["QpiAI Opt key", s.keys.opt], ["QCloud key", s.keys.qcloud],
    ].map(([n, on]) => `<span class="chip ${on ? "on" : "off"}"><i></i>${n}: ${on ? "set" : "missing"}</span>`).join("")
      + `<span class="chip"><i></i>QCloud device: ${esc(s.qcloud_device)}</span>`;
    renderLog(s.log);
    const wasBusy = BUSY;
    BUSY = s.busy;
    $("#busy").hidden = !BUSY;
    $("#busy").textContent = BUSY ? `Running: ${BUSY}…` : "";
    document.querySelectorAll("button[data-act], button[data-m]").forEach((b) => { if (b.dataset.m !== "probe") b.disabled = !!BUSY; });
    if (wasBusy && !BUSY) refresh();
  } catch (e) { /* server restarting */ }
}

// ---------------------------------------------------------------- actions
async function act(name, arg) {
  const path = { scan: "/api/scan", plan: "/api/plan", drill: "/api/drill", report: null, wave: `/api/wave/${arg}`,
    repos: "/api/repos", bench: "/api/bench", circuits: "/api/circuits",
    notify: "/api/notify?bank=" + encodeURIComponent($("#notify-bank").value || ""),
    alert: "/api/notify/alert?bank=" + encodeURIComponent($("#notify-bank").value || "") }[name];
  try {
    if (path) {
      BUSY = name; poll();
      const r = await api(path, "POST");
      if (name === "alert") toast(r.sent ? `✓ CRITICAL alert emailed to ${r.recipients.join(", ")}
Change on record: ${r.change.join(", ") || "none"}` : `No alert sent: ${r.reason}`, 10000);
      if (name === "notify") toast(`✓ Report emailed to ${r.recipients.join(", ")}
${r.bank}: ${r.findings} findings, ${r.pdf_kb} KB PDF attached`, 10000);
    }
  } catch (e) { toast(`✗ ${{ notify: "email report", alert: "email alert" }[name] || name}: ${e.message}`, 12000); }
  await refresh();
}
function alertBox(msg) { $("#log").insertAdjacentHTML("beforeend", logRow(`${new Date().toTimeString().slice(0, 8)}  ERROR ${msg}`)); }

// Run log: one row per line, time in its own column, colour by what happened.
function logRow(l) {
  const m = /^(\d\d:\d\d:\d\d)\s+(.*)$/.exec(l) || ["", "", l];
  const msg = m[2];
  const kind = /ERROR|FAILED|FAILURES|PREFLIGHT|LEFT IN PLACE|NOT WORKING/.test(msg) ? "bad"
    : /REFUSED|not sent|CRITICAL|rolling back/.test(msg) ? "warn"
    : /PASSED|ALL PASS|promoted|healthy: True|Testbed up|EMAILED|done in/.test(msg) ? "ok" : "";
  const body = esc(msg).replace(/^(\[[^\]]+\]|OPERATOR:|ALERT|EMAILED|REFUSED [\w ]+:|ERROR in [\w ]+:)/, '<b class="tg">$1</b>');
  return `<div class="lr ${kind}"><time>${m[1]}</time><span>${body}</span></div>`;
}
function renderLog(lines) {
  const el = $("#log"), stick = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
  el.innerHTML = lines.map(logRow).join("");
  if (stick) el.scrollTop = el.scrollHeight;
}

document.addEventListener("click", (e) => {
  const b = e.target.closest("button[data-act]");
  if (b) act(b.dataset.act, b.dataset.arg);
  const t = e.target.closest("a.tr");
  if (t) showTrace(t.dataset.label, t.dataset.svc);
});
$("#trace-close").onclick = () => $("#trace-dlg").close();
$("#f-status").onchange = renderInventory;
$("#f-cat").onchange = renderInventory;

async function showTrace(label, svc) {
  const r = await fetch(`/api/trace/${label}/${svc}`);
  $("#trace-title").textContent = `openssl s_client -trace · ${svc} · ${label}`;
  $("#trace-pre").textContent = r.ok ? await r.text() : "trace not found";
  $("#trace-dlg").showModal();
}

// ---------------------------------------------------------------- email report
async function renderNotify() {
  try {
    const c = await api("/api/notify"), sel = $("#notify-bank"), keep = sel.value;
    sel.hidden = c.banks.length < 2;
    sel.innerHTML = c.banks.map((b) => `<option value="${esc(b.id)}">${esc(b.name)}</option>`).join("");
    if (keep) sel.value = keep;
  } catch (e) { /* server restarting */ }
}
$("#notify-bank").onchange = renderNotify;

// ---------------------------------------------------------------- inventory + risk
function renderInventory() {
  renderNotify();
  if (!INV || !INV.findings.length) return;
  const f = INV.findings, qv = f.filter((x) => x.status === "quantum-vulnerable");
  $("#inv-summary").innerHTML =
    tile("Findings", f.length, "each with file / endpoint evidence") +
    tile("Quantum-vulnerable", qv.length, "RSA · ECDSA · ECDH · X25519") +
    tile("PQ-safe", f.filter((x) => x.status === "pq-safe").length, "HQC · FN-DSA · SLH-DSA") +
    tile("Live TLS endpoints", f.filter((x) => x.category === "endpoint").length, "checked with real handshakes");
  const st = $("#f-status").value, cat = $("#f-cat").value;
  const rows = f.filter((x) => (!st || x.status === st) && (!cat || x.category === cat));
  $("#inv-table").innerHTML = `<tr><th>Status</th><th>Service</th><th>Where</th><th>Algorithm</th><th>Severity</th><th>Found by</th></tr>` +
    rows.map((x) => `<tr><td><span class="pill ${x.status === "pq-safe" ? "pq" : "qv"}">${x.status === "pq-safe" ? "PQ-safe" : "vulnerable"}</span></td>
      <td>${esc(x.service || "–")}</td><td class="mono" title="${esc(x.snippet)}">${esc(x.file)}${x.line ? ":" + x.line : ""}</td>
      <td>${esc(x.algorithm)}</td>
      <td>${x.severity ? `<span class="pill ${x.severity === "critical" || x.severity === "high" ? "qv" : ""}">${esc(x.severity)}</span>` : "–"}</td>
      <td>${esc({ code: "code scan", config: "config scan", certificate: "certificate", dependency: "dependency", endpoint: "live handshake" }[x.category] || x.category)}</td></tr>`).join("");
}

const tile = (l, v, s) => `<div class="tile"><span>${esc(l)}</span><b>${v}</b><br><small>${esc(s)}</small></div>`;

function renderRisk() {
  const r = INV && INV.risk;
  if (!r) return;
  const svc = Object.entries(r.services);
  $("#risk-body").className = "";
  $("#risk-body").innerHTML = `<div class="scroll"><table><tr><th>Service</th><th>What it does</th><th>Risk</th><th>Exposure</th><th>Vulnerable</th></tr>
  ${svc.map(([s, v]) => `<tr><td><b>${s}</b></td><td style="min-width:260px">${esc(v.desc)}</td>
    <td style="min-width:130px"><span class="num"><b>${v.score}</b></span><div class="bar-h" style="margin-top:4px"><i style="width:${v.score * 10}%"></i></div></td>
    <td>${v.exposure === 1 ? "internet" : "internal"}</td><td class="num">${v.findings}</td></tr>`).join("")}</table></div>`;
}

// ---------------------------------------------------------------- plan
function renderPlan() {
  const p = PLAN;
  if (!p || !p.final_waves) return;
  const W = p.windows, prim = p.primary;
  const byId = Object.fromEntries(p.tasks.map((t) => [t.id, t])), bk = p.blackout;
  const kindName = { enabler: "prepare", confidentiality: "key exchange", authentication: "signatures" };
  const wins = p.final_waves.map((ids, w) => {
    const ts = ids.map((i) => byId[i]).filter(Boolean), effort = ts.reduce((a, t) => a + t.effort, 0);
    const frozen = bk && bk.window === w;
    return `<div class="win${frozen ? " frozen" : ""}">
      <div class="win-head"><span>Window ${w}</span><b>${ts.length} tasks</b></div>
      <div class="win-cap"><div class="bar-h"><i style="width:${Math.min(100, (100 * effort) / p.capacity)}%"></i></div><small>effort ${effort} of ${p.capacity}</small></div>
      ${frozen ? `<p class="win-freeze"><b>Change freeze · ${esc(bk.reason)}.</b> The planner avoids ${esc(bk.services.join(", "))} in this window.</p>` : ""}
      <ol class="win-list">${ts.map((t) => `<li><span class="win-title">${esc(t.title)}</span>
        <span class="win-meta"><span class="kind ${t.kind}">${kindName[t.kind] || t.kind}</span><span class="pill">${esc(t.service)}</span>${frozen && bk.services.includes(t.service) ? '<span class="kind frz">in freeze</span>' : ""}<span class="mono">${t.id}</span></span></li>`).join("")}</ol></div>`;
  }).join("");
  $("#plan-body").className = "";
  $("#plan-body").innerHTML = `
  ${prim.fallback_reason ? `<p class="rollback" style="border-color:var(--accent);background:var(--accent-soft)">QpiAI Opt was not used for this plan: ${esc(prim.fallback_reason)}. Add QPIAI_OPT_API_KEY to .env and regenerate.</p>` : ""}
  <h3 class="sub">Wave plan</h3>
  <p class="hint">Windows run in order. Each window applies its tasks, runs the verification gate, then promotes or rolls back.</p>
  <div class="wins">${wins}</div>
  <div class="grid2">
    <div class="card"><h3>Remaining quantum exposure after each window</h3>${curve([["Final plan", p.final.exposure_curve_pct, "var(--steel)"]])}</div>
  </div>`;
}

function curve(series) {
  const W = 320, H = 150, L = 34, B = 22, n = series[0][1].length;
  const x = (i) => L + (i * (W - L - 10)) / (n - 1), y = (v) => 8 + ((100 - v) * (H - B - 8)) / 100;
  const grid = [0, 50, 100].map((v) => `<line x1="${L}" x2="${W - 10}" y1="${y(v)}" y2="${y(v)}" stroke="var(--line)"/><text x="${L - 6}" y="${y(v) + 4}" text-anchor="end">${v}%</text>`).join("");
  const xl = [...Array(n).keys()].map((i) => `<text x="${x(i)}" y="${H - 6}" text-anchor="middle">${i === 0 ? "start" : "w" + (i - 1)}</text>`).join("");
  const lines = series.map(([name, d, c], k) => `<polyline fill="none" stroke="${c}" stroke-width="2.5" points="${d.map((v, i) => `${x(i)},${y(v)}`).join(" ")}"/>
     ${d.map((v, i) => `<circle cx="${x(i)}" cy="${y(v)}" r="3" fill="${c}"/>`).join("")}<text x="${W - 12}" y="${14 + k * 14}" text-anchor="end" style="fill:${c}">${name}</text>`).join("");
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Exposure curve">${grid}${xl}${lines}</svg>`;
}
// ---------------------------------------------------------------- waves
function renderWaves() {
  if (!PLAN || !PLAN.final_waves) return;
  const done = {};
  WAVES.forEach((w) => (done[w.label] = w));
  const lastPassed = (i) => i === 0 || (done[`wave${i - 1}`] && done[`wave${i - 1}`].passed);
  $("#waves-body").className = "";
  $("#waves-body").innerHTML = PLAN.final_waves.map((tasks, i) => waveCard(`wave${i}`, `Window ${i}`, tasks, done[`wave${i}`],
    `<button data-act="wave" data-arg="${i}" ${!lastPassed(i) ? "title='previous wave has not passed yet: the gate will show what breaks'" : ""}>${done[`wave${i}`] ? "Re-run" : "Run"} wave ${i}</button>`)).join("")
    + (done.drill ? waveCard("drill", "Fault drill: public certificate switched early", done.drill.tasks, done.drill, "") : "");
}
function waveCard(label, title, tasks, rec, btn) {
  let body = "";
  if (rec) {
    const groups = {};
    rec.checks.forEach((c) => (groups[c.category] = groups[c.category] || []).push(c));
    const passed = rec.checks.filter((c) => c.passed).length;
    const svcs = Object.keys(rec.after);
    body = `<p><span class="pill ${rec.passed ? "pass" : "fail"}">${rec.passed ? "PROMOTED" : "GATE FAILED"}</span>
      ${passed}/${rec.checks.length} gate checks · customer path during the wave: ${rec.traffic_delta.probe_ok} of ${rec.traffic_delta.probe_ops} requests succeeded (${rec.traffic_delta.probe_payments} payments), ${rec.traffic_delta.probe_failed} failed</p>
      <div class="scroll"><table><tr><th>Service</th><th>Before</th><th>After (gate)</th><th>Handshake bytes</th><th>p95 ms</th><th>Traces</th></tr>
      ${svcs.map((s) => { const b = rec.before[s], a = rec.after[s];
        return `<tr><td>${s}</td><td class="mono">${b ? `${b.group} / ${b.peer_sig}` : "–"}</td><td class="mono">${a.group} / ${a.peer_sig}</td>
        <td class="num">${b ? b.bytes_read + " → " : ""}${a.bytes_read}</td><td class="num">${rec.timing[s] ? rec.timing[s].p95_ms : "–"}</td>
        <td>${b ? `<a class="tr" data-label="${label}-before" data-svc="${s}">before</a> · ` : ""}<a class="tr" data-label="${label}-after" data-svc="${s}">after</a></td></tr>`; }).join("")}</table></div>
      <div class="checks">${rec.checks.map((c) => `<div class="check"><span class="pill ${c.passed ? "pass" : "fail"}">${c.passed ? "✓" : "✗"}</span><span class="cat">${c.category}</span><span>${esc(c.name)}</span></div>`).join("")}</div>
      ${rec.rollback ? `<div class="rollback"><b>Automatic rollback</b> of ${rec.rollback.services.join(", ")} completed in <b>${rec.rollback.restore_s} s</b> (${rec.rollback.healthy ? "traffic healthy again" : "check traffic"}).
        Failed: ${rec.checks.filter((c) => !c.passed).map((c) => esc(c.name)).join("; ")}</div>` : ""}`;
  }
  return `<div class="wave"><div class="wave-head"><h3>${title}</h3>${btn}</div>
    <div class="tasks">${tasks.map((t) => `<code>${t}</code>`).join("")}</div>${body}</div>`;
}

// ---------------------------------------------------------------- report
async function renderReport() {
  const r = await api("/api/report"), m = r.migration, el = $("#report-body");
  if (!r.changes.length) { el.className = "empty"; el.textContent = "No migration yet. Apply a task on the Migrate page and its gate result appears here."; return; }
  el.className = "";
  const num0 = (n) => (n ?? 0).toLocaleString();
  const when = (ts) => new Date(ts * 1000).toLocaleString([], { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const pillFor = (o) => (o === "promoted" || o === "gate passed" ? "pass" : o === "undone by operator" ? "warn" : "fail");
  const title = (c) => (c.type === "apply" ? (c.label || "").replace(/^manual-.*/, "Manual apply").replace(/^wave(\d+)$/, "Wave $1").replace(/^drill$/, "Fault drill") : c.type[0].toUpperCase() + c.type.slice(1));
  const stat = (k, v, cls = "", sub = "") => `<div class="cs ${cls}"><span>${k}</span><b>${v}</b>${sub ? `<small>${sub}</small>` : ""}</div>`;
  const d = r.during_changes;
  const card = (c) => {
    const tone = pillFor(c.outcome), gateOk = c.checks && c.checks_passed === c.checks;
    const probe = [c.probe_retried ? `${c.probe_retried} retried` : "", c.probe_failed ? `${c.probe_failed} failed` : ""].filter(Boolean).join(" · ");
    const notes = [c.failed_checks.length ? `Failed check: ${esc(c.failed_checks[0])}${c.failed_checks.length > 1 ? ` (+${c.failed_checks.length - 1} more)` : ""}` : "",
      c.restore_s != null ? `Customer path healthy again in ${c.restore_s} s` : ""].filter(Boolean);
    return `<div class="chg ${tone}">
      <div class="chg-top"><b>${esc(title(c))}</b><span class="pill ${tone}">${esc(c.outcome)}</span><time>${when(c.ts)}</time></div>
      ${c.tasks.length ? `<div class="chg-tasks mono">${esc(c.tasks.join(", "))}</div>` : ""}
      <div class="chg-stats">
        ${stat("Gate checks", c.checks ? `${c.checks_passed} / ${c.checks}` : "–", c.checks ? (gateOk ? "ok" : "bad") : "")}
        ${stat("Customer path", c.probe_ops == null ? "–" : `${c.probe_ops - c.probe_failed} / ${c.probe_ops}`, c.probe_failed ? "bad" : "", probe)}
        ${stat("Real customers", c.customer_requests == null ? "–" : num0(c.customer_requests), c.customer_5xx ? "bad" : "", c.customer_5xx ? `${c.customer_5xx} retried errors` : "")}
        ${stat("Applied in", c.apply_s != null ? `${c.apply_s} s` : "–")}
      </div>
      ${notes.map((n) => `<p class="chg-note">${n}</p>`).join("")}</div>`;
  };
  el.innerHTML = `<div class="tiles">
    ${tile("Tasks live now", `${m.tasks_live} / ${m.tasks_total}`, "read from the running bank")}
    ${tile("Changes applied", m.applied, `${m.promoted} promoted by the gate`)}
    ${tile("Rolled back", m.auto_rolled_back + m.undone, `${m.auto_rolled_back} by the gate · ${m.undone} by the operator`)}
    ${tile("Customer path during changes", d.operations ? `${d.operations - d.failed} / ${d.operations}` : "–", `${d.payments} payments · ${d.retried} needed a retry · slowest ${d.slowest_s} s`)}
    ${tile("Real customers during changes", num0(d.customer_requests), `${d.customer_5xx} server errors, retried quietly by NetBank`)}</div>
    ${m.live.length ? `<h3 class="sub">In effect now</h3><div class="tags">${m.live.map((t) => `<span class="tag"><b>${esc(t.id)}</b> ${esc(t.service)}</span>`).join("")}</div>` : ""}
    <h3 class="sub">Every change, newest first</h3>
    <div class="chgs">${r.changes.map(card).join("")}</div>
    <div class="legend"><p><b>Customer path</b>: a simulated customer signs in, reads balances and pays while the change is applied. A request that needed a retry still succeeded for the customer.</p>
    <p><b>Real customers</b>: requests NetBank users made through the gateway during the change.</p></div>`;
}

async function refresh() {
  try {
    INV = await api("/api/inventory");
    renderInventory(); renderRisk();
    PLAN = await api("/api/plan");
    WAVES = await api("/api/waves");
    renderPlan(); renderWaves(); await renderReport();
    renderReal(await api("/api/repos"));
    renderBench(await api("/api/bench")); renderCircuits(await api("/api/circuits"));
    if (window.afterRefresh) await window.afterRefresh();
  } catch (e) { alertBox(e.message); }
}
refresh();
poll();
setInterval(poll, 1000);
