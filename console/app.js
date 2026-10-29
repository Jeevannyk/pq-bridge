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
    const p = s.traffic.payments || {}, l = s.traffic.legacy || {}, g = s.traffic.ledger || {};
    $("#k-ok").textContent = (p.ok ?? 0).toLocaleString();
    $("#k-fail").textContent = (p.fail ?? 0).toLocaleString();
    $("#k-fail").className = p.fail ? "badv" : "good";
    $("#k-legacy").textContent = `${l.ok ?? 0} ok / ${l.fail ?? 0} fail`;
    $("#k-ledger").textContent = (g.tx_count ?? 0).toLocaleString();
    $("#k-alg").textContent = p.last_alg || "–";
    $("#chips").innerHTML = [
      ["QpiAI Opt key", s.keys.opt], ["QCloud key", s.keys.qcloud],
    ].map(([n, on]) => `<span class="chip ${on ? "on" : "off"}">${n}: ${on ? "set" : "missing"}</span>`).join("")
      + `<span class="chip">QCloud device: ${esc(s.qcloud_device)}</span>`;
    $("#log").textContent = s.log.join("\n");
    $("#log").scrollTop = 1e9;
    const wasBusy = BUSY;
    BUSY = s.busy;
    $("#busy").hidden = !BUSY;
    $("#busy").textContent = BUSY ? `Running: ${BUSY}…` : "";
    document.querySelectorAll("button[data-act], button[data-m]").forEach((b) => { if (b.dataset.m !== "probe" && b.dataset.m !== "analyse" && b.dataset.m !== "analyse-sample") b.disabled = !!BUSY; });
    if (wasBusy && !BUSY) refresh();
  } catch (e) { /* server restarting */ }
}

// ---------------------------------------------------------------- actions
async function act(name, arg) {
  const path = { scan: "/api/scan", plan: "/api/plan", drill: "/api/drill", report: null, wave: `/api/wave/${arg}`,
    repos: "/api/repos", survey: "/api/survey", bench: "/api/bench", circuits: "/api/circuits" }[name];
  try {
    if (path) { BUSY = name; poll(); await api(path, "POST"); }
  } catch (e) { toast(`✗ ${name}: ${e.message}`, 12000); }
  await refresh();
}
function alertBox(msg) { $("#log").textContent += `\n!! ${msg}`; }

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

// ---------------------------------------------------------------- inventory + risk
function renderInventory() {
  if (!INV || !INV.findings.length) return;
  const f = INV.findings, qv = f.filter((x) => x.status === "quantum-vulnerable");
  const cats = {};
  qv.forEach((x) => (cats[x.category] = (cats[x.category] || 0) + 1));
  $("#inv-summary").innerHTML =
    tile("Findings", f.length, "with file / endpoint evidence") +
    tile("Quantum-vulnerable", qv.length, "RSA · ECDSA · ECDH · X25519") +
    tile("PQ-safe", f.filter((x) => x.status === "pq-safe").length, "HQC · FN-DSA · SLH-DSA · hybrid") +
    Object.entries(cats).map(([c, n]) => tile(c, n, "vulnerable")).join("");
  const ev = INV.eval;
  if (ev) {
    const row = (n, k) => `<tr><td>${n}</td><td class="num">${ev[k].precision}</td><td class="num">${ev[k].recall}</td><td class="num">${ev[k].f1}</td><td class="num">${ev[k].tp}/${ev[k].fp}/${ev[k].fn}</td></tr>`;
    $("#inv-eval").innerHTML = `<div class="card"><h3>Detection accuracy on labelled corpus (${ev.labelled_positives} positives, ${ev.files} files, hard negatives included)</h3>
      <div class="scroll"><table><tr><th>Detector</th><th>Precision</th><th>Recall</th><th>F1</th><th>TP/FP/FN</th></tr>
      ${row("PQ-Bridge scanner", "pq_bridge")}${row("Naive grep baseline", "naive_grep")}</table></div>
      ${ev.pq_bridge.missed.length ? `<p>Missed: ${ev.pq_bridge.missed.map((m) => `<span class="mono">${esc(m[0])}:${m[1]}</span>`).join(", ")}</p>` : ""}</div>`;
  }
  const st = $("#f-status").value, cat = $("#f-cat").value;
  const rows = f.filter((x) => (!st || x.status === st) && (!cat || x.category === cat));
  $("#inv-table").innerHTML = `<tr><th>Status</th><th>Category</th><th>Service</th><th>Evidence</th><th>Algorithm</th><th>Snippet</th></tr>` +
    rows.map((x) => `<tr><td><span class="pill ${x.status === "pq-safe" ? "pq" : "qv"}">${x.status === "pq-safe" ? "PQ-safe" : "vulnerable"}</span></td>
      <td>${esc(x.category)}</td><td>${esc(x.service || "–")}</td><td class="mono">${esc(x.file)}${x.line ? ":" + x.line : ""}</td>
      <td>${esc(x.algorithm)}</td><td class="mono">${esc(x.snippet)}</td></tr>`).join("");
}
const tile = (l, v, s) => `<div class="tile"><span>${esc(l)}</span><b>${v}</b><br><small>${esc(s)}</small></div>`;

function renderRisk() {
  const r = INV && INV.risk;
  if (!r) return;
  const svc = Object.entries(r.services);
  $("#risk-body").className = "";
  $("#risk-body").innerHTML = `<p class="empty">Mosca's inequality: data is at risk when shelf-life X + migration time Y (${r.migration_years} y) exceeds years-to-CRQC Z (${r.crqc_years} y, configurable assumption).</p>
  <div class="scroll"><table><tr><th>Service</th><th>Risk</th><th></th><th>X + Y vs Z</th><th>Exposure</th><th>Vulnerable findings</th></tr>
  ${svc.map(([s, v]) => `<tr><td><b>${s}</b><br><small class="empty">${esc(v.desc)}</small></td><td class="num">${v.score}</td>
    <td style="min-width:140px"><div class="bar-h"><i style="width:${v.score * 10}%"></i></div></td>
    <td class="num">${v.mosca.X} + ${v.mosca.Y} ${v.mosca.at_risk ? "&gt;" : "≤"} ${v.mosca.Z} ${v.mosca.at_risk ? '<span class="pill qv">at risk</span>' : ""}</td>
    <td>${v.exposure === 1 ? "internet" : "internal"}</td><td class="num">${v.findings}</td></tr>`).join("")}</table></div>
  <h3 style="margin:18px 0 6px;font-size:1rem">Task risk (input r<sub>t</sub> to the optimiser)</h3>
  <div class="tasks">${Object.entries(r.tasks).sort((a, b) => b[1] - a[1]).map(([t, v]) => `<code>${t} · ${v}</code>`).join("")}</div>`;
}

// ---------------------------------------------------------------- plan
function renderPlan(qr) {
  const p = PLAN;
  if (!p || !p.final_waves) return;
  const W = p.windows, prim = p.primary, ex = p.baselines["OR-Tools CP-SAT (exact)"], gr = p.baselines["Greedy (risk-first, manual-style)"];
  const deg = p.hubo.terms_by_degree;
  const solverRows = [
    [prim.solver + (prim.fallback_reason ? " ⚠" : ""), prim.objective, prim.violations.length, prim.wall_s, prim.optimality_gap_pct + "%"],
    ["Final plan (after QAOA refinement)", p.final.objective, p.final.violations.length, "", ((p.final.objective - ex.objective) / ex.objective * 100).toFixed(2) + "%"],
    [ex.solver, ex.objective, ex.violations.length, ex.wall_s, "0%"],
    [gr.solver, gr.objective, gr.violations.length, "", ((gr.objective - ex.objective) / ex.objective * 100).toFixed(2) + "%"],
  ];
  const q = p.qaoa;
  const gantt = `<div class="gantt" style="--w:${W}"><div class="row"><div></div>${[...Array(W).keys()].map((w) => `<div class="hdr">Window ${w}${w === 1 ? " · freeze" : ""}</div>`).join("")}</div>
    ${p.tasks.map((t) => `<div class="row"><div class="lab" title="${esc(t.title)}">${t.id}</div>${[...Array(W).keys()].map((w) =>
      `<div class="cell ${p.final_plan[t.id] === w ? "on" : ""} ${w === 1 && t.service === "ledger" ? "freeze" : ""}" title="${p.final_plan[t.id] === w ? esc(t.title) : ""}"></div>`).join("")}</div>`).join("")}</div>`;
  $("#plan-body").className = "";
  $("#plan-body").innerHTML = `
  <div class="tiles">${tile("HUBO variables", p.hubo.variables, `${p.tasks.length} tasks × ${W} windows + slack`)}${tile("Terms", p.hubo.terms, `linear ${deg[1] || 0} · quad ${deg[2] || 0} · cubic ${deg[3] || 0}`)}
    ${tile("Violations", p.final.violations.length, "precedence · capacity · blast radius")}${tile("Risk-weighted delay", p.final.objective, "lower is better")}</div>
  ${prim.fallback_reason ? `<p class="rollback" style="border-color:var(--accent);background:var(--accent-soft)">QpiAI Opt was not used for this plan: ${esc(prim.fallback_reason)}. Add QPIAI_OPT_API_KEY to .env and regenerate.</p>` : ""}
  <div class="scroll"><table><tr><th>Solver</th><th>Objective</th><th>Violations</th><th>Time (s)</th><th>Gap vs exact</th></tr>
    ${solverRows.map((r) => `<tr><td>${esc(r[0])}</td><td class="num">${r[1]}</td><td class="num">${r[2]}</td><td class="num">${r[3]}</td><td class="num">${r[4]}</td></tr>`).join("")}</table></div>
  <h3 style="margin:20px 0 8px;font-size:1rem">Wave plan</h3>${gantt}
  <p class="empty">Deferred: ${p.deferred.map((d) => `<b>${d.id}</b> (${esc(d.reason)})`).join("; ")}</p>
  <div class="grid2">
    <div class="card"><h3>Remaining quantum exposure after each window</h3>${curve([["Final plan", p.final.exposure_curve_pct, "var(--steel)"], ["Greedy", gr.exposure_curve_pct, "var(--accent)"]])}</div>
    <div class="card"><h3>QAOA cross-check · QpiAI QCloud</h3>
      <p>Cluster <span class="mono">${q.cluster.join(", ")}</span> re-optimised with all other tasks fixed.</p>
      <div class="tiles" style="margin-top:8px">${tile("Qubits", q.qubits, `${q.reps} QAOA layers · ${q.device}`)}${tile("Circuit runs", q.circuit_runs, `${q.shots} shots each`)}
      ${tile("QAOA best", q.qaoa_best.energy, `optimum ${q.brute_force.energy}`)}${tile("P(optimum)", q.p_optimal, `uniform ${q.p_optimal_uniform_random}`)}</div>
      <p>${q.found_optimum ? '<span class="pill pass">found brute-force optimum</span>' : '<span class="pill fail">optimum not reached</span>'}
      ${q.qaoa_improves_plan ? ' <span class="pill pass">improved the plan</span>' : ""} mean approximation ratio ${q.approx_ratio_mean}</p>
      ${spark(q.cvar_history)}</div>
    <div class="card"><h3>Quantum randomness for PQC keys · QpiAI QCloud</h3>${qr.length ? qr.map((r) => `<p><b>${esc(r.purpose)}</b>: ${r.labels.length} key seeds (SLH-DSA root, FN-DSA leaves / JWT) from ${r.run.shots} shots × ${r.run.qubits} qubits on ${esc(r.run.device)}.
      Health: monobit p=${r.health.monobit_p}, χ² p=${r.health.nibble_chi2_p}, max bias ${r.health.max_qubit_bias}
      <span class="pill ${r.health.passed ? "pass" : "fail"}">${r.health.passed ? "pass" : "fail"}</span></p>`).join("") + `<p class="empty">${esc(qr[0].run.source_note)}. Seeds = HKDF-SHA256(quantum bits ‖ OS CSPRNG), mixed into OpenSSL's DRBG with genpkey -rand.</p>` : '<p>Keys are generated when the wave containing <span class="mono">pki.pq-root</span> runs.</p>'}</div>
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
function spark(h) {
  if (!h || !h.length) return "";
  const W = 320, H = 60, mn = Math.min(...h), mx = Math.max(...h), r = mx - mn || 1;
  const pts = h.map((v, i) => `${(i * (W - 10)) / (h.length - 1) + 5},${5 + ((v - mn) * (H - 20)) / r}`).join(" ");
  return `<svg viewBox="0 0 ${W} ${H}" width="100%"><polyline fill="none" stroke="var(--steel)" stroke-width="1.5" points="${pts}"/><text x="5" y="${H - 2}">CVaR objective over ${h.length} optimiser steps (${h[0]} → ${h[h.length - 1]})</text></svg>`;
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
      ${passed}/${rec.checks.length} gate checks · ${rec.traffic_delta.pay_ok} payments settled, ${rec.traffic_delta.pay_fail} failed during wave</p>
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
  const r = await api("/api/report");
  if (!r.waves.length) return;
  $("#report-body").className = "";
  const d = r.detection_eval || {};
  $("#report-body").innerHTML = `<div class="tiles">
    ${tile("Payments during migration", r.payments_during_migration.settled, `${r.payments_during_migration.failed} failed`)}
    ${tile("Waves promoted", r.waves.filter((w) => w.passed && w.label !== "drill").length, `of ${r.waves.filter((w) => w.label !== "drill").length} run`)}
    ${tile("Detection P / R", d.pq_bridge ? `${d.pq_bridge.precision} / ${d.pq_bridge.recall}` : "–", d.naive_grep ? `grep ${d.naive_grep.precision} / ${d.naive_grep.recall}` : "")}
    ${tile("Exposure left", r.plan.exposure_curve_pct ? r.plan.exposure_curve_pct.at(-1) + "%" : "–", "after final window (plan)")}
    ${tile("Rollbacks", r.waves.filter((w) => w.rollback_s != null).length, r.waves.filter((w) => w.rollback_s != null).map((w) => w.rollback_s + " s").join(", "))}</div>
    <div class="scroll"><table><tr><th>Wave</th><th>Tasks</th><th>Gate</th><th>Payments ok / failed</th><th>Rollback</th></tr>
    ${r.waves.map((w) => `<tr><td>${w.label}</td><td class="mono">${w.tasks.join(", ")}</td><td><span class="pill ${w.passed ? "pass" : "fail"}">${w.checks_passed}/${w.checks}</span></td>
      <td class="num">${w.traffic.pay_ok} / ${w.traffic.pay_fail}</td><td class="num">${w.rollback_s != null ? w.rollback_s + " s" : "–"}</td></tr>`).join("")}</table></div>
    <p class="empty">Evidence files: evidence/inventory.json, detection_eval.json, risk.json, plan.json, qaoa.json, qrng_runs.jsonl, waves.jsonl, traces/, report.json</p>`;
}

async function refresh() {
  try {
    INV = await api("/api/inventory");
    renderInventory(); renderRisk();
    PLAN = await api("/api/plan");
    const qr = await api("/api/qrng");
    WAVES = await api("/api/waves");
    renderPlan(qr); renderWaves(); await renderReport();
    renderReal(await api("/api/repos")); renderSurvey(await api("/api/survey"));
    renderBench(await api("/api/bench")); renderCircuits(await api("/api/circuits"));
    if (window.afterRefresh) await window.afterRefresh();
  } catch (e) { alertBox(e.message); }
}
refresh();
poll();
setInterval(poll, 1000);
