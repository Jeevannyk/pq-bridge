// Multi-page router + every manual operator control. Loaded after sections.js, before app.js.

// ---------------------------------------------------------------- router
function route() {
  const id = (location.hash || "#overview").slice(1) || "overview";
  const target = document.getElementById(id) && document.getElementById(id).classList.contains("page") ? id : "overview";
  document.querySelectorAll(".page").forEach((p) => p.classList.toggle("active", p.id === target));
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.getAttribute("href") === "#" + target));
  window.scrollTo(0, 0);
}
window.addEventListener("hashchange", route);
document.addEventListener("DOMContentLoaded", route);

// ---------------------------------------------------------------- helpers
function toast(msg, ms = 6000) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.hidden = true), ms);
}

async function postJSON(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || r.statusText);
  return data;
}

function autoRollback() {
  const el = document.getElementById("ar");
  return el ? el.checked : true;
}

async function operate(label, path, body) {
  try {
    toast(`${label}… (gate checks take ~15 s)`, 60000);
    BUSY = label;
    const r = await postJSON(path, body);
    toast(summarise(r), 9000);
    await refresh();
    return r;
  } catch (e) {
    toast(`✗ ${label}: ${e.message}`, 12000);
  }
}

function summarise(r) {
  if (!r) return "done";
  if (r.type === "rollback" || (r.rollback && r.label && r.label.startsWith("rollback"))) {
    return `↩ Rolled back ${r.tasks.join(", ")} in ${r.rollback.restore_s} s (traffic healthy: ${r.rollback.healthy})`;
  }
  if (r.checks) {
    const failed = r.checks.filter((c) => !c.passed);
    const head = r.tasks && r.tasks.length ? `${r.tasks.join(", ")}: ` : "Gate on current state: ";
    if (!failed.length && r.chain && r.chain.length > 1) return `✓ Applied in order, each step gated: ${r.chain.join(" → ")}`;
    if (!failed.length) return `✓ ${head}all ${r.checks.length} gate checks passed${r.tasks.length ? " → promoted" : ""}`;
    const rb = r.rollback ? `\n↩ auto-rolled back in ${r.rollback.restore_s} s` : r.tasks.length ? "\n⚠ left in place (auto-rollback off): use Rollback last change" : "";
    const cf = r.chain_failed_at ? `\n(chain stopped at ${r.chain_failed_at}; earlier steps stay applied, use Rollback last change to undo them)` : "";
    return `✗ ${head}${failed.length} check(s) failed:\n- ${failed.map((c) => c.name).join("\n- ")}${rb}${cf}`;
  }
  if (r.group !== undefined) return `${r.service}: ${r.ok ? "handshake OK" : "HANDSHAKE FAILED"} · ${r.group} / ${r.peer_sig} · ${r.bytes_read ?? "?"} B`;
  return "done";
}

// ---------------------------------------------------------------- migration control

function cryptoPill(kind, v) {
  const map = {
    kex: { classical: ["X25519 (classical)", "qv"], hybrid: ["X25519+HQC-1 hybrid", "pq"], "pq-only": ["HQC-1 only", "pq"] },
    cert: { rsa: ["RSA-2048", "qv"], pq: ["FN-DSA-512", "pq"] },
    trust: { rsa: ["RSA root", "qv"], both: ["RSA + SLH-DSA roots", "pq"] },
  };
  const [t, c] = (map[kind] && map[kind][v]) || [v, ""];
  return `<span class="pill ${c}">${esc(t)}</span>`;
}

function renderControl(tv) {
  const el = document.getElementById("control-body");
  if (!el || !tv) return;
  const st = tv.state;
  const svcs = Object.keys(st).filter((s) => !s.startsWith("_"));
  const app = (s, v) => [
    v.jwt_alg && `signs tokens ${v.jwt_alg}`, v.jwt_publish && `JWKS: ${v.jwt_publish.join(" + ")}`,
    v.jwt_accept && `accepts ${v.jwt_accept.join(" + ")}`, v.audit_alg && `audit ${v.audit_alg}`,
    v.settle_alg && `settlement ${v.settle_alg}`, v.accept_settle && `partner accepts ${v.accept_settle.join(" + ")}`,
  ].filter(Boolean).join("<br>") || "–";
  const ar = autoRollback();
  el.innerHTML = `
  <div class="card"><h3>Live crypto posture of the bank</h3>
    <div class="scroll"><table class="matrix"><tr><th>Service</th><th>Key exchange</th><th>TLS identity</th><th>Trust store</th><th>Application crypto</th><th>Test it now (real handshake)</th></tr>
    ${svcs.map((s) => `<tr><td><b>${s}</b>${s === "clearing" ? '<small class="note">external partner</small>' : ""}</td><td>${cryptoPill("kex", st[s].kex)}</td>
      <td>${s === "gateway" ? `public ${cryptoPill("cert", st[s].public_cert)}<br>internal ${cryptoPill("cert", st[s].cert)}` : cryptoPill("cert", st[s].cert)}</td>
      <td>${cryptoPill("trust", st[s].trust)}</td>
      <td class="mono">${app(s, st[s])}</td>
      <td><button class="ghost small" data-m="probe" data-svc="${s}" data-mode="default">modern client</button>
          <button class="ghost small" data-m="probe" data-svc="${s}" data-mode="classical">classical client</button></td></tr>`).join("")}</table></div>
    <div id="probe-out"></div></div>

  <div class="card" style="margin-top:14px"><h3>Test &amp; recover</h3>
    <div class="ctrl">
      <button data-m="gate">Run verification gate now</button>
      <button data-m="rollback" class="ghost" ${tv.history.length ? "" : "disabled"}>Rollback last change${tv.history.length ? ` (${esc(tv.history[tv.history.length - 1].label)})` : ""}</button>
      <button data-m="reset" class="danger">Reset bank to classical</button>
      <label><input type="checkbox" id="ar" ${ar ? "checked" : ""}> Auto-rollback when the gate fails</label>
    </div>
    <p class="hint">The gate checks real handshakes per service, classical clients, forged/none/expired JWTs, missing or rogue client certificates, PQ-only downgrade, handshake latency budget, legacy customers and failed payments. Turn auto-rollback off to leave a bad change in place, inspect it, then roll it back by hand.</p></div>

  <div class="card" style="margin-top:14px"><h3>Migration tasks: apply one at a time (prioritised by QpiAI Opt)</h3>
    <div class="scroll"><table><tr><th></th><th>Task</th><th>Risk</th><th>Plan window</th><th>Needs first</th><th>Status</th><th>Action</th></tr>
    ${tv.tasks.slice().sort((a, b) => (a.window ?? 9) - (b.window ?? 9) || (b.risk ?? 0) - (a.risk ?? 0)).map((t) => `<tr>
      <td>${t.done || t.deferred ? "" : `<input type="checkbox" class="tsel" value="${t.id}">`}</td>
      <td><b class="mono">${t.id}</b><small class="note">${esc(t.title)}</small></td>
      <td class="num">${t.risk ?? "–"}</td><td class="num">${t.deferred ? "deferred" : t.window ?? "–"}</td>
      <td class="mono">${t.deps.length ? t.deps.map((d) => `<span class="${t.missing_deps.includes(d) ? "bad" : "ok"}">${d}</span>`).join("<br>") : "–"}</td>
      <td><span class="pill ${t.status === "applied" ? "pass" : t.status === "blocked" || t.status === "deferred" ? "fail" : "warn"}" title="${t.deferred ? "kept out of the plan: legacy customers cannot verify FN-DSA yet" : ""}">${t.status}</span></td>
      <td>${t.done ? "" : t.missing_deps.length
        ? `<button class="small" data-m="apply-chain" data-task="${t.id}" title="Applies every missing prerequisite first, in order, each one tested by the gate">Apply + prerequisites</button> <button class="danger small" data-m="force" data-task="${t.id}" title="Apply only this task, anyway: expect the pre-check or the gate to refuse it">Force</button>`
        : t.deferred
        ? `<button class="danger small" data-m="force" data-task="${t.id}" title="Expected to fail: legacy customers cannot verify FN-DSA yet">Force</button>`
        : `<button class="small" data-m="apply" data-task="${t.id}">Apply</button>`}</td></tr>`).join("")}</table></div>
    <div class="ctrl"><button data-m="apply-selected">Apply selected together</button>
      <span class="hint" style="margin:0">Blocked = a prerequisite is not in effect yet. <b>Apply + prerequisites</b> applies the whole chain in order, each step tested. <b>Force</b> applies only that task, so the checks can show why the order matters (expect a refusal).</span></div></div>`;
  const arEl = document.getElementById("ar");
  arEl.onchange = () => { try { localStorage.setItem("pqb-ar", arEl.checked ? "1" : "0"); } catch (e) {} };
  try { if (localStorage.getItem("pqb-ar") === "0") arEl.checked = false; } catch (e) {}
}

function renderEvents(evs) {
  const el = document.getElementById("events-body");
  if (!el) return;
  if (!evs || !evs.length) { el.className = "empty"; el.textContent = "No operator activity yet."; return; }
  el.className = "";
  el.innerHTML = evs.map((e) => {
    const when = new Date(e.ts * 1000).toLocaleTimeString();
    if (e.type === "rollback") {
      return `<div class="wave"><div class="wave-head"><h3>↩ ${esc(e.label)}</h3><span class="mono">${when}</span></div>
        <p>Restored ${esc((e.rollback.services || []).join(", ") || "state")} in <b>${e.rollback.restore_s} s</b>; traffic healthy: ${e.rollback.healthy}</p></div>`;
    }
    const title = e.type === "gate" ? `Gate run on current state · ${when}` : `${e.label.startsWith("manual") ? "Manual apply" : e.label} · ${when}`;
    return `<details class="wave"${e === evs[0] ? " open" : ""}><summary class="wave-head" style="cursor:pointer"><h3 style="display:inline">${esc(title)}</h3>
      <span class="pill ${e.passed ? "pass" : "fail"}">${e.passed ? "PASS" : e.rollback ? "FAILED → ROLLED BACK" : "FAILED"}</span></summary>
      ${waveCard(e.label, "", e.tasks || [], e, "").replace(/^<div class="wave">/, "<div>")}</details>`;
  }).join("");
}

// ---------------------------------------------------------------- risk form
function renderRiskForm(p) {
  const el = document.getElementById("risk-form");
  if (!el || !p || el.dataset.loaded) return;
  el.dataset.loaded = "1";
  el.innerHTML = `<div class="formrow">
      <label>Years until CRQC (Z) <input type="number" step="0.5" id="rp-z" value="${p.crqc_years}"></label>
      <label>Migration time (Y) <input type="number" step="0.5" id="rp-y" value="${p.migration_years}"></label></div>
    <div class="scroll"><table><tr><th>Service</th><th>Data shelf-life X (years)</th><th>Exposure (0.5 internal, 1 internet)</th><th>Criticality (0-1)</th></tr>
    ${Object.entries(p.services).map(([s, v]) => `<tr><td><b>${s}</b></td>
      <td><input type="number" step="1" data-rs="${s}" data-k="shelf_life_years" value="${v.shelf_life_years}"></td>
      <td><input type="number" step="0.1" data-rs="${s}" data-k="exposure" value="${v.exposure}"></td>
      <td><input type="number" step="0.1" data-rs="${s}" data-k="criticality" value="${v.criticality}"></td></tr>`).join("")}</table></div>
    <div class="ctrl"><button data-m="rescore">Re-score criticality</button><a class="tr" href="#plan">then regenerate the plan →</a></div>`;
}

// ---------------------------------------------------------------- click handling
document.addEventListener("click", async (e) => {
  const b = e.target.closest("button[data-m]");
  if (!b || b.disabled) return;
  const m = b.dataset.m;
  if (m === "apply") return operate(`Apply ${b.dataset.task}`, "/api/apply", { tasks: [b.dataset.task], auto_rollback: autoRollback() });
  if (m === "apply-chain") return operate(`Apply ${b.dataset.task} + prerequisites`, "/api/apply", { tasks: [b.dataset.task], auto_rollback: autoRollback(), with_deps: true });
  if (m === "force") {
    if (!confirm(`${b.dataset.task} has unmet prerequisites. Apply anyway to demonstrate the gate?`)) return;
    return operate(`Force ${b.dataset.task}`, "/api/apply", { tasks: [b.dataset.task], auto_rollback: autoRollback(), force: true });
  }
  if (m === "apply-selected") {
    const ids = [...document.querySelectorAll(".tsel:checked")].map((x) => x.value);
    if (!ids.length) return toast("Tick one or more tasks first");
    return operate(`Apply ${ids.join(", ")}`, "/api/apply", { tasks: ids, auto_rollback: autoRollback() });
  }
  if (m === "gate") return operate("Verification gate", "/api/gate");
  if (m === "rollback") return operate("Rollback last change", "/api/rollback");
  if (m === "reset") {
    if (!confirm("Reset the bank to fully classical? Takes ~30 s. Analysis results are kept.")) return;
    return operate("Reset bank", "/api/reset?keep=true");
  }
  if (m === "probe") {
    try {
      const r = await postJSON(`/api/probe/${b.dataset.svc}?mode=${b.dataset.mode}`);
      document.getElementById("probe-out").innerHTML = `<p class="${r.ok ? "" : "bad"}"><b>${esc(r.service)}</b> with ${esc(r.offered_groups)}:
        ${r.ok ? "✓ handshake OK" : "✗ HANDSHAKE FAILED"} · group <span class="mono">${esc(r.group)}</span> · server signature <span class="mono">${esc(r.peer_sig)}</span>
        · ${r.bytes_read ?? "?"} B received · <a class="tr" data-label="${r.trace_label}" data-svc="${r.service}">full TLS trace</a></p>`;
    } catch (err) { toast(`✗ probe: ${err.message}`); }
    return;
  }
  if (m === "rescore") {
    const p = { crqc_years: +document.getElementById("rp-z").value, migration_years: +document.getElementById("rp-y").value, services: {} };
    document.querySelectorAll("[data-rs]").forEach((i) => { (p.services[i.dataset.rs] = p.services[i.dataset.rs] || {})[i.dataset.k] = +i.value; });
    return operate("Re-score criticality", "/api/risk/params", p);
  }
});

// ---------------------------------------------------------------- refresh hook (called by app.js)
window.afterRefresh = async function () {
  const [tv, evs, rp] = await Promise.all([api("/api/tasks"), api("/api/events"), api("/api/risk/params")]);
  if (window.loadDashboard) loadDashboard();
  renderControl(tv);
  renderEvents(evs);
  renderRiskForm(rp);
};
