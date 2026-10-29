// Security-admin dashboard (the Start page): the whole bank on one screen. Data from /api/dashboard, refreshed every 8 s.
(function () {
  const inr0 = new Intl.NumberFormat("en-IN", { style: "currency", currency: "INR", maximumFractionDigits: 0 });
  const inr2 = new Intl.NumberFormat("en-IN", { style: "currency", currency: "INR" });
  const rupees = (p) => inr0.format((p || 0) / 100);
  const rupees2 = (p) => inr2.format((p || 0) / 100);
  const num = (n) => (n ?? 0).toLocaleString("en-IN");
  const clock = (ts) => (ts ? new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "–");
  const stamp = (ts) => (ts ? new Date(ts * 1000).toLocaleString([], { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }) : "–");
  const pct = (a, b) => (b ? Math.round((100 * a) / b) : 0);
  const algPill = (a) => (a ? `<span class="pill ${/^RS|^ES|^PS/.test(a) ? "qv" : "pq"}">${esc(a)}</span>` : '<span class="dim">–</span>');
  const certPill = (v) => (v ? cryptoPill("cert", v) : '<span class="dim">–</span>');
  const bar = (v, max, cls) => `<div class="bar-h ${cls || ""}"><i style="width:${Math.min(100, pct(v, max))}%"></i></div>`;
  let last = null, audit = null, inflight = false;

  function banner(d) {
    const up = d.containers.filter((c) => c.state === "running").length, m = d.migration, led = d.ledger || {};
    const head = { ok: "All systems operational", warn: "Needs attention", bad: "Action required" }[d.overall];
    const ledger = led.money_conserved && led.journal_balanced ? "ledger balanced" : "LEDGER CHECK FAILED";
    const auditN = d.settlement.last_status ? ` · last settlement ${d.settlement.last_status}` : "";
    return `<div class="dbanner ${d.overall}">
      <div><span class="dlabel">Bank status</span><b>${head}</b>
        <small>${up} of ${d.containers.length} bank services running · ${ledger}${auditN}</small></div>
      <div class="dprog"><span class="dlabel">Post-quantum migration</span><b>${m.done}<em> / ${m.total} tasks</em></b>${bar(m.done, m.total)}
        <small>${pct(m.done, m.total)}% live · ${m.blocked} waiting on a prerequisite</small></div></div>`;
  }

  function kpis(d) {
    const c = d.customers, a = d.accounts, t = d.transfers, x = d.exposure;
    const up = d.containers.filter((s) => s.state === "running").length;
    return `<div class="tiles dtiles">
      ${tile("Customers", num(c.total), `${num(c.active_24h)} signed in today`)}
      ${tile("Accounts", num(a.total), `${rupees(a.balance)} held`)}
      ${tile("Transactions", num(t.posted), `${num(t.last_hour)} in the last hour`)}
      ${tile("Money moved", rupees(t.volume), t.posted ? `largest ${rupees2(t.largest)}` : "no payments yet")}
      ${tile("Services up", `${up} / ${d.containers.length}`, "bank services")}
      ${tile("Quantum-vulnerable", `${x.services_exposed} / ${x.services}`, `services · ${num(x.items)} crypto items in use now`)}</div>
    <p class="hint" style="margin:-6px 0 14px">Customer figures count people using NetBank. The ${num(c.excluded_bots)} automated test accounts used by the verification gate are excluded.</p>`;
  }

  function attention(d) {
    const icon = { bad: "✗", warn: "!", info: "i" };
    const rows = d.alerts.length
      ? d.alerts.map((a) => `<a class="alert ${a.level}" href="${esc(a.href)}"><i>${icon[a.level]}</i><span>${esc(a.text)}</span></a>`).join("")
      : '<p class="dim">Nothing needs attention.</p>';
    return `<div class="card"><h3>Needs attention</h3><div class="alerts">${rows}</div></div>`;
  }

  function migration(d) {
    const m = d.migration, a = d.algorithms, kind = { enabler: "Prepare (keys, trust, PKI)", confidentiality: "Key exchange (HQC hybrid)", authentication: "Signatures (FN-DSA / SLH-DSA)" };
    const next = m.next.length
      ? m.next.map((t) => `<li><span>${esc(t.title)}</span><small>${esc(t.service)} · window ${t.window ?? "–"} · risk ${t.risk ?? "–"}</small></li>`).join("")
      : '<li class="dim">No task is ready.</li>';
    return `<div class="card"><h3>Migration progress</h3>
      <div class="dsplit">
        <div>${Object.entries(m.by_kind).map(([k, v]) => `<div class="hb"><span>${esc(kind[k] || k)}</span>${bar(v.done, v.total)}<b>${v.done}/${v.total}</b></div>`).join("")}
          <h4>Next up</h4><ul class="dlist">${next}</ul></div>
        <div><h4 style="margin-top:0">Algorithms live now</h4>
          <table class="dmini"><tr><td>Customer tokens</td><td>${algPill(a.token)}</td></tr>
          <tr><td>Audit log</td><td>${algPill(a.audit)}</td></tr><tr><td>Settlement batches</td><td>${algPill(a.settlement)}</td></tr>
          <tr><td>Public certificate</td><td>${certPill(a.public_cert)}</td></tr>
          <tr><td>Customer key exchange</td><td>${a.gateway_kex ? cryptoPill("kex", a.gateway_kex) : "–"}</td></tr></table></div></div></div>`;
  }

  function services(d) {
    const rows = d.services.map((s) => {
      const c = s.crypto, signs = [c.jwt_alg && "tokens " + c.jwt_alg, c.audit_alg && "audit " + c.audit_alg, c.settle_alg && "batches " + c.settle_alg].filter(Boolean);
      const run = s.state === "running";
      return `<tr><td><b>${esc(s.title)}</b><small class="dnote">${esc(s.name)} · ${esc(s.desc)}</small></td>
        <td><span class="pill ${run ? "pass" : "fail"}">${esc(s.state)}</span><small class="dnote">${esc(s.status.replace(/^Up /, "up "))}</small></td>
        <td>${c.kex ? cryptoPill("kex", c.kex) : '<span class="dim">–</span>'}</td>
        <td>${c.cert ? certPill(c.cert) + (c.public_cert ? `<small class="dnote">public ${esc(c.public_cert === "rsa" ? "RSA-2048" : "FN-DSA-512")}</small>` : "") : '<span class="dim">–</span>'}</td>
        <td>${c.trust ? cryptoPill("trust", c.trust) : '<span class="dim">–</span>'}</td>
        <td>${signs.length ? signs.map((x) => { const [what, alg] = x.split(" "); return `<span class="dnote2">${what}</span> ${algPill(alg)}`; }).join("<br>") : '<span class="dim">–</span>'}</td>
        <td>${s.exposed.length ? `<span class="pill qv">${s.exposed.length} left</span>` : '<span class="pill pq">PQ-safe</span>'}</td></tr>`;
    }).join("");
    return `<div class="card"><h3>Services and crypto posture</h3><div class="scroll"><table class="dtable">
      <tr><th>Service</th><th>Status</th><th>Key exchange</th><th>TLS identity</th><th>Trust store</th><th>Signs</th><th>Quantum-vulnerable</th></tr>${rows}</table></div>
      <p class="hint" style="margin:8px 0 0">Live: read from each service's running configuration.</p></div>`;
  }

  function throughput(d) {
    const max = Math.max(1, ...d.buckets.map((b) => b.n)), t = d.transfers, avg = t.posted ? t.volume / t.posted : 0;
    const bars = d.buckets.map((b, i) => `<div class="col" title="${clock(b.t)}: ${num(b.n)} payments, ${rupees(b.v)}"><i style="height:${Math.max(2, pct(b.n, max))}%"></i><small>${i % 3 === 0 ? new Date(b.t * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : ""}</small></div>`).join("");
    return `<div class="card"><h3>Transactions</h3>
      <div class="spark" role="img" aria-label="Posted payments per 5 minutes, last hour">${bars}</div><p class="hint" style="margin:2px 0 10px">Posted payments per 5 minutes, last hour</p>
      <div class="dstats"><div><b>${num(t.posted)}</b><span>posted</span></div><div><b class="${t.held ? "warnv" : ""}">${num(t.held)}</b><span>held</span></div><div><b>${num(t.rejected)}</b><span>rejected</span></div>
        <div><b>${num(t.last_hour)}</b><span>last hour</span></div></div>
      <p class="hint" style="margin:10px 0 0">${rupees(t.volume_last_hour)} moved in the last hour · average payment ${rupees2(avg)}</p></div>`;
  }

  function recent(d) {
    const rows = d.recent.map((r) => `<tr><td class="num">${clock(r.created)}</td><td>${esc(r.from_name || r.from_account)}<small class="dnote">${esc(r.from_account)}</small></td>
      <td>${esc(r.to_name || r.to_account)}<small class="dnote">${esc(r.to_account)}</small></td><td class="num">${rupees2(r.amount)}</td>
      <td><span class="pill ${r.status === "posted" ? "pass" : r.status === "held" ? "warn" : "fail"}">${esc(r.status)}</span></td></tr>`).join("");
    return `<div class="card"><h3>Recent transactions</h3><div class="scroll"><table class="dtable"><tr><th>Time</th><th>From</th><th>To</th><th>Amount</th><th>Status</th></tr>${rows || '<tr><td colspan="5" class="dim">No transactions yet.</td></tr>'}</table></div></div>`;
  }

  function risk(d) {
    const x = d.exposure, n = x.services;
    const left = d.services.filter((s) => s.exposed.length).sort((a, b) => b.exposed.length - a.exposed.length);
    return `<div class="card"><h3>Quantum-vulnerable crypto in use</h3>
      <p class="hint" style="margin:0 0 8px">Services still on each classical algorithm, right now.</p>
      ${Object.entries(x.by_kind).map(([k, c]) => `<div class="hb"><span>${esc(k)}</span>${bar(c, k === "signatures" ? 3 : n, "bad")}<b>${c}</b></div>`).join("")}
      <h4>What is left, per service</h4>
      ${left.length ? `<ul class="dlist">${left.map((s) => `<li><span><b>${esc(s.title)}</b></span><small>${s.exposed.map(esc).join(" · ")}</small></li>`).join("")}</ul>`
        : '<p class="good">Every bank service is on post-quantum crypto.</p>'}</div>`;
  }

  function customers(d) {
    const c = d.customers;
    return `<div class="card"><h3>Customers and access</h3>
      <table class="dmini"><tr><td>Customers</td><td><b>${num(c.total)}</b></td></tr><tr><td>Signed in, last 24 h</td><td><b>${num(c.active_24h)}</b></td></tr>
      <tr><td>Live sessions</td><td><b>${num(c.sessions)}</b></td></tr><tr><td>Locked accounts</td><td><b class="${c.locked ? "badv" : ""}">${num(c.locked)}</b></td></tr>
      <tr><td>Failed sign-in counters</td><td><b>${num(c.failed_attempts)}</b></td></tr><tr><td>Saved payees</td><td><b>${num(c.payees)}</b></td></tr></table></div>`;
  }

  function integrity(d) {
    const led = d.ledger || {}, au = d.audit, se = d.settlement;
    const tick = (ok) => `<span class="pill ${ok ? "pass" : "fail"}">${ok ? "yes" : "NO"}</span>`;
    const algs = Object.entries(au.by_alg || {}).map(([a, n]) => `${esc(a)} ${num(n)}`).join(" · ");
    const v = audit ? `<p class="${audit.ok ? "good" : "badv"}" style="margin:8px 0 0">${audit.ok ? "✓" : "✗"} chain ${audit.hash_chain_ok ? "intact" : "BROKEN at " + audit.first_broken_seq}, ${audit.signatures_checked} signatures checked (${audit.signatures_failed.length} failed) at ${clock(audit.checked_at)}</p>` : "";
    return `<div class="card"><h3>Integrity and settlement</h3>
      <table class="dmini"><tr><td>Money conserved</td><td>${tick(led.money_conserved)}</td></tr><tr><td>Journal balanced</td><td>${tick(led.journal_balanced)}</td></tr>
      <tr><td>Customer audit entries</td><td><b>${num(au.entries)}</b><small class="dnote">${algs || "none yet"}</small></td></tr>
      <tr><td>Last settlement batch</td><td>${se.last_status ? `<span class="pill ${se.last_status === "accepted" ? "pass" : "fail"}">${esc(se.last_status)}</span><small class="dnote">${esc(se.last_alg || "")} · ${clock(se.last_ts)}</small>` : '<span class="dim">none yet</span>'}</td></tr></table>
      ${v}<div class="ctrl" style="margin-top:10px"><button class="ghost" data-dash="audit">Verify audit log</button></div></div>`;
  }

  function held(d) {
    const rows = d.held.map((r) => `<tr><td class="num">${stamp(r.created)}</td><td>${esc(r.from_name || r.from_account)}</td><td>${esc(r.to_name || r.to_account)}</td><td class="num">${rupees2(r.amount)}</td></tr>`).join("");
    return `<div class="card"><h3>Held for review</h3>${rows
      ? `<div class="scroll"><table class="dtable"><tr><th>When</th><th>From</th><th>To</th><th>Amount</th></tr>${rows}</table></div><p class="hint" style="margin:8px 0 0">Large first payments to a new payee are held by the fraud rule. No money has moved.</p>`
      : '<p class="dim">No payments are held.</p>'}</div>`;
  }

  function changes(d) {
    const rows = d.events.map((e) => `<tr><td class="num">${stamp(e.ts)}</td><td>${esc(e.type)}${e.tasks.length ? `<small class="dnote">${esc(e.tasks.join(", "))}</small>` : ""}</td>
      <td><span class="pill ${e.result === "passed" ? "pass" : e.result === "failed" ? "fail" : "warn"}">${esc(e.result)}</span>${e.failed_checks.length ? `<small class="dnote">${esc(e.failed_checks.join("; "))}</small>` : ""}</td></tr>`).join("");
    return `<div class="card"><h3>Recent changes</h3><div class="scroll"><table class="dtable"><tr><th>Time</th><th>Change</th><th>Gate result</th></tr>${rows || '<tr><td colspan="3" class="dim">No changes yet.</td></tr>'}</table></div></div>`;
  }

  function actions() {
    return `<div class="card"><h3>Actions</h3><div class="ctrl">
      <button data-m="gate">Run verification gate</button><button data-act="scan" class="ghost">Scan bank</button>
      <a class="btn ghost" href="#migrate">Open migration controls</a>
      <a class="btn ghost" href="https://localhost:8443/" target="_blank" rel="noopener">Open NetBank ↗</a>
      <button data-m="reset" class="danger">Reset bank to classical</button></div>
      <p class="hint" style="margin:8px 0 0">The gate runs every live check (handshakes, tokens, legacy client, payments). Reset returns the bank to RSA / X25519 in about 30 s and keeps scans and the plan.</p></div>`;
  }

  function render(d) {
    const el = document.getElementById("overview-body");
    if (!el) return;
    el.innerHTML = `${banner(d)}${kpis(d)}
      <div class="dash"><div class="c5">${attention(d)}</div><div class="c7">${migration(d)}</div>
        <div class="c12">${services(d)}</div>
        <div class="c5">${throughput(d)}</div><div class="c7">${recent(d)}</div>
        <div class="c5">${risk(d)}</div><div class="c3">${customers(d)}</div><div class="c4">${integrity(d)}</div>
        <div class="c6">${held(d)}</div><div class="c6">${changes(d)}</div>
        <div class="c12">${actions()}</div></div>`;
    const st = document.getElementById("dash-stamp");
    if (st) st.textContent = `Updated ${clock(d.generated)} · refreshes every 8 s`;
  }

  function header(d) {
    const el = document.getElementById("hstatus");
    if (!el) return;
    const up = d ? d.containers.filter((c) => c.state === "running").length : 0;
    el.dataset.level = d ? d.overall : "bad";
    document.getElementById("hs-text").textContent = d ? { ok: "Bank operational", warn: "Needs attention", bad: "Action required" }[d.overall] : "Bank unreachable";
    document.getElementById("hs-sub").textContent = d ? `${up} of ${d.containers.length} services running` : "no data from the console";
  }

  async function load() {
    if (inflight) return;
    inflight = true;
    try {
      last = await api("/api/dashboard");
      render(last); header(last);
    } catch (e) {
      header(null);
      const st = document.getElementById("dash-stamp");
      if (st) st.textContent = `Dashboard unavailable: ${e.message}`;
    } finally { inflight = false; }
  }

  document.addEventListener("click", async (e) => {
    const b = e.target.closest("button[data-dash='audit']");
    if (!b) return;
    b.disabled = true; b.textContent = "Verifying…";
    try { audit = await api("/api/audit/verify", "POST"); } catch (err) { toast(`✗ audit verification: ${err.message}`, 8000); }
    if (last) render(last);
  });

  window.loadDashboard = load;
  setInterval(() => { if (!document.hidden) load(); }, 8000);
  addEventListener("hashchange", () => { if (location.hash === "" || location.hash === "#overview") load(); });
})();
