"use strict";
// PQBank NetBanking: a single-page customer app. All data comes from the bank's own API behind the public gateway.

const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const inr = new Intl.NumberFormat("en-IN", { style: "currency", currency: "INR" });
const money = (paise) => inr.format(paise / 100);
const when = (ts) => new Date(ts * 1000).toLocaleString("en-IN", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
const view = $("#view");

// ------------------------------------------------------------------ session (tab-scoped, never persisted to disk)
let S = {};
try { S = JSON.parse(sessionStorage.getItem("nb") || "{}"); } catch (e) { /* storage blocked: session lasts until reload */ }
const saveS = () => { try { sessionStorage.setItem("nb", JSON.stringify(S)); } catch (e) { /* ignore */ } };
const clearS = () => { S = {}; try { sessionStorage.removeItem("nb"); } catch (e) { /* ignore */ } };

let refreshing = null;
function refreshTokens() {
  if (!S.refresh) return Promise.resolve(false);
  refreshing = refreshing || fetch("/api/auth/refresh", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ refresh_token: S.refresh }) })
    .then(async (r) => {
      if (!r.ok) return false;
      const d = await r.json();
      S.access = d.access_token; S.refresh = d.refresh_token; saveS();
      return true;
    })
    .catch(() => false)
    .finally(() => { refreshing = null; });
  return refreshing;
}

const NET = { status: 0, ok: false, data: { error: "Network problem. Check your connection and try again." } };
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
// While the bank does not answer (connection lost, 502/503/504) keep trying quietly, with the same Idempotency-Key for
// payments, so a short outage on the bank's side never shows up as a failed payment. Only requests that are safe to
// repeat are retried: reads, anything with an Idempotency-Key (payments stop at their own deadline), and sign-in.
const UNANSWERED = (r) => r === null || r.status === 502 || r.status === 503 || r.status === 504;
async function api(method, path, body, idem, until) {
  const attempt = () => fetch(path, {
    method, cache: "no-store", body: body === undefined ? undefined : JSON.stringify(body),
    headers: { "Content-Type": "application/json", ...(S.access ? { Authorization: "Bearer " + S.access } : {}), ...(idem ? { "Idempotency-Key": idem } : {}) },
  }).catch(() => null);
  const safe = method === "GET" || !!idem || path === "/api/auth/login";
  const go = async () => {
    let r = await attempt(), delay = 400;
    const t0 = Date.now();
    while (safe && UNANSWERED(r) && Date.now() < (until || t0 + 45000)) { await sleep(delay); delay = Math.min(delay * 1.6, 2500); r = await attempt(); }
    return r;
  };
  let r = await go();
  if (r === null) return NET;
  if (r.status === 401 && S.refresh && !path.startsWith("/api/auth/")) {
    if (!(await refreshTokens())) { signOut("Your session has expired. Please sign in again."); return { status: 401, ok: false, data: { error: "Session expired" } }; }
    r = await go();
    if (r === null) return NET;
  }
  return { status: r.status, ok: r.ok, data: await r.json().catch(() => ({})) };
}

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg; t.hidden = false;
  clearTimeout(toast.t); toast.t = setTimeout(() => { t.hidden = true; }, 3500);
}

// ------------------------------------------------------------------ sign in / out
let idle;
const bump = () => { clearTimeout(idle); if (S.access) idle = setTimeout(() => signOut("You were signed out after 10 minutes of inactivity."), 600000); };
["click", "keydown", "mousemove", "touchstart"].forEach((e) => addEventListener(e, bump, { passive: true }));

function showLogin(msg) {
  $("#app").hidden = true; $("#login").hidden = false;
  const err = $("#login-error");
  err.hidden = !msg; err.textContent = msg || "";
  $("#u").focus();
}

async function signOut(msg) {
  const refresh = S.refresh;
  clearS(); clearTimeout(idle);
  if (refresh) fetch("/api/auth/logout", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ refresh_token: refresh }) }).catch(() => {});
  history.replaceState(null, "", location.pathname);
  showLogin(msg);
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = $("#login-form button"), err = $("#login-error");
  err.hidden = true; btn.disabled = true;
  const r = await api("POST", "/api/auth/login", { username: $("#u").value.trim(), password: $("#p").value });
  btn.disabled = false;
  if (!r.ok) { err.textContent = r.data.error || "Sign-in failed. Try again."; err.hidden = false; return; }
  S = { access: r.data.access_token, refresh: r.data.refresh_token, customer: r.data.customer, previous: r.data.previous_login };
  saveS(); $("#p").value = ""; bump();
  if (location.hash === "#/overview") route(); else location.hash = "#/overview";
});
$("#signout").addEventListener("click", () => signOut("You have been signed out."));

// ------------------------------------------------------------------ helpers
const fail = (res) => { view.innerHTML = `<div class="notice bad">${esc(res.data.error || "Request failed.")}</div>`; };
const acctLabel = (a) => `${a.type} · ${a.id} · ${money(a.balance)}`;
const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join(""));

function toPaise(text) {
  const m = /^(\d{1,9})(?:\.(\d{1,2}))?$/.exec(String(text).replace(/[,\s₹]/g, ""));
  return m ? parseInt(m[1], 10) * 100 + (m[2] ? parseInt(m[2].padEnd(2, "0"), 10) : 0) : null;
}

const txRow = (t, withAcct) => `<tr><td class="num">${when(t.ts)}</td>
  <td>${esc(t.counterparty.name || t.counterparty.account)}<span class="sub">${esc(t.memo || t.ref)}${withAcct ? ` · ${esc(t.acct.type)} ${esc(t.acct.id)}` : ""}</span></td>
  <td class="num right ${t.type === "credit" ? "cr" : "dr"}">${t.type === "credit" ? "+" : "−"}${money(t.amount)}</td></tr>`;

// ------------------------------------------------------------------ overview
async function viewOverview() {
  const a = await api("GET", "/api/accounts");
  if (!a.ok) return fail(a);
  const accts = a.data.accounts, total = accts.reduce((s, x) => s + x.balance, 0), hour = new Date().getHours();
  const first = (S.customer.name || "").split(" ")[0];
  view.innerHTML = `
    <div class="head"><div><h2>${hour < 12 ? "Good morning" : hour < 17 ? "Good afternoon" : "Good evening"}, ${esc(first)}</h2>
      <p>${S.previous ? "Last sign-in: " + when(S.previous) : "Welcome to PQBank. This is your first sign-in."}</p></div>
      <a class="btn" href="#/pay">Pay or transfer</a></div>
    <div class="grid">
      <div class="card total"><div class="label">Total balance</div><div class="big">${money(total)}</div><div>${accts.length} accounts</div></div>
      ${accts.map((x) => `<div class="card acct"><div class="meta"><span class="chip">${esc(x.type)}</span><span class="mono">${esc(x.id)}</span></div>
        <div class="label muted" style="margin-top:12px">Available balance</div><div class="big">${money(x.balance)}</div>
        <div class="actions"><a class="btn ghost small" href="#/statement?acct=${esc(x.id)}">Statement</a><a class="btn small" href="#/pay?from=${esc(x.id)}">Pay from here</a></div></div>`).join("")}
    </div>
    <div class="card"><div class="head" style="margin-bottom:6px"><h3>Recent activity</h3><a href="#/statement">Full statement</a></div>
      <div id="recent" class="scroll"><div class="skeleton"></div></div></div>`;
  const lists = await Promise.all(accts.map((x) => api("GET", `/api/accounts/transactions?account=${encodeURIComponent(x.id)}&limit=6`)));
  const rows = lists.flatMap((l, i) => (l.ok ? l.data.items.map((t) => ({ ...t, acct: accts[i] })) : [])).sort((x, y) => y.ts - x.ts).slice(0, 8);
  $("#recent").innerHTML = rows.length
    ? `<table class="list"><tr><th>Date</th><th>Details</th><th class="right">Amount</th></tr>${rows.map((t) => txRow(t, true)).join("")}</table>`
    : '<div class="empty">No transactions yet.</div>';
}

// ------------------------------------------------------------------ statement
async function viewStatement(p) {
  const a = await api("GET", "/api/accounts");
  if (!a.ok) return fail(a);
  const accts = a.data.accounts;
  view.innerHTML = `
    <div class="head"><div><h2>Statement</h2><p id="s-bal"></p></div><button id="s-csv" class="ghost" type="button" disabled>Download CSV</button></div>
    <div class="card">
      <div class="filters">
        <div><label for="s-acct">Account</label><select id="s-acct">${accts.map((x) => `<option value="${esc(x.id)}" ${x.id === p.get("acct") ? "selected" : ""}>${esc(x.type)} · ${esc(x.id)}</option>`).join("")}</select></div>
        <div><label for="s-from">From</label><input id="s-from" type="date"></div>
        <div><label for="s-to">To</label><input id="s-to" type="date"></div>
        <div><label for="s-type">Type</label><select id="s-type"><option value="">All</option><option value="debit">Money out</option><option value="credit">Money in</option></select></div>
        <button id="s-go" type="button">Apply</button>
      </div>
      <div id="s-held"></div>
      <div class="scroll" id="s-table"></div>
      <div class="btns" style="justify-content:center"><button id="s-more" class="ghost" type="button" hidden>Load more</button></div>
    </div>`;
  let items = [], offset = 0, bal = null;
  async function load(reset) {
    if (reset) { items = []; offset = 0; }
    const q = new URLSearchParams({ account: $("#s-acct").value, limit: 25, offset });
    for (const [k, id] of [["from", "s-from"], ["to", "s-to"], ["type", "s-type"]]) if ($("#" + id).value) q.set(k, $("#" + id).value);
    const r = await api("GET", "/api/accounts/transactions?" + q);
    if (!r.ok) { $("#s-table").innerHTML = `<div class="notice bad">${esc(r.data.error)}</div>`; return; }
    items = items.concat(r.data.items); offset = items.length; bal = r.data.balance;
    $("#s-bal").textContent = `${r.data.type} · ${r.data.account} · balance ${money(bal)}`;
    $("#s-held").innerHTML = r.data.held.length ? r.data.held.map((h) => `<div class="notice ${h.status === "held" ? "" : "bad"}">${h.status === "held" ? "Held for review" : "Declined"}: ${money(h.amount)} to ${esc(h.to_account)} (${esc(h.ref)}, ${when(h.ts)})${h.status === "held" ? ". No money has moved." : "."}</div>`).join("") : "";
    $("#s-table").innerHTML = items.length
      ? `<table class="list"><tr><th>Date</th><th>Details</th><th class="right">Money out</th><th class="right">Money in</th><th class="right">Balance</th></tr>
         ${items.map((t) => `<tr><td class="num">${when(t.ts)}</td><td>${esc(t.counterparty.name || t.counterparty.account)}<span class="sub">${esc(t.ref)}${t.memo ? " · " + esc(t.memo) : ""}</span></td>
         <td class="num right dr">${t.type === "debit" ? money(t.amount) : ""}</td><td class="num right cr">${t.type === "credit" ? money(t.amount) : ""}</td><td class="num right">${money(t.balance_after)}</td></tr>`).join("")}</table>`
      : '<div class="empty">No transactions match these filters.</div>';
    $("#s-more").hidden = !r.data.has_more; $("#s-csv").disabled = !items.length;
  }
  $("#s-go").onclick = () => load(true);
  $("#s-acct").onchange = () => load(true);
  $("#s-more").onclick = () => load(false);
  $("#s-csv").onclick = () => {
    const cell = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };   // block spreadsheet formula injection
    const lines = [["Date", "Reference", "Details", "Money out", "Money in", "Balance"].map(cell).join(",")].concat(items.map((t) => [
      new Date(t.ts * 1000).toISOString(), t.ref, `${t.counterparty.name || t.counterparty.account} ${t.memo}`.trim(),
      t.type === "debit" ? (t.amount / 100).toFixed(2) : "", t.type === "credit" ? (t.amount / 100).toFixed(2) : "", (t.balance_after / 100).toFixed(2)].map(cell).join(",")));
    const a2 = document.createElement("a");
    a2.href = URL.createObjectURL(new Blob([lines.join("\r\n")], { type: "text/csv" }));
    a2.download = `statement-${$("#s-acct").value}.csv`; a2.click(); URL.revokeObjectURL(a2.href);
  };
  await load(true);
}

// ------------------------------------------------------------------ pay and transfer
async function viewPay(p) {
  const [a, py, lim] = await Promise.all([api("GET", "/api/accounts"), api("GET", "/api/accounts/payees"), api("GET", "/api/payments/limits")]);
  if (!a.ok) return fail(a);
  const accts = a.data.accounts, payees = py.ok ? py.data.payees : [], limits = lim.ok ? lim.data : null;
  view.innerHTML = `<div class="head"><div><h2>Pay &amp; transfer</h2><p>Send money between your accounts or to anyone with a PQBank account.</p></div></div><div id="pay-box"></div>`;
  const box = $("#pay-box");

  function formStep(v = {}) {
    box.innerHTML = `<div class="card form"><form id="pf" novalidate>
      <label for="pf-from">From</label><select id="pf-from">${accts.map((x) => `<option value="${esc(x.id)}" ${x.id === (v.from || p.get("from")) ? "selected" : ""}>${esc(acctLabel(x))}</option>`).join("")}</select>
      <label for="pf-to">To</label><select id="pf-to"></select>
      <div id="pf-other" hidden><label for="pf-acc">Account number</label>
        <div class="row"><input id="pf-acc" placeholder="ACC-0000" autocomplete="off" autocapitalize="characters" spellcheck="false"><button id="pf-check" type="button" class="ghost">Verify</button></div>
        <p id="pf-name" class="muted"></p></div>
      <div class="row"><div><label for="pf-amt">Amount (₹)</label><input id="pf-amt" inputmode="decimal" placeholder="0.00" autocomplete="off" value="${esc(v.amount || "")}"></div>
        <div><label for="pf-memo">Remark (optional)</label><input id="pf-memo" maxlength="60" autocomplete="off" value="${esc(v.memo || "")}"></div></div>
      ${limits ? `<p class="muted">Limit ${money(limits.per_transfer)} per payment. ${money(limits.remaining_today)} left to send today. First payments above ${money(limits.review_above)} to a new payee are held for review.</p>` : ""}
      <p id="pf-err" class="error" role="alert" hidden></p>
      <div class="btns"><button type="submit">Review payment</button></div></form></div>`;
    const fromSel = $("#pf-from"), toSel = $("#pf-to");
    function fillTo(keep) {
      const own = accts.filter((x) => x.id !== fromSel.value);
      toSel.innerHTML = (own.length ? `<optgroup label="My accounts">${own.map((x) => `<option value="own:${esc(x.id)}">${esc(x.type)} · ${esc(x.id)}</option>`).join("")}</optgroup>` : "")
        + (payees.length ? `<optgroup label="Saved payees">${payees.map((x) => `<option value="payee:${esc(x.account)}">${esc(x.nickname)} · ${esc(x.account)}</option>`).join("")}</optgroup>` : "")
        + '<option value="other">Another account…</option>';
      const want = keep || p.get("to");
      if (want && [...toSel.options].some((o) => o.value === want)) toSel.value = want;
      $("#pf-other").hidden = toSel.value !== "other";
    }
    fillTo(v.to);
    fromSel.onchange = () => fillTo(toSel.value);
    toSel.onchange = () => { $("#pf-other").hidden = toSel.value !== "other"; };
    if (v.other) $("#pf-acc").value = v.other;
    $("#pf-check").onclick = async () => {
      const r = await api("GET", "/api/accounts/lookup?account=" + encodeURIComponent($("#pf-acc").value.trim().toUpperCase()));
      $("#pf-name").textContent = r.ok ? (r.data.own ? "This is one of your own accounts: " : "Account holder: ") + r.data.name : r.data.error;
    };
    $("#pf").onsubmit = async (e) => {
      e.preventDefault();
      const err = $("#pf-err"), bad = (m) => { err.textContent = m; err.hidden = false; };
      err.hidden = true;
      const amount = toPaise($("#pf-amt").value), from = accts.find((x) => x.id === fromSel.value);
      let to = toSel.value, dest = null;
      if (amount === null || amount < 1) return bad("Enter a valid amount, for example 1500.00.");
      if (limits && amount > limits.per_transfer) return bad(`The limit is ${money(limits.per_transfer)} per payment.`);
      if (amount > from.balance) return bad("Insufficient balance in the selected account.");
      if (to === "other") {
        const r = await api("GET", "/api/accounts/lookup?account=" + encodeURIComponent($("#pf-acc").value.trim().toUpperCase()));
        if (!r.ok) return bad(r.data.error);
        dest = { account: r.data.account, name: r.data.name, own: r.data.own, saved: false };
      } else {
        const id = to.split(":")[1], o = accts.find((x) => x.id === id), s = payees.find((x) => x.account === id);
        dest = o ? { account: id, name: `${o.type} account (yours)`, own: true, saved: true } : { account: id, name: s.name, own: false, saved: true };
      }
      if (dest.account === from.id) return bad("Choose a different account to pay.");
      reviewStep({ from, dest, amount, memo: $("#pf-memo").value.trim(), raw: { from: from.id, to, amount: $("#pf-amt").value, memo: $("#pf-memo").value, other: $("#pf-acc").value } });
    };
  }

  function reviewStep(d) {
    const idem = uuid();                           // one key per reviewed payment: a retry can never pay twice
    box.innerHTML = `<div class="card form"><h3>Review and confirm</h3>
      <table class="review">
        <tr><td>From</td><td>${esc(d.from.type)} · <span class="mono">${esc(d.from.id)}</span></td></tr>
        <tr><td>To</td><td>${esc(d.dest.name)}<span class="sub mono">${esc(d.dest.account)}</span></td></tr>
        <tr><td>Amount</td><td class="amt">${money(d.amount)}</td></tr>
        <tr><td>Remark</td><td>${esc(d.memo) || '<span class="muted">none</span>'}</td></tr>
        <tr><td>Balance after</td><td>${money(d.from.balance - d.amount)}</td></tr></table>
      <p id="rv-err" class="error" role="alert" hidden></p>
      <div class="btns"><button id="rv-go" type="button">Confirm &amp; pay</button><button id="rv-back" class="ghost" type="button">Edit</button></div></div>`;
    $("#rv-back").onclick = () => formStep(d.raw);
    $("#rv-go").onclick = async () => {
      const btn = $("#rv-go"), err = $("#rv-err");
      btn.disabled = true; err.hidden = true; btn.textContent = "Processing…";
      // The bank settles or fails a payment within 12 s (never posting a failed one later), so waiting 20 s is enough
      // to know. The same key is reused for every try: a retry can never pay twice.
      const until = Date.now() + 20000;
      const pay = () => api("POST", "/api/payments/transfers", { from_account: d.from.id, to_account: d.dest.account, amount: d.amount, memo: d.memo }, idem, until);
      let r = await pay();
      while (r.data.status === "processing" && Date.now() < until) { await sleep(1500); r = await pay(); }
      btn.disabled = false; btn.textContent = "Confirm & pay";
      if (r.data.status && r.data.status !== "processing") return receiptStep(r.data, d);
      if (r.status === 0 || r.status >= 500 || r.data.status === "processing") {   // the bank did not answer in time
        return receiptStep({ status: "failed", unconfirmed: true, reason: "The bank is temporarily unavailable, so we could not complete this payment.",
          amount: d.amount * 1, to_name: d.dest.name, to_account: d.dest.account, from_account: d.from.id, memo: d.memo, created: Date.now() / 1000 }, d);
      }
      err.textContent = r.data.error || "The payment could not be completed."; err.hidden = false;
    };
  }

  function receiptStep(r, d) {
    const posted = r.status === "posted", held = r.status === "held_for_review", failed = r.status === "failed";
    box.innerHTML = `<div class="card receipt"><div class="tick ${posted ? "ok" : held ? "warn" : "bad"}">${posted ? "✓" : held ? "!" : "×"}</div>
      <h2>${posted ? "Payment successful" : held ? "Payment held for review" : failed ? "Payment failed" : "Payment declined"}</h2>
      <p class="muted">${posted ? "The money has been sent." : held ? "Large first payments to a new payee are reviewed before money moves. Nothing has left your account." : esc(r.reason || "The bank declined this payment.") }</p>
      ${failed && r.unconfirmed ? `<p class="muted">If this payment shows on your statement it went through, so do not repeat it. Otherwise nothing was taken from your account.</p>` : ""}
      <table class="review">${r.reference ? `<tr><td>Reference</td><td class="mono">${esc(r.reference)}</td></tr>` : ""}
        <tr><td>Amount</td><td>${money(r.amount)}</td></tr>
        <tr><td>To</td><td>${esc(r.to_name)} · <span class="mono">${esc(r.to_account)}</span></td></tr>
        <tr><td>From</td><td class="mono">${esc(r.from_account)}</td></tr>
        <tr><td>Date</td><td>${when(r.created)}</td></tr>${r.memo ? `<tr><td>Remark</td><td>${esc(r.memo)}</td></tr>` : ""}</table>
      <div class="btns" style="justify-content:center">${failed ? '<button id="retry" type="button">Try again</button>' : ""}<a class="${failed ? "btn ghost" : "btn"}" href="#/pay" id="again">New payment</a>
        <a class="btn ghost" href="#/statement?acct=${esc(r.from_account)}">View statement</a>
        ${posted && !d.dest.own && !d.dest.saved ? '<button id="save-payee" class="ghost" type="button">Save payee</button>' : ""}</div></div>`;
    $("#again").onclick = (e) => { e.preventDefault(); viewPay(new URLSearchParams()); };
    if (failed) $("#retry").onclick = () => reviewStep(d);                      // same details, fresh payment reference
    const sp = $("#save-payee");
    if (sp) sp.onclick = async () => { const s = await api("POST", "/api/accounts/payees", { account: d.dest.account, nickname: d.dest.name }); toast(s.ok ? "Payee saved" : s.data.error); sp.hidden = s.ok; };
  }
  formStep();
}

// ------------------------------------------------------------------ payees
async function viewPayees() {
  const r = await api("GET", "/api/accounts/payees");
  if (!r.ok) return fail(r);
  view.innerHTML = `<div class="head"><div><h2>Payees</h2><p>People and businesses you pay often.</p></div></div>
    <div class="card"><div class="scroll">${r.data.payees.length
      ? `<table class="list"><tr><th>Name</th><th>Nickname</th><th>Account</th><th></th></tr>${r.data.payees.map((x) => `<tr><td>${esc(x.name)}</td><td>${esc(x.nickname)}</td><td class="mono">${esc(x.account)}</td>
         <td class="right"><a class="btn small" href="#/pay?to=payee:${esc(x.account)}">Pay</a> <button class="danger small" data-rm="${esc(x.account)}" type="button">Remove</button></td></tr>`).join("")}</table>`
      : '<div class="empty">No saved payees yet.</div>'}</div></div>
    <div class="card form"><h3>Add a payee</h3>
      <div class="row"><div><label for="py-acc">Account number</label><input id="py-acc" placeholder="ACC-0000" autocomplete="off" autocapitalize="characters"></div>
        <div><label for="py-nick">Nickname (optional)</label><input id="py-nick" maxlength="40" autocomplete="off"></div></div>
      <p id="py-msg" class="muted" role="status"></p>
      <div class="btns"><button id="py-add" type="button">Verify &amp; add</button></div></div>`;
  $("#py-add").onclick = async () => {
    const acc = $("#py-acc").value.trim().toUpperCase(), msg = $("#py-msg");
    const l = await api("GET", "/api/accounts/lookup?account=" + encodeURIComponent(acc));
    if (!l.ok) { msg.textContent = l.data.error; return; }
    const s = await api("POST", "/api/accounts/payees", { account: acc, nickname: $("#py-nick").value });
    if (!s.ok) { msg.textContent = s.data.error; return; }
    toast(`${l.data.name} added`); viewPayees();
  };
  view.querySelectorAll("[data-rm]").forEach((b) => { b.onclick = async () => { await api("POST", "/api/accounts/payees/remove", { account: b.dataset.rm }); toast("Payee removed"); viewPayees(); }; });
}

// ------------------------------------------------------------------ profile and security
function tokenAlg() {
  try { return JSON.parse(atob(S.access.split(".")[0].replace(/-/g, "+").replace(/_/g, "/"))).alg; } catch (e) { return "unknown"; }
}

async function viewProfile() {
  const r = await api("GET", "/api/accounts/profile");
  if (!r.ok) return fail(r);
  const u = r.data;
  view.innerHTML = `<div class="head"><div><h2>Profile &amp; security</h2></div></div>
    <div class="grid">
      <div class="card"><h3>Personal details</h3>
        <table class="review"><tr><td>Name</td><td>${esc(u.name)}</td></tr><tr><td>Username</td><td>${esc(u.username)}</td></tr>
          <tr><td>Customer ID</td><td class="mono">${esc(u.id)}</td></tr><tr><td>Last sign-in</td><td>${S.previous ? when(S.previous) : "This is your first sign-in"}</td></tr></table>
        <label for="pr-email">Email</label><input id="pr-email" type="email" value="${esc(u.email)}" autocomplete="email">
        <label for="pr-phone">Mobile</label><input id="pr-phone" type="tel" value="${esc(u.phone)}" autocomplete="tel">
        <p id="pr-msg" class="muted" role="status"></p>
        <div class="btns"><button id="pr-save" type="button">Save changes</button></div></div>
      <div class="card"><h3>Change password</h3>
        <label for="pw-cur">Current password</label><input id="pw-cur" type="password" autocomplete="current-password">
        <label for="pw-new">New password</label><input id="pw-new" type="password" autocomplete="new-password">
        <label for="pw-new2">Repeat new password</label><input id="pw-new2" type="password" autocomplete="new-password">
        <p class="muted">At least 10 characters with letters and digits. You will be signed out everywhere.</p>
        <p id="pw-msg" class="error" role="alert" hidden></p>
        <div class="btns"><button id="pw-go" type="button">Change password</button></div></div>
    </div>
    <div class="card"><h3>Session security</h3>
      <p>Your session token is signed with <span class="chip ok">${esc(tokenAlg())}</span>. The bank signs tokens with this algorithm and checks them on every request. It changes when the bank migrates its token signing to post-quantum cryptography, and your session carries on without interruption.</p></div>`;
  $("#pr-save").onclick = async () => {
    const s = await api("POST", "/api/accounts/profile", { email: $("#pr-email").value, phone: $("#pr-phone").value });
    $("#pr-msg").textContent = s.ok ? "Saved." : s.data.error;
  };
  $("#pw-go").onclick = async () => {
    const err = $("#pw-msg"), bad = (m) => { err.textContent = m; err.hidden = false; };
    err.hidden = true;
    if ($("#pw-new").value !== $("#pw-new2").value) return bad("The new passwords do not match.");
    const s = await api("POST", "/api/accounts/password", { current: $("#pw-cur").value, new: $("#pw-new").value });
    if (!s.ok) return bad(s.data.error);
    signOut("Password changed. Sign in with your new password.");
  };
}

// ------------------------------------------------------------------ router
const routes = { overview: viewOverview, statement: viewStatement, pay: viewPay, payees: viewPayees, profile: viewProfile };
async function route() {
  if (!S.access) return showLogin();
  const [name, qs] = (location.hash.slice(2) || "overview").split("?");
  $("#login").hidden = true; $("#app").hidden = false;
  $("#who").textContent = S.customer.name;
  document.querySelectorAll("#nav a").forEach((x) => x.classList.toggle("active", x.getAttribute("href") === "#/" + name));
  view.innerHTML = '<div class="skeleton"></div>';
  try { await (routes[name] || viewOverview)(new URLSearchParams(qs || "")); }
  catch (e) { view.innerHTML = `<div class="notice bad">Something went wrong. Please try again.</div>`; }
  window.scrollTo(0, 0);
}
addEventListener("hashchange", route);
bump();
route();
