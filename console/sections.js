// Renderers for real-code analysis, benchmarks and QCloud circuits. Loaded before app.js.

const short = (r) => r.replace(/^(Consensys|jpmorganchase|aws-samples|apache|OpenBankProject|juspay|moov-io|goldmansachs|hyperledger)_/, "$1/");

// ---------------------------------------------------------------- real code (ML engine)
function renderReal(d) {
  if (!d || !d.eval) return;
  const ev = d.eval, S = d.summary;
  const m = ev.methods, pr = (k) => (m[k] ? `P ${m[k].precision} · R ${m[k].recall}` : "–");
  const stage = (t, k, s, hot) => `<div class="stage${hot ? " hot" : ""}"><span>${t}</span><b>${pr(k)}</b><small>${s}</small></div>`;
  const engine = `<div class="pipe pipe-one" style="margin-bottom:14px">
    <div class="stage"><span>Repositories</span><b>${Object.keys(S).length}</b><small>real, cloned from GitHub</small></div><i>›</i>
    ${stage("1 · Rules", "rules only", "per-language patterns", false)}<i>+</i>
    ${stage("2 · ML classifier", "ML classifier only (p>=0.5)", "n-grams, path, banking context", false)}<i>+</i>
    ${stage("3 · Crypto verification", "crypto verification only", "OpenSSL registry, RFC 7518, JCA", false)}<i>⇒</i>
    ${stage("Fused (balanced)", "fused: balanced", "a rule hit survives unless ML says no AND nothing verifies; no rule needs ML + verification", true)}</div>`;
  const meth = Object.entries(ev.methods).map(([k, v]) =>
    `<tr><td>${esc(k)}</td><td class="num">${v.precision}</td><td class="num">${v.recall}</td><td class="num">${v.f1}</td><td class="num">${v.tp}/${v.fp}/${v.fn}</td></tr>`).join("");
  const repos = Object.entries(S).filter(([, v]) => v.findings).sort((a, b) => b[1].findings - a[1].findings);
  $("#real-body").className = "";
  $("#real-body").innerHTML = `<h3 style="margin:0 0 8px;font-size:1rem">How the engine decides (accuracy on repos it was not trained on)</h3>${engine}
  <div class="card"><h3>Engine accuracy, tested on repositories it was not trained on</h3><div class="scroll"><table><tr><th>Method</th><th>Precision</th><th>Recall</th><th>F1</th><th>TP/FP/FN</th></tr>${meth}</table></div>
    <p>Fused: a rule hit is kept unless ML p &lt; ${ev.thresholds.veto_t} and no algorithm verifies; a line no rule caught needs ML p ≥ ${ev.thresholds.balanced} (audit mode: ${ev.thresholds.audit}) <i>and</i> a verified algorithm.</p></div>
  <div class="scroll" style="margin-top:14px"><table><tr><th>Repository</th><th>Findings</th><th>Verified</th><th>Added by ML + verification</th><th>Production code</th><th>Primitives</th><th>Banking context</th></tr>
  ${repos.map(([r, v]) => `<tr><td class="mono">${esc(short(r))}</td><td class="num">${v.findings}</td><td class="num">${v.confirmed}</td><td class="num">${v.ml_only}</td><td class="num">${v.production}</td>
    <td>${Object.entries(v.primitives).slice(0, 4).map(([p, n]) => `${esc(p)} ${n}`).join(" · ")}</td>
    <td>${Object.entries(v.contexts).slice(0, 3).map(([p, n]) => `${esc(p)} ${n}`).join(" · ")}</td></tr>`).join("")}</table></div>`;
}

// ---------------------------------------------------------------- benchmarks
const BENCH_MODE = { classical: "Classical", hybrid: "Hybrid", "pq-only": "Pure PQC" };

function renderBench(d) {
  if (!d || !d.tls || !d.signed) return;
  const num = (v) => (v >= 100 ? Math.round(v).toLocaleString() : v);
  const kb = (b) => (b / 1000).toFixed(1);
  const x = (v) => (v === 1 ? "baseline" : `×${Math.round(v * 10) / 10}`);
  const base = d.tls[0], hyb = d.tls.find((r) => r.family === "hybrid") || base;
  const maxB = Math.max(...d.tls.map((r) => r.bytes_total)), maxT = Math.max(...d.tls.map((r) => r.median_ms));
  const bar = (v, mx) => `<div class="bar-h" style="margin-top:4px"><i style="width:${(100 * v) / mx}%"></i></div>`;
  $("#bench-body").className = "";
  $("#bench-body").innerHTML = `
  <h3 class="sub" style="margin-top:0">mTLS between two bank services</h3>
  <div class="scroll"><table><tr><th>Mode</th><th>Key exchange</th><th>Certificate signature</th><th>Bytes on wire</th><th>Connect, median / p95</th><th>Handshakes/s</th></tr>
  ${d.tls.map((r) => `<tr><td><b>${esc(BENCH_MODE[r.family] || r.mode)}</b></td><td class="mono">${esc(r.group)}</td><td class="mono">${esc(r.peer_sig)}</td>
    <td><b>${kb(r.bytes_total)} KB</b> <small>${x(r.bytes_vs_classical_x)}</small>${bar(r.bytes_total, maxB)}</td>
    <td><b>${r.median_ms.toFixed(1)} / ${r.p95_ms.toFixed(1)} ms</b> <small>${x(r.latency_vs_classical_x)}</small>${bar(r.median_ms, maxT)}</td>
    <td class="num">${num(r.handshakes_per_s)}</td></tr>`).join("")}</table></div>
  <p class="hint">Hybrid adds ${kb(hyb.bytes_total - base.bytes_total)} KB and ${(hyb.median_ms - base.median_ms).toFixed(0)} ms per connection (HQC-1 key share plus the FN-DSA chain). Pure PQC is about the same size and speed as hybrid.</p>

  <h3 class="sub">What the bank signs</h3>
  <div class="scroll"><table><tr><th>Item</th><th>Algorithm</th><th>Signature</th><th>Sign</th><th>Verify</th></tr>
  ${d.signed.map((r) => `<tr><td>${esc(r.item)}</td><td class="mono">${esc(r.algorithm)}</td><td class="num">${r.signature_bytes.toLocaleString()} B</td>
    <td class="num">${num(r.sign_ms)} ms</td><td class="num">${num(r.verify_ms)} ms</td></tr>`).join("")}</table></div>`;
}

// ---------------------------------------------------------------- circuits
function circuitNote(c) {
  if (c.name === "qrng" && c.health) {
    return `Health: monobit p=${c.health.monobit_p}, χ² p=${c.health.nibble_chi2_p}, max bias ${c.health.max_qubit_bias}
      <span class="pill ${c.health.passed ? "pass" : "fail"}">${c.health.passed ? "pass" : "fail"}</span>`;
  }
  if (c.name === "qaoa") return `${c.variables.length} decision qubits (task@window). QAOA best ${c.qaoa_best_energy} vs brute-force ${c.brute_force_energy}.`;
  return "";
}

function renderCircuits(d) {
  if (!d || !Object.keys(d).length) return;
  $("#circ-body").className = "";
  $("#circ-body").innerHTML = `<div class="grid2">${Object.values(d).map((c) => c.error
    ? `<div class="card"><h3>${esc(c.name)}</h3><p>${esc(c.error)}</p></div>`
    : `<div class="card"><h3>${esc(c.name.toUpperCase())} <span class="pill ${c.role.startsWith("decision") ? "pass" : ""}">${esc(c.role)}</span></h3>
      <p>${esc(c.purpose)}</p>
      <div class="tiles" style="margin-top:8px">${tile("Qubits", c.qubits, "")}${tile("Depth", c.depth, "")}${tile("Gates", c.size, Object.entries(c.gates).slice(0, 3).map(([g, n]) => `${g}:${n}`).join(" "))}</div>
      ${c.diagram && c.diagram.endsWith(".png") ? `<div class="scroll" style="background:#fff;border-radius:4px"><img src="/api/circuits/file/${c.diagram}?v=${Date.now()}" alt="${esc(c.name)} circuit diagram" style="width:100%;height:auto;max-height:520px;object-fit:contain"></div>` : ""}
      <p>${circuitNote(c)}</p>
      ${c.cloud_error ? `<p><span class="pill warn">QCloud refused the job</span> ${esc(c.cloud_error)}. Ran on the local QpiAI simulator instead.</p>` : ""}
      <p class="empty">Ran on ${esc(c.device)} · ${c.shots} shots · ${c.run_s}s${c.job_id ? ` · job ${esc(c.job_id)}` : ""} ·
        <a class="tr" href="/api/circuits/file/${c.qasm}" target="_blank" rel="noopener">OpenQASM 2.0</a></p></div>`).join("")}</div>`;
}
