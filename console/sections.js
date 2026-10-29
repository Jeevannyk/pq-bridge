// Renderers for real-code analysis, TLS survey, benchmarks and QCloud circuits. Loaded before app.js.

const short = (r) => r.replace(/^(Consensys|jpmorganchase|aws-samples|apache|OpenBankProject|juspay|moov-io|goldmansachs|hyperledger)_/, "$1/");

// ---------------------------------------------------------------- real code (ML engine)
function renderReal(d) {
  if (!d || !d.eval) return;
  const ev = d.eval, S = d.summary;
  const meth = Object.entries(ev.methods).map(([k, v]) =>
    `<tr><td>${esc(k)}</td><td class="num">${v.precision}</td><td class="num">${v.recall}</td><td class="num">${v.f1}</td><td class="num">${v.tp}/${v.fp}/${v.fn}</td></tr>`).join("");
  const repos = Object.entries(S).filter(([, v]) => v.findings).sort((a, b) => b[1].findings - a[1].findings);
  const tot = repos.reduce((a, [, v]) => a + v.findings, 0);
  const conf = repos.reduce((a, [, v]) => a + v.confirmed, 0);
  const sev = (s) => `<span class="pill ${s === "critical" || s === "high" ? "qv" : ""}">${s}</span>`;
  const perRepo = {};
  const top = d.findings.filter((f) => (perRepo[f.repo] = (perRepo[f.repo] || 0) + 1) <= 4);
  $("#real-body").className = "";
  $("#real-body").innerHTML = `<div class="tiles">${tile("Repositories", Object.keys(S).length, "real, cloned from GitHub")}${tile("Findings", tot, "quantum-vulnerable usage sites")}
    ${tile("Crypto-verified", conf, "algorithm resolved via OpenSSL registry / RFC 7518 / JCA")}${tile("Labelled lines", ev.n, `${ev.positives} positive · leave-one-repo-out`)}</div>
  <div class="card"><h3>Engine accuracy on held-out repositories</h3><div class="scroll"><table><tr><th>Method</th><th>Precision</th><th>Recall</th><th>F1</th><th>TP/FP/FN</th></tr>${meth}</table></div>
    <p>Fused: a rule hit is kept unless ML p &lt; ${ev.thresholds.veto_t} and no algorithm verifies; a line no rule caught needs ML p ≥ ${ev.thresholds.balanced} (audit mode: ${ev.thresholds.audit}) <i>and</i> a verified algorithm.</p></div>
  <div class="scroll" style="margin-top:14px"><table><tr><th>Repository</th><th>Findings</th><th>Verified</th><th>Added by ML + verification</th><th>Production code</th><th>Primitives</th><th>Banking context</th></tr>
  ${repos.map(([r, v]) => `<tr><td class="mono">${esc(short(r))}</td><td class="num">${v.findings}</td><td class="num">${v.confirmed}</td><td class="num">${v.ml_only}</td><td class="num">${v.production}</td>
    <td>${Object.entries(v.primitives).slice(0, 4).map(([p, n]) => `${esc(p)} ${n}`).join(" · ")}</td>
    <td>${Object.entries(v.contexts).slice(0, 3).map(([p, n]) => `${esc(p)} ${n}`).join(" · ")}</td></tr>`).join("")}</table></div>
  <h3 style="margin:18px 0 6px;font-size:1rem">Highest-severity findings, up to 4 per repository (${top.length} of ${d.total})</h3>
  <div class="scroll"><table><tr><th>Severity</th><th>Repository</th><th>Evidence</th><th>Primitive</th><th>Context</th><th>Detected by</th><th>ML p</th><th>Verification</th><th>Snippet</th></tr>
  ${top.map((f) => `<tr><td>${sev(f.severity)}</td><td class="mono">${esc(short(f.repo))}</td><td class="mono">${esc(f.file)}:${f.line}</td>
    <td>${esc(f.primitive || "–")}</td><td>${esc(f.banking_context)}</td><td>${esc(f.detected_by)}</td><td class="num">${f.ml_p}</td>
    <td>${esc(f.verification)}</td><td class="mono">${esc(f.snippet)}</td></tr>`).join("")}</table></div>`;
}

// ---------------------------------------------------------------- survey
function renderSurvey(d) {
  if (!d || !d.summary) return;
  const s = d.summary;
  $("#survey-body").className = "";
  $("#survey-body").innerHTML = `<div class="tiles">${tile("Endpoints", s.reachable, `of ${s.probed} probed · ${s.ts}`)}${tile("PQ hybrid key exchange", s.pq_hybrid_kex, "negotiated X25519MLKEM768")}
    ${tile("HQC support", s.hqc_kex, "none yet: HQC applies on bank-controlled links")}${tile("PQ certificates", s.pq_signature_leaf, `RSA ${s.rsa_leaf} · ECDSA ${s.ecdsa_leaf}`)}</div>
  <p class="empty">Client offered <span class="mono">${esc(s.offered_groups)}</span>. Key exchange is moving through CDNs; authentication (certificates) has not moved at all. That is the gap PQ-Bridge's FN-DSA / SLH-DSA PKI migration targets.</p>
  <div class="scroll"><table><tr><th>Host</th><th>TLS</th><th>Key exchange</th><th>Server signature</th><th>Leaf key</th><th>Chain</th><th>Bytes</th></tr>
  ${d.rows.map((r) => `<tr><td class="mono">${esc(r.host)}</td><td>${esc(r.protocol)}</td><td><span class="pill ${r.pq_kex ? "pq" : "qv"}">${esc(r.group)}</span></td>
    <td class="mono">${esc(r.peer_sig)}</td><td class="mono">${esc((r.leaf_key || "").replace("PKEY: ", "").split(";")[0])}</td>
    <td class="num">${r.chain_certs}</td><td class="num">${r.bytes_read ?? "–"}</td></tr>`).join("")}</table></div>`;
}

// ---------------------------------------------------------------- benchmarks
function hbars(rows, key, unit, color) {
  const mx = Math.max(...rows.map((r) => r[key] || 0));
  return rows.map((r) => `<div style="display:grid;grid-template-columns:minmax(160px,1.4fr) 3fr 84px;gap:8px;align-items:center;margin:3px 0;font-size:.8rem">
    <span class="mono" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.mode)}">${esc(r.short || r.mode)}</span>
    <div class="bar-h"><i style="width:${(100 * (r[key] || 0)) / mx}%;background:${r.family === "classical" ? "var(--muted)" : color}"></i></div>
    <span class="num" style="text-align:right">${(r[key] ?? 0).toLocaleString()} ${unit}</span></div>`).join("");
}

function renderBench(d) {
  if (!d || !d.tls) return;
  const fmt = (v) => (v == null ? "–" : v >= 100 ? Math.round(v).toLocaleString() : v);
  $("#bench-body").className = "";
  $("#bench-body").innerHTML = `<p class="empty">${esc(d.env.openssl)} · oqs-provider ${esc(d.env.oqsprovider)} · ${esc(d.env.cpu)} (${d.env.nproc} vCPU, Docker Desktop emulator, not bank hardware) · ${d.env.handshakes} handshakes per mode · ${d.ts}</p>
  <div class="grid2">
    <div class="card"><h3>Handshake bytes on the wire</h3>${hbars(d.tls, "bytes_total", "B", "var(--steel)")}</div>
    <div class="card"><h3>Median handshake latency</h3>${hbars(d.tls, "median_ms", "ms", "var(--accent)")}</div>
    <div class="card"><h3>Handshakes per second</h3>${hbars(d.tls, "handshakes_per_wall_sec", "/s", "var(--ok)")}</div>
  </div>
  <div class="scroll" style="margin-top:14px"><table><tr><th>TLS mode</th><th>Group</th><th>Signature</th><th>Bytes</th><th>× classical</th><th>Median / p95 ms</th><th>× latency</th><th>Handshakes/s</th><th>Leaf cert B</th><th>GB/day @ ${d.projection.daily_handshakes / 1e6}M</th></tr>
  ${d.tls.map((r) => `<tr><td>${esc(r.mode)}</td><td class="mono">${esc(r.group)}</td><td class="mono">${esc(r.peer_sig)}</td><td class="num">${r.bytes_total.toLocaleString()}</td>
    <td class="num">${r.bytes_vs_classical_x}</td><td class="num">${r.median_ms} / ${r.p95_ms}</td><td class="num">${r.latency_vs_classical_x}</td>
    <td class="num">${fmt(r.handshakes_per_wall_sec)}</td><td class="num">${r.leaf_cert_bytes.toLocaleString()}</td><td class="num">${r.bandwidth_GB_per_day}</td></tr>`).join("")}</table></div>
  <div class="grid2">
    <div class="card"><h3>Signatures: storage and runtime</h3><div class="scroll"><table><tr><th>Algorithm</th><th>PK B</th><th>Sig B</th><th>Cert B</th><th>Sign/s</th><th>Verify/s</th><th>Keygen/s</th></tr>
      ${d.signatures.map((r) => `<tr><td>${esc(r.algorithm)}</td><td class="num">${fmt(r.public_key_bytes)}</td><td class="num">${fmt(r.signature_bytes)}</td><td class="num">${fmt(r.self_signed_cert_bytes)}</td>
        <td class="num">${fmt(r.sign_per_s)}</td><td class="num">${fmt(r.verify_per_s)}</td><td class="num">${fmt(r.keygen_per_s)}</td></tr>`).join("")}</table></div></div>
    <div class="card"><h3>Key exchange (KEM)</h3><div class="scroll"><table><tr><th>Algorithm</th><th>PK B</th><th>CT B</th><th>Keygen/s</th><th>Encaps/s</th><th>Decaps/s</th></tr>
      ${d.kems.map((r) => `<tr><td>${esc(r.algorithm)}</td><td class="num">${fmt(r.public_key_bytes)}</td><td class="num">${fmt(r.ciphertext_bytes)}</td>
        <td class="num">${fmt(r.keygen_per_s)}</td><td class="num">${fmt(r.encaps_per_s)}</td><td class="num">${fmt(r.decaps_per_s)}</td></tr>`).join("")}</table></div></div>
    <div class="card"><h3>JWT tokens (open-banking APIs)</h3><div class="scroll"><table><tr><th>Alg</th><th>Sig B</th><th>Token B</th><th>Sign ms</th><th>Verify ms</th><th>GB / 100M tokens</th></tr>
      ${d.jwt.map((r) => `<tr><td>${esc(r.jwt_alg)}</td><td class="num">${r.signature_bytes}</td><td class="num">${r.token_bytes}</td><td class="num">${r.sign_ms}</td>
        <td class="num">${r.verify_ms}</td><td class="num">${r.storage_GB_per_100M_tokens}</td></tr>`).join("")}</table></div></div>
  </div>
  ${(d.findings || []).map((f) => `<p class="rollback" style="border-color:var(--accent);background:var(--accent-soft)">${esc(f)}</p>`).join("")}`;
}

// ---------------------------------------------------------------- circuits
function circuitNote(c) {
  if (c.name === "qrng" && c.health) {
    return `Health: monobit p=${c.health.monobit_p}, χ² p=${c.health.nibble_chi2_p}, max bias ${c.health.max_qubit_bias}
      <span class="pill ${c.health.passed ? "pass" : "fail"}">${c.health.passed ? "pass" : "fail"}</span>`;
  }
  if (c.name === "qaoa") return `${c.variables.length} decision qubits (task@window). QAOA best ${c.qaoa_best_energy} vs brute-force ${c.brute_force_energy}.`;
  if (c.name === "shor") return `N=${c.N}, a=${c.a}: factors <b>${(c.factors_found || []).join(" × ")}</b>. ${esc(c.scale_note)}`;
  if (c.name === "grover") {
    return `Toy-cipher key ${c.target} found with p=${c.measured_success} (theory ${c.predicted_success}) after ${c.optimal_iterations} iterations
      vs ${c.classical_expected_tries} expected classical tries. ${esc(c.scale_note)}`;
  }
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
      ${c.diagram && c.diagram.endsWith(".png") ? `<div class="scroll" style="background:#fff;border-radius:4px"><img src="/api/circuits/file/${c.diagram}" alt="${esc(c.name)} circuit diagram" style="width:100%;height:auto;max-height:520px;object-fit:contain"></div>` : ""}
      <p>${circuitNote(c)}</p>
      <p class="empty">Ran on ${esc(c.device)} · ${c.shots} shots · ${c.run_s}s${c.job_id ? ` · job ${esc(c.job_id)}` : ""} ·
        <a class="tr" href="/api/circuits/file/${c.qasm}" target="_blank" rel="noopener">OpenQASM 2.0</a></p></div>`).join("")}</div>`;
}
