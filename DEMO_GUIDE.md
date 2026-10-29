# PQ-Bridge: Demo & Operator Guide

This guide is for the team presenting PQ-Bridge to the judges. It covers what every page of the console does, where the core logic lives, and how to show each part manually and live.

---

## 1. What PQ-Bridge does, in one minute

A bank cannot switch every RSA/ECC dependency to post-quantum cryptography at once without breaking payments. PQ-Bridge runs the migration safely, in five steps:

1. **Find** every quantum-vulnerable use of cryptography (RSA, ECDSA, ECDH, X25519, EdDSA, DH) with evidence.
2. **Score** how critical each one is (Mosca's inequality, exposure, criticality).
3. **Prioritise** the migration as a HUBO optimisation solved on **QpiAI Opt**, respecting dependencies, change-window capacity, a month-end freeze and a blast-radius rule.
4. **Migrate** one change at a time: hybrid X25519+HQC key exchange, FN-DSA-512 certificates and JWTs, SLH-DSA root CA.
5. **Prove** each change with a live verification gate, and **roll back** automatically or by hand if anything breaks.

Everything runs against a real mini-bank in Docker, with continuous payment traffic and a legacy customer client.

---

## 2. What is running

| Piece | What it is | How it runs |
|---|---|---|
| **Mini-bank** (`testbed/`) | `gateway` (nginx, public), `card-auth` (issues JWTs), `payment-switch` (verifies JWTs, routes payments), `ledger` (SQLite). All service-to-service traffic uses mTLS. | Docker Compose project `pqbank`, Alpine 3.22, OpenSSL 3.5.9 + liboqs 0.16 + oqs-provider 0.12 |
| **Load generator** | Sends payments through the gateway continuously (about 10/s). Counts every failure. | container `loadgen` |
| **Legacy client** | A customer app that only speaks classical TLS and trusts only the RSA root. Probes once a second. | container `legacy` |
| **Toolbox** | Issues certificates and runs the gate's real TLS handshakes and attack tests. | container `toolbox` |
| **Console** | FastAPI backend and a multi-page web UI. | `.\dev.ps1` → http://127.0.0.1:8000 |

**Header bar (every page):** live payments settled, failed payments since boot, legacy client ok/fail, ledger transactions, the JWT algorithm in use, and QpiAI key status. Keep it visible: *"payments never stop while we migrate"* is the core claim.

---

## 3. Starting up (before the demo)

```powershell
# 1. Start Docker Desktop and wait until it is running
# 2. First time only (builds images, ~5 min; runs the whole pipeline once so every page has data):
cd pq-bridge
.venv\Scripts\python run_all.py
# 3. Start the console (auto-reload: backend restarts on .py changes, browser reloads on UI changes)
.\dev.ps1
# 4. Open http://127.0.0.1:8000
```

`.env` must contain `QPIAI_OPT_API_KEY` and `QCLOUD_API_KEY`. The header chips show "set" when they are loaded.

**Right before presenting:** Overview → **Reset bank to classical** (about 30 s). This puts every service back to RSA-2048 / X25519 and clears the migration history. Scans, plan, survey, benchmarks and circuits are kept.

---

## 4. The core user flow, and where it lives in code

```
Discover ─▶ Criticality ─▶ Prioritise (QpiAI Opt) ─▶ Migrate one change ─▶ Verification gate ─▶ promote │ rollback
 scanner.py     risk.py         qubo.py                tasks.py / migrate.py    migrate.run_gate        migrate.rollback*
 detect.py
```

| Step | Console page | Code | What actually happens |
|---|---|---|---|
| Find the mini-bank's vulnerabilities | 1 · Bank inventory | `pqbridge/scanner.py` → `detect.py` | The **hybrid engine** (rules + ML + verification) reads the mini-bank's code and nginx configs; X.509/PEM and dependency manifests are parsed exactly; plus a real `openssl s_client` handshake to each service |
| How the detector was built | 2 · Detection engine | `pqbridge/detect.py` | **Trained and tested on 11 real bank / fintech repos** (read-only training data, not part of the migrated estate).  Rules, then an ML classifier (logistic regression on n-grams, path and banking context), then crypto verification (OpenSSL registry, RFC 7518, JCA names) |
| Criticality | 4 · Criticality | `pqbridge/risk.py` | Mosca X+Y>Z urgency × exposure × criticality × evidence count, giving a risk score per service and per task |
| Prioritise | 5 · Plan | `pqbridge/qubo.py` | Builds a HUBO (64 binaries, ~730 terms, 8 cubic terms). **QpiAI Opt** solves it multi-start; a validator checks every rule; CP-SAT (exact) and greedy are baselines; QAOA on QCloud re-checks one cluster |
| Migrate | 7 · Migration control | `pqbridge/tasks.py`, `testbed.py` | A task changes the bank's crypto state. nginx configs are re-rendered and **gracefully reloaded** (no dropped connections); PKI tasks issue SLH-DSA / FN-DSA certs with QRNG-seeded keys |
| Verify | 7 · Migration control | `pqbridge/migrate.py: run_gate` | 24 live checks: handshakes, compatibility, attacks, latency, payments |
| Rollback | 7 · Migration control | `migrate.rollback`, `rollback_last` | Restores the previous crypto state and reloads; measures time until traffic is healthy |

---

## 5. Page by page

### Overview & user flow
- Live migration progress (tasks in effect out of 16), payments, QpiAI key status, and how many changes can be rolled back.
- Clickable user-flow cards, one per page.
- **Reset bank to classical**: the demo restart button.

### 1 · Bank inventory
- **Scan bank estate** rescans the bank's code, rendered nginx configs, certificates and keys, and makes one live handshake per service.
- **Tiles:** totals, quantum-vulnerable vs PQ-safe, broken down by category.
- **Detection accuracy card:** precision/recall on the labelled corpus vs naive grep.
- **Filters:** status and category. Every row carries evidence (`file:line` or `tls://service:443`).
- **Demo point:** scan before migrating (everything vulnerable), then scan after a few waves. Endpoint rows flip to `x25519_hqc1` / `falcon512` (PQ-safe) and the vulnerable count drops.

### 2 · Detection engine (ML), trained on real bank code
The 11 real repos are **training and validation data only**. The engine on this page is the same one that scans the mini-bank on page 1.
- **Paste-and-analyse box (manual criticality detection).** Click **Load sample**, then **Analyse snippet**. Each candidate line shows:
  - decision: vulnerable or ignored
  - severity: critical, high, medium or low (RSA-1024 is critical, test code is lower)
  - primitive: RSA, ECDSA, ECDH, …
  - **why:** which rule fired, the ML probability, or that it was "no rule, ML + verification"
  - verification evidence: OpenSSL registry, RFC 7518 or JCA name
  - banking context: payments/cards, open banking, ledger/blockchain, settlement, transport TLS
  
  Paste any code the judges suggest. Comments, imports and AES/SHA lines are correctly ignored.
- **Re-validate on real repos** re-runs the engine over the 11 repos (2 to 9 minutes; don't click it live: the last results are already on the page). Shows:
  - engine accuracy, tested on repos it never saw in training
  - findings per repo with primitives and banking contexts
  - the highest-severity findings
- Modes: **balanced** (precision about 0.93, recall about 0.91) and **audit** (recall about 0.96).

### 3 · Public TLS survey
- One ordinary HTTPS handshake to each of 24 public bank and fintech sites (JPMorgan, Chase, BofA, Citi, HSBC, AWS, Visa, SBI, HDFC, NPCI, RBI, …).
- **Finding:** 21/24 already negotiate ML-KEM hybrid key exchange (through CDNs), but **0/24 use post-quantum certificates**. Authentication is the gap PQ-Bridge closes.
- **Re-run survey** takes about 40 s.

### 4 · Criticality (risk), the manual criticality controls
- An editable form with years to a quantum computer (Z), migration time (Y), and per-service data shelf-life (X), exposure and criticality.
- **Re-score criticality** recomputes service and task risk.
- **Demo:** set Z = 4 → card-auth becomes "at risk" and its tasks gain priority. Go to Plan → **Generate plan** and the windows reorder.

### 5 · Plan (QpiAI Opt)
- **Generate plan** builds the HUBO from the current task risks and solves it on QpiAI Opt (8 seeds, best feasible kept). It then validates the plan, compares it with CP-SAT and greedy, and runs QAOA on QCloud.
- **Shows:**
  - HUBO size (variables, terms, cubic terms)
  - solver comparison table: objective, violations, time, gap to the exact optimum
  - the Gantt of change windows (window 1 hatched = month-end freeze for the ledger)
  - the exposure-reduction curve
  - the QAOA card (qubits, runs, energy vs brute force)
  - the QRNG card
- **Talking point:** the plan is risk-first (e.g. `kex.gateway`, risk 10, lands in window 0). It respects every prerequisite and beats the manual-style greedy order.

### 6 · QCloud circuits
Four circuits built gate by gate with the QpiAI Quantum SDK. Each card has the diagram, qubits, depth, gate counts, run results and an OpenQASM 2.0 download.

| Circuit | Role | Result to mention |
|---|---|---|
| QRNG (16 qubits) | **decision input**: seeds for SLH-DSA / FN-DSA keys | health tests pass; mixed with OS CSPRNG and fed to OpenSSL's DRBG |
| QAOA (9–12 qubits) | **decision input**: schedule cross-check | finds the brute-force optimum for the cluster |
| Shor (N=15) | threat evidence | factors 15 = 3 × 5; RSA-2048 is estimated to need under 1M noisy qubits for under a week (Gidney 2025) |
| Grover (4-qubit toy cipher) | policy evidence | finds the key with about 96% probability in 3 iterations, which supports the AES-256 / SHA-384 policy |

**Re-run circuits** re-executes them. To use QCloud instead of the local simulator, set `QCLOUD_DEVICE` in `.env`; list devices with `python -m pqbridge.circuits --devices`.

### 7 · Migration control: the heart of the demo
**a) Live crypto posture.** For every service: key exchange, TLS identity (gateway shows public and internal), trust store and JWT algorithm. Red pill = classical, green = post-quantum.
- **modern client** / **classical client** buttons make a real handshake now and show the negotiated group, server signature and bytes. **full TLS trace** opens the raw `openssl s_client -trace` output.

**b) Test & recover.**
- **Run verification gate now**: runs all gate checks against the *current* state, without changing anything (about 15 s).
- **Rollback last change**: restores the state from before the most recent change and reloads. The toast shows the time until traffic is healthy.
- **Reset bank to classical**: full demo restart.
- **Auto-rollback when the gate fails:**
  - **On:** a failing change is undone automatically.
  - **Off:** the failing change stays in place, so you can show the damage (probe, header counters), then click **Rollback last change** by hand.

**c) Migration tasks: manual, one at a time.** Ordered by the QpiAI Opt plan window, then risk.
- **Status:** `applied`, `ready` (prerequisites in effect) or `blocked` (prerequisite missing, shown in red).
- **Apply** runs that one task, then the full gate. Promoted, or rolled back.
- **Apply + prerequisites** (shown on blocked tasks) applies every missing prerequisite first, in order, each as its own gated change, then the task itself. One click on `cert.ledger` does `pki.pq-root → trust.payment-switch → cert.ledger`. It stops at the first failed step; earlier steps stay applied (use **Rollback last change** to undo them one at a time).
- **Force** applies only that task, anyway, to show why order matters. Asks for confirmation. What you will see depends on the task:
  - certificate / trust tasks without the PQ PKI: the **pre-reload check** refuses ("`ledger.pq.crt` does not exist yet: apply `pki.pq-root` first"). Files are restored, the running bank is never touched, and the activity log shows a failed `preflight` check.
  - JWT / key-exchange order mistakes: real traffic breaks, the gate fails and rolls back (see the Fault scenarios).
- **Apply selected together:** tick several tasks and apply them as one change.
- Applying a blocked task with plain **Apply** (API call without force) is refused up front, naming the missing prerequisites and the chain that would fix it.

**d) Fault scenarios: break it on purpose.** Each button is only active when the scenario can actually fail in the current state.

| Scenario | What it does | Expected result |
|---|---|---|
| Public certificate switched before customers are ready | `cert.gateway-public`: gateway's public cert becomes FN-DSA | legacy client fails → gate ✗ "legacy customer client" → rollback ≈1 s; payments unaffected |
| JWT issuer switched before verifiers accept FN-DSA | `jwt.sign-fndsa` before `jwt.dual-verify` | payments get 401 → gate ✗ "failed payments" → rollback ≈1.5 s |
| Ledger forced to PQ-only before its client speaks HQC | `pqonly.ledger` before `kex.payment-switch` | ledger unreachable (502) → gate ✗ → rollback |

**e) Planned waves.** The QpiAI Opt schedule as windows. **Run wave N** applies the whole window and gates it. **Run fault drill** = the public-certificate scenario.

**f) Activity.** Every apply, gate run and rollback, newest first. Expand an entry to see every check, before/after handshake per service, bytes, p95 latency and trace links.

#### The 24 gate checks

| Category | Check |
|---|---|
| trace (4) | real handshake per service: expected group (`X25519` / `x25519_hqc1` / `hqc1`) and signature (`rsa_pss_rsae_sha256` / `falcon512`); chain verifies |
| compat (5) | a classical-only client still connects to each service (unless PQ-only is intended); legacy customer client keeps working |
| negative (9) | forged JWT, `alg=none` JWT and expired-but-validly-signed JWT rejected; missing client cert and rogue self-signed client cert rejected on all 3 internal services; classical client refused by a PQ-only service |
| overhead (4) | handshake p95 under 50 ms per service |
| functional (1) | payments settled during the window |
| availability (1) | **zero failed payments** during the window |

### 8 · Benchmarks
Classical vs hybrid vs PQ-only on the same OpenSSL build.
- TLS bytes on the wire, median/p95 latency, handshakes/s, leaf certificate size, GB/day projection.
- Signature table (sizes, sign/verify/keygen per second), KEM table, JWT size and storage table.
- **Talking points:**
  - hybrid costs about 17 KB and 11 ms per handshake vs 1.8 KB and 1.6 ms classical
  - an all-FN-DSA chain cuts that to about 9.8 KB
  - SLH-DSA signs in about 390 ms, so it is only used for the offline root
  - SLH-DSA cannot be a TLS leaf at all in OpenSSL 3.5 (finding shown on the page)
  - FN-DSA JWTs are 2.2× larger but sign faster than RS256
- **Re-run benchmarks** takes about 3 min.

### 9 · Report
Payments during migration (settled / failed), waves promoted, detection accuracy, remaining exposure, rollbacks with times, and the list of evidence files.

### Operator log
Everything the backend did, with timestamps, including refused actions.

---

## 6. Live demo script (about 12 minutes, all manual)

**Before:** Overview → *Reset bank to classical*. Leave the header visible.

1. **Overview (30 s).** "A real bank runs here: 10 payments a second, a legacy customer client, all classical crypto." Point at the counters.
2. **Bank inventory (1 min).** *Scan bank estate.* "One detection engine reads the bank: its code, its nginx configs, its certificates and a live handshake per service. Each finding has evidence and an ML + verification trail. These findings set the risk scores."
3. **Detection engine (2 min).** "This is the engine that just scanned our bank; we trained and tested it on real bank code." *Load sample* → *Analyse snippet.* Walk through four lines:
   - RSA-1024 → critical
   - `SHA256withECDSA` → JCA verified
   - `RSASSAVerifier` found by ML + verification, with no rule needed
   - the comment and AES line → ignored
   
   Scroll down: "Tested on repositories it never saw in training: JPMorgan, AWS, Juspay and others, precision about 0.92, recall about 0.91."
4. **TLS survey (30 s).** "21 of 24 banks already do PQ key exchange; none have PQ certificates."
5. **Criticality (1 min).** Show the Mosca table. Change Z to 4 → *Re-score*. "card-auth is now at risk too." (Assumptions are saved. Set Z back to 8 and re-score after the demo.)
6. **Plan (1.5 min).** *Generate plan.*
   - "QpiAI Opt solves the HUBO: 64 variables, with cubic terms for the blast radius."
   - Point to: feasible, beats greedy, gap to the exact optimum, the freeze respected, highest risk first.
7. **QCloud circuits (1 min).** QRNG seeds our keys, QAOA cross-checks the plan, Shor factors 15, Grover justifies AES-256.
8. **Migration control (4 min): the core.**
   1. In *Migration tasks*, click **Apply** on `kex.gateway` (window 0, risk 10). Toast: ✓ 24/24 → promoted. Posture: gateway turns green `X25519+HQC-1`. Click **modern client** on gateway → `x25519_hqc1`; **classical client** → still `X25519`. Backward compatible.
   2. **Apply** `pki.pq-root` (SLH-DSA root + FN-DSA leaves, QRNG-seeded) and `jwt.dual-verify`.
   3. Show that the order is enforced: **Apply** on a blocked task (e.g. `cert.ledger`) is refused, naming the missing prerequisite.
   4. **Fault:** untick *Auto-rollback*. Trigger *Ledger forced to PQ-only…* (needs `kex.payment-switch` not yet applied). Watch failed payments rise in the header. The activity entry shows ✗. Click **Rollback last change**: restored in about 1 s, payments recover.
   5. Tick *Auto-rollback* again. Trigger *Public certificate switched before customers are ready*. The gate fails on the legacy client and rolls back automatically. Payments are untouched.
   6. **Run verification gate now**: all green on the current state.
   7. Optionally **Run wave N** for the rest of the plan, showing a full window promoted.
9. **Inventory again (20 s).** *Scan bank estate*: endpoint rows are now PQ-safe; vulnerable count down.
10. **Benchmarks (1 min).** The cost of PQ: bytes ×10, latency ×7, and how the all-FN-DSA chain halves the bytes.
11. **Report (20 s).** Payments settled / failed during migration, rollbacks and their times.

**If something hangs:** watch the *Running…* badge in the sidebar; only one operation runs at a time. Check the Operator log page.

---

## 7. Manual testing without the UI (backup, or for judges who ask)

All endpoints are on `http://127.0.0.1:8000`. In PowerShell, `curl` is aliased, so use `curl.exe`.

```bash
curl.exe -s http://127.0.0.1:8000/api/tasks                                   # live state + task status
curl.exe -s -X POST http://127.0.0.1:8000/api/apply -H "Content-Type: application/json" -d "{\"tasks\":[\"kex.gateway\"]}"
curl.exe -s -X POST http://127.0.0.1:8000/api/apply -H "Content-Type: application/json" -d "{\"tasks\":[\"jwt.sign-fndsa\"],\"force\":true,\"auto_rollback\":false}"
curl.exe -s -X POST http://127.0.0.1:8000/api/rollback                        # undo the last change
curl.exe -s -X POST http://127.0.0.1:8000/api/gate                            # run all gate checks now
curl.exe -s -X POST "http://127.0.0.1:8000/api/probe/ledger?mode=classical"   # one handshake (default|classical|pq-only)
curl.exe -s -X POST http://127.0.0.1:8000/api/analyse -H "Content-Type: application/json" -d "{\"code\":\"KeyPairGenerator.getInstance(\\\"RSA\\\")\",\"filename\":\"A.java\"}"
curl.exe -s -X POST http://127.0.0.1:8000/api/plan                            # QpiAI Opt plan
curl.exe -s -X POST "http://127.0.0.1:8000/api/reset?keep=true"               # bank back to classical
```

A scripted end-to-end check of the manual controls is in `data/manual_smoke.py`. It resets the bank, then:
1. tries an apply that is refused for missing prerequisites
2. applies a ready task (passes the gate)
3. forces the JWT fault with auto-rollback on
4. applies a task with auto-rollback off, then rolls it back by hand
5. runs the gate on demand and two probes

Last run: refusal named the missing prerequisite; JWT fault caused 30 failed payments, rolled back in 1.57 s; manual rollback 0.74 s; gate all-pass.

To inspect the bank directly:
```bash
docker compose -f testbed/docker-compose.yml ps
docker compose -f testbed/docker-compose.yml exec toolbox sh -c "echo | openssl s_client -connect ledger:443 -CAfile /pki/trust/both.pem -cert /pki/certs/probe.rsa.crt -key /pki/certs/probe.rsa.key -trace | grep -E 'Negotiated|Peer signature'"
type testbed\runtime\state\services.json        # the bank's current crypto state
type testbed\runtime\conf\ledger.conf           # the nginx config the executor rendered
```

---

## 8. How a migration actually changes the bank

- `testbed/runtime/state/services.json` holds each service's crypto posture: `kex`, `cert`, `trust`, and JWT settings.
- A task (`pqbridge/tasks.py`) edits that state. PKI tasks also issue keys and certificates in the toolbox:
  - `pki.pq-root`: SLH-DSA-SHA2-128s root plus FN-DSA-512 leaves. Keys come from `openssl genpkey -rand <QRNG seed>`.
  - `jwt.dual-verify`: issues the FN-DSA JWT key.
- `testbed.render_conf` regenerates the nginx config for each changed service (`ssl_ecdh_curve`, certificates, trust store, outbound `Groups`). It runs `nginx -t`, then `nginx -s reload`: a graceful reload, so in-flight connections finish.
- JWT settings are read by the app on every request (no restart).
- **Rollback** writes the previous state back and reloads the same services. New PKI files stay on disk; they are additive and harmless.
- Every change is recorded in `testbed/runtime/state/history.json`. That is what *Rollback last change* pops.

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| Header shows "–" everywhere | Docker Desktop is not running, or the bank is down: Overview → Reset bank, or run `python run_all.py` |
| A button does nothing | Another operation is running (sidebar badge). Wait, or check Operator log |
| "prerequisites not applied" | Expected: click **Apply + prerequisites**, or use Force to demonstrate the refusal |
| Forced cert task says "does not exist yet" | Expected: the PQ PKI was not issued. Apply `pki.pq-root` first (or use Apply + prerequisites) |
| Fault scenario says "already safe" | The state no longer allows that failure. Reset the bank |
| Plan shows "QpiAI Opt was not used" | `QPIAI_OPT_API_KEY` missing or invalid in `.env`; restart `dev.ps1` |
| UI not updating after code edits | `dev.ps1` must be the running server (it uses polling reload because of OneDrive) |
| Port 8000 busy | Close the old server window, or `Get-NetTCPConnection -LocalPort 8000` and stop that process |

---

## 10. Honest answers for judges' questions

- **"Is this a toy?"** No. Real OpenSSL 3.5 TLS 1.3 with real HQC / FN-DSA / SLH-DSA handshakes; real nginx, mTLS and JWTs; real payment traffic; real public repos and real public TLS endpoints. It is a mini-bank, not a production bank, and benchmarks run on a laptop's Docker Desktop.
- **"What does QpiAI Opt decide?"** Which migration task goes in which change window. That is the bank's actual change calendar. The executor runs exactly those waves.
- **"Is QpiAI Opt's answer optimal?"** It is multi-start (8 seeds), and only plans passing the validator are used. On the current risks the best plan is about 6–7% above the CP-SAT optimum and better than the manual greedy order. We show the gap openly.
- **"Why HQC and not ML-KEM?"** Team choice: HQC is NIST's code-based backup KEM, with different maths from ML-KEM. Trade-offs we show: no public client or CDN supports HQC yet (survey 0/24), so internet customers fall back to X25519, and HQC is slower and larger than lattice KEMs (benchmarks).
- **"Is the QRNG truly quantum?"** On the local QpiAI simulator, no. It is pseudo-random. Seeds are always mixed with the OS CSPRNG, so they are never weaker. On a QCloud hardware device the bits are quantum.
- **"How good is the ML?"** Tested on repositories it never saw. The gain over rules alone is modest (F1 0.906 → 0.915; recall 0.86 → 0.96 in audit mode). The 571 training labels were made by the team with AI assistance and should be spot-checked.
- **"Can SLH-DSA be used for TLS?"** Not in OpenSSL 3.5: there is no TLS codepoint (our benchmark shows the error). That is why it is the offline root only.

---

## 11. Code map

| Path | Purpose |
|---|---|
| `pqbridge/api.py` | All HTTP endpoints (pipeline steps and manual controls) |
| `pqbridge/pipeline.py` | Orchestration: scan, repos, survey, assess, plan, circuits, waves, manual apply/rollback/gate/probe, report, reset |
| `pqbridge/scanner.py` | Bank-estate discovery and corpus evaluation |
| `pqbridge/detect.py` | Hybrid ML detection engine and snippet analyser |
| `pqbridge/risk.py` | Mosca risk model and editable assumptions |
| `pqbridge/qubo.py` | HUBO formulation, QpiAI Opt multi-start, validator, CP-SAT and greedy baselines |
| `pqbridge/qaoa.py`, `qrng.py`, `circuits.py` | QpiAI QCloud circuits |
| `pqbridge/tasks.py` | Migration task catalogue (16 tasks + 1 deferred) and how each changes the bank |
| `pqbridge/migrate.py` | Executor, 24-check verification gate, rollback, history, probes |
| `pqbridge/testbed.py` | Docker control, PKI issuance, nginx rendering, graceful reload |
| `pqbridge/bench.py`, `bench_tool.py` | Benchmarks |
| `pqbridge/survey.py` | Public TLS survey |
| `console/` | Multi-page UI (`index.html`, `app.js`, `sections.js`, `manual.js`, `style.css`) |
| `testbed/` | Dockerfile (OpenSSL 3.5 + liboqs + oqs-provider), compose file, service/loadgen/legacy/probe apps |
| `evidence/` | Every recorded result: inventory, plan, waves, events, traces, benchmarks, circuits, report |
| `run_all.py`, `dev.ps1`, `data/manual_smoke.py` | Full reproducible run, dev server, manual-control smoke test |
