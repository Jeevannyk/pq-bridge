# PQ-Bridge

Verification-gated post-quantum migration for banking applications (Quant-a-Maze 3.0, PQC-01).

**The product is one pipeline on one bank (the mini-bank):**
`find its vulnerabilities (hybrid engine) → score criticality → prioritise with QpiAI Opt → migrate → gate / rollback.`

- **Detection:** a hybrid engine (rules + ML classifier + cryptographic verification) reads the mini-bank's code and configs; certificates, dependency files and live TLS handshakes are parsed exactly. The classifier is **trained and validated on 11 real bank / fintech repositories** (read-only; they are training data, not an estate we migrate).
- **Prioritisation:** the findings set each task's risk; a HUBO over tasks × change windows is solved on **QpiAI Opt**.
- **Migration:** the mini-bank is moved to HQC key exchange, FN-DSA certificates and JWTs, and an SLH-DSA root, one change at a time. Each change is verified by a live gate and rolled back automatically if any check fails.
- **QpiAI QCloud** circuits supply quantum entropy for the new keys, cross-check the schedule with QAOA, and demonstrate the threat (Shor, Grover).

## Post-quantum suite (team decision)

| Role | Algorithm | Where |
|---|---|---|
| TLS key exchange | **HQC-1**: hybrid `x25519_hqc1`, PQ-only `hqc1` | liboqs 0.16.0 + oqs-provider 0.12.0 |
| Leaf certificates (TLS, mTLS) and JWTs | **FN-DSA-512** (Falcon) | oqs-provider |
| Root CA | **SLH-DSA-SHA2-128s** (FIPS 205) | native OpenSSL 3.5 |

ML-KEM and ML-DSA are deliberately not used. The public TLS survey offers ML-KEM only to *measure* industry adoption.

## Modules

| Module | File | What it does |
|---|---|---|
| Mini-bank testbed | `testbed/` | Docker, Alpine 3.22 / OpenSSL 3.5.9 + oqs-provider. Services: gateway, card-auth (JWT issuer), payment-switch (JWT verifier), ledger (SQLite), all connected over mTLS. A load generator sends continuous payments; a legacy client is classical-only and trusts the RSA root only. |
| 1. Find vulnerabilities in the mini-bank | `pqbridge/scanner.py` | `scan_estate()` runs the **same hybrid engine** (`detect.py`) over the mini-bank's code and nginx configs. X.509 certs/keys (FN-DSA / SLH-DSA OIDs recognised), dependency manifests and live TLS endpoints are exact parsers feeding the same finding format. Every finding carries evidence. |
| 2. Hybrid detection engine | `pqbridge/detect.py` | The engine used in step 1. Trained and validated on real bank/fintech repos. **Rules** (per-language), an **ML classifier** (logistic regression on char/word n-grams, path and banking-context features, trained on 571 hand-labelled lines) and **crypto verification** (algorithm resolved via OpenSSL's registry, the RFC 7518 JOSE table, JCA names and API semantics). Evaluated leave-one-repo-out. |
| 3. Real data (training + context) | `data/repos/`, `pqbridge/survey.py` | 11 public repos: JPMorgan Quorum, Tessera and Fusion; AWS Payment Cryptography samples; Apache Fineract; OpenBankProject; Juspay Hyperswitch; Moov ISO 8583 and ACH; Goldman gs-quant; Hyperledger Fabric. Plus a TLS survey of 24 public bank / fintech endpoints (one ordinary handshake each). |
| 4. Risk | `pqbridge/risk.py` | Mosca's inequality, exposure and criticality give a risk score per migration task. |
| 5. Schedule | `pqbridge/qubo.py` | 16 tasks × 4 windows, as a HUBO with a native cubic blast-radius term. Solved on QpiAI Opt, validated, and compared with CP-SAT (exact) and greedy. |
| 6. QCloud circuits | `pqbridge/circuits.py`, `qaoa.py`, `qrng.py` | Built gate by gate with the QpiAI Quantum SDK, each exported as OpenQASM 2.0 with a diagram, run and measured: **QRNG** (entropy → `openssl genpkey -rand`), **QAOA** (schedule cluster), **Shor** (N=15 threat demo), **Grover** (toy-cipher key search → AES-256 policy). |
| 7. Executor + gate | `pqbridge/migrate.py`, `tasks.py` | Graceful nginx reloads. Gate checks: `openssl s_client -trace` traces (group / signature / chain); classical-client compatibility; forged / alg=none / expired JWTs, missing or rogue client certs and PQ-only downgrade all rejected; p95 budget; zero failed payments. Automatic rollback. |
| 8. Benchmarks | `pqbridge/bench.py`, `bench_tool.py` | Classical vs hybrid vs PQ-only. TLS bytes, latency, handshakes/s and bandwidth projection; signature and KEM ops/s and sizes; JWT size and storage. |
| 9. Console | `pqbridge/api.py`, `console/` | FastAPI and a web console covering all of the above. |

**Presenting? Read [DEMO_GUIDE.md](DEMO_GUIDE.md)**: every console page, the manual migrate / test / rollback controls, a 12-minute live demo script and answers to likely judge questions.

## Run on a fresh machine

**You need:** Docker Desktop (running, WSL2 backend on Windows), Python 3.11 to 3.13, git, internet, and free ports 8000 and 8443.
About 6 GB of disk (Docker image about 1 GB, real repos about 450 MB). Clone it **outside OneDrive or other synced folders**:
they slow the repo analysis from about 2 minutes to about 9.

```powershell
git clone https://github.com/Jeevannyk/pq-bridge.git ; cd pq-bridge
python -m venv .venv
.venv\Scripts\pip install uv                       # optional: much faster than plain pip for the QpiAI packages
.venv\Scripts\uv pip install -r requirements.txt   # or: .venv\Scripts\pip install -r requirements.txt
copy .env.example .env                              # then edit .env: set QPIAI_OPT_API_KEY and QCLOUD_API_KEY
.venv\Scripts\python run_all.py                    # the whole pipeline, 15 to 25 minutes the first time
.\dev.ps1                                           # console at http://127.0.0.1:8000
```

(Linux / macOS: use `.venv/bin/python` and `.venv/bin/uvicorn pqbridge.api:app --reload --reload-dir pqbridge` instead of `dev.ps1`.)

Free keys: https://opt.qpiai.tech and https://qcloud.qpiai.tech. Without the Opt key the plan falls back to a classical annealer, clearly labelled.

**What `run_all.py` does, in order** (everything is created locally; nothing needs to be copied from another machine):

| Step | Creates | First-run time |
|---|---|---|
| Fetch real repos | `data/repos/`: 11 public repos at the commits pinned in `data/repos.json` | 2 to 5 min |
| Reset + build bank | Docker image (compiles liboqs and oqs-provider), `testbed/runtime/`: RSA root CA, RSA certs and RS256 JWT key, nginx configs, state | 5 to 10 min |
| Scan the bank estate | `evidence/inventory.json`, `detection_eval.json` | seconds |
| ML detection on real repos | `evidence/ml_eval.json`, `repo_findings.json`, retrains `data/model.joblib` | 2 to 3 min |
| Public TLS survey | `evidence/tls_survey.json` (needs internet) | about 1 min |
| Risk, plan | `evidence/risk.json`, `plan.json` (QpiAI Opt, needs the key and internet) | about 1 min |
| QCloud circuits | `evidence/circuits/` (diagrams, `.qasm`), `qrng_runs.jsonl` | seconds |
| 4 migration waves + fault drill | SLH-DSA root and FN-DSA keys/certs in `testbed/runtime/pki/`, `evidence/waves.jsonl`, `events.jsonl`, `traces/` | about 2 min |
| Benchmarks | `evidence/benchmarks.json` | about 3 min |
| Report | `evidence/report.json` | seconds |

Then open the console and click **Overview, Reset bank to classical** before a demo; that returns the bank to the all-classical starting point.

A bare `docker compose up` does not work: the keys and configs are generated by `pqbridge/testbed.py` (`run_all.py`, or the console's Reset button), not by Docker.

**What reproduces exactly, and what will differ:**

| Reproduces | Differs by machine or time |
|---|---|
| Bank scan findings, scanner precision/recall, ML engine accuracy (same labels and commits), findings per repo (same pinned commits), CP-SAT and greedy plan scores, the HUBO size, which gate checks pass | Every key and certificate (random by design); the public TLS survey (the sites change); all timings, handshakes per second and benchmark numbers (your CPU); QAOA success probabilities (sampled); QpiAI Opt's best-of-8 plan if the SDK version differs |

Console pages that need `data/repos/` or Docker show a clear error if those are missing. `python -m pqbridge.fetch_repos` fetches the repos on its own; `python -m pqbridge.circuits --devices` lists QCloud devices once the QCloud key is set.

## Honest notes

- **QpiAI Opt:** without `QPIAI_OPT_API_KEY` the schedule falls back to classical simulated annealing on the same HUBO, labelled as such. The Opt local solver needs a free key.
- **QCloud randomness:** `QpiAI-QSV-Local` is a simulator, so its randomness is pseudo-random. Seeds are mixed with the OS CSPRNG (HKDF), then into OpenSSL's DRBG via `-rand`. liboqs is built with `OQS_USE_OPENSSL=ON`, so FN-DSA keygen draws from that DRBG.
- **HQC on the internet:** no public client or CDN supports HQC today; the survey found 0 of 24. Internet customers fall back to X25519, so HQC protects bank-controlled links (service-to-service mTLS).
- **SLH-DSA cannot be a TLS leaf:** OpenSSL 3.5 has no TLS 1.3 codepoint for it (verified in the benchmark). It is used for the offline root CA only.
- **HQC sizes:** oqs-provider has no OID for HQC keys, so HQC public-key and ciphertext sizes come from the liboqs 0.16.0 constants. TLS bytes on the wire are measured.
- **ML labels:** the 571 labelled lines were labelled by the team with AI assistance against a written definition, and should be spot-checked before external claims. The engine's gain over rules is modest (F1 0.906 → 0.915 balanced; recall 0.86 → 0.96 in audit mode).
- **Benchmarks:** measured on Docker Desktop on a laptop CPU, not on bank hardware.
