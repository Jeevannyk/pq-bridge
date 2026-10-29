# PQ-Bridge

Verification-gated post-quantum migration for banking applications (Quant-a-Maze 3.0, PQC-01).

PQ-Bridge finds quantum-vulnerable cryptography in bank and fintech code with a hybrid detection engine
(rules + ML classifier + cryptographic verification). It plans the migration order as a HUBO solved on **QpiAI Opt**,
then moves services to post-quantum cryptography wave by wave. Each wave is promoted only after a live verification
gate passes, and is rolled back automatically if any check fails. **QpiAI QCloud** circuits supply quantum entropy
for the new keys, cross-check the schedule with QAOA, and demonstrate the threat (Shor, Grover).

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
| 1. Estate discovery | `pqbridge/scanner.py` | Scans code, configs, X.509 certs/keys (FN-DSA / SLH-DSA OIDs recognised), dependency manifests and live TLS endpoints. Every finding carries evidence. |
| 2. Hybrid detection engine | `pqbridge/detect.py` | Scans real bank/fintech repos. **Rules** (per-language), an **ML classifier** (logistic regression on char/word n-grams, path and banking-context features, trained on 571 hand-labelled lines) and **crypto verification** (algorithm resolved via OpenSSL's registry, the RFC 7518 JOSE table, JCA names and API semantics). Evaluated leave-one-repo-out. |
| 3. Real data | `data/repos/`, `pqbridge/survey.py` | 11 public repos: JPMorgan Quorum, Tessera and Fusion; AWS Payment Cryptography samples; Apache Fineract; OpenBankProject; Juspay Hyperswitch; Moov ISO 8583 and ACH; Goldman gs-quant; Hyperledger Fabric. Plus a TLS survey of 24 public bank / fintech endpoints (one ordinary handshake each). |
| 4. Risk | `pqbridge/risk.py` | Mosca's inequality, exposure and criticality give a risk score per migration task. |
| 5. Schedule | `pqbridge/qubo.py` | 16 tasks × 4 windows, as a HUBO with a native cubic blast-radius term. Solved on QpiAI Opt, validated, and compared with CP-SAT (exact) and greedy. |
| 6. QCloud circuits | `pqbridge/circuits.py`, `qaoa.py`, `qrng.py` | Built gate by gate with the QpiAI Quantum SDK, each exported as OpenQASM 2.0 with a diagram, run and measured: **QRNG** (entropy → `openssl genpkey -rand`), **QAOA** (schedule cluster), **Shor** (N=15 threat demo), **Grover** (toy-cipher key search → AES-256 policy). |
| 7. Executor + gate | `pqbridge/migrate.py`, `tasks.py` | Graceful nginx reloads. Gate checks: `openssl s_client -trace` traces (group / signature / chain); classical-client compatibility; forged / alg=none / expired JWTs, missing or rogue client certs and PQ-only downgrade all rejected; p95 budget; zero failed payments. Automatic rollback. |
| 8. Benchmarks | `pqbridge/bench.py`, `bench_tool.py` | Classical vs hybrid vs PQ-only. TLS bytes, latency, handshakes/s and bandwidth projection; signature and KEM ops/s and sizes; JWT size and storage. |
| 9. Console | `pqbridge/api.py`, `console/` | FastAPI and a web console covering all of the above. |

**Presenting? Read [DEMO_GUIDE.md](DEMO_GUIDE.md)**: every console page, the manual migrate / test / rollback controls, a 12-minute live demo script and answers to likely judge questions.

## Run

Prerequisites: Docker Desktop running, Python 3.11+, git.

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt
# fill in QPIAI_OPT_API_KEY and QCLOUD_API_KEY in .env (template already present)
python run_all.py          # full reproducible run; all evidence -> evidence/
python -m pqbridge.api     # console at http://127.0.0.1:8000
python -m pqbridge.circuits --devices   # list QCloud devices once QCLOUD_API_KEY is set
```

The first `docker compose build` compiles liboqs and oqs-provider (about 5 min). Real repos are cloned into `data/repos/` (see `data/REPOS.md`).

## Honest notes

- **QpiAI Opt:** without `QPIAI_OPT_API_KEY` the schedule falls back to classical simulated annealing on the same HUBO, labelled as such. The Opt local solver needs a free key.
- **QCloud randomness:** `QpiAI-QSV-Local` is a simulator, so its randomness is pseudo-random. Seeds are mixed with the OS CSPRNG (HKDF), then into OpenSSL's DRBG via `-rand`. liboqs is built with `OQS_USE_OPENSSL=ON`, so FN-DSA keygen draws from that DRBG.
- **HQC on the internet:** no public client or CDN supports HQC today; the survey found 0 of 24. Internet customers fall back to X25519, so HQC protects bank-controlled links (service-to-service mTLS).
- **SLH-DSA cannot be a TLS leaf:** OpenSSL 3.5 has no TLS 1.3 codepoint for it (verified in the benchmark). It is used for the offline root CA only.
- **HQC sizes:** oqs-provider has no OID for HQC keys, so HQC public-key and ciphertext sizes come from the liboqs 0.16.0 constants. TLS bytes on the wire are measured.
- **ML labels:** the 571 labelled lines were labelled by the team with AI assistance against a written definition, and should be spot-checked before external claims. The engine's gain over rules is modest (F1 0.906 → 0.915 balanced; recall 0.86 → 0.96 in audit mode).
- **Benchmarks:** measured on Docker Desktop on a laptop CPU, not on bank hardware.
