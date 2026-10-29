"""QpiAI QCloud circuit designs used by PQ-Bridge.

  qrng    16-qubit H+measure entropy source -> seeds for FN-DSA / SLH-DSA keys (decision input)
  qaoa    QAOA ansatz for the migration-schedule cluster sub-QUBO (decision input)
  shor    Shor period finding for N=15 (threat evidence: why RSA/ECC must go; context only)
  grover  Grover key search on a 4-bit toy cipher (why AES-256 / SHA-384 in the migration policy; context only)

Each design is built gate-by-gate with the QpiAI Quantum SDK and exported as OpenQASM 2.0 with a
rendered diagram. It is then run on QCLOUD_DEVICE and its metrics (qubits, depth, gate counts) and
results are recorded in evidence/circuits/.
    python -m pqbridge.circuits            design + run all four
    python -m pqbridge.circuits --devices  list QCloud compute resources (needs QCLOUD_API_KEY)
"""
import json
import math
import os
import re
import sys
import time
from collections import Counter

from . import config

OUT = config.EVIDENCE / "circuits"


def _login():
    if config.QCLOUD_API_KEY:
        from qpiai_quantum import QpiAIQuantumAuth
        QpiAIQuantumAuth.login(api_key=config.QCLOUD_API_KEY)


def _gate_counts(qasm):
    ops = re.findall(r"^\s*([a-z][a-z0-9_]*)\b", qasm, re.M)
    return dict(Counter(o for o in ops if o not in {"openqasm", "include", "qreg", "creg", "barrier"}).most_common())


def _render(circuit, name):
    """Save the SDK's own matplotlib rendering of the circuit as PNG."""
    os.environ.setdefault("MPLBACKEND", "Agg")
    import io

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from PIL import Image
    # The SDK draws long circuits in chunks and calls plt.show(); plt.close() per chunk.
    # Capture each chunk's figure as PNG, then stack the chunks vertically into one diagram.
    chunks = []
    real_show, real_close = plt.show, plt.close

    def grab(*a, **k):
        buf = io.BytesIO()
        plt.gcf().savefig(buf, format="png", dpi=110, bbox_inches="tight")
        chunks.append(Image.open(io.BytesIO(buf.getvalue())).convert("RGB"))
    try:
        plt.show = grab
        circuit.show(theme="light", dpi=110)
    except Exception as e:
        return f"render failed: {e}"
    finally:
        plt.show = real_show
        real_close("all")
    if not chunks:
        return "render failed: no figure produced"
    w = max(c.width for c in chunks)
    out = Image.new("RGB", (w, sum(c.height for c in chunks)), "white")
    y = 0
    for c in chunks:
        out.paste(c, (0, y))
        y += c.height
    out.save(OUT / f"{name}.png")
    return f"{name}.png"


def _record(name, circuit, purpose, role, run=None, extra=None):
    OUT.mkdir(parents=True, exist_ok=True)
    qasm = circuit.to_qasm()
    (OUT / f"{name}.qasm").write_text(qasm)
    rec = {"name": name, "purpose": purpose, "role": role, "qubits": circuit.num_qubits,
           "clbits": circuit.num_clbits, "depth": circuit.depth(), "size": circuit.size(),
           "gates": _gate_counts(qasm), "qasm": f"{name}.qasm", "diagram": _render(circuit, name),
           "device": config.QCLOUD_DEVICE, **(run or {}), **(extra or {})}
    (OUT / f"{name}.json").write_text(json.dumps(rec, indent=1))
    return rec


def _run(circuit, shots, name):
    _login()
    t0 = time.time()
    r = circuit.run(shots=shots, experiment_name=f"pqbridge-{name}", device_name=config.QCLOUD_DEVICE)
    counts = r.get_counts()
    top = dict(sorted(counts.items(), key=lambda kv: -kv[1])[:8])
    return {"shots": shots, "job_id": getattr(r, "job_id", None), "run_s": round(time.time() - t0, 3),
            "distinct_outcomes": len(counts), "top_counts": top}, counts


# ------------------------------------------------------------------ designs
def qrng(n=16, shots=256):
    from qpiai_quantum import Circuit
    from . import qrng as Q
    c = Circuit(n, n)
    for q in range(n):
        c.h(q)
    c.measure(list(range(n)), list(range(n)))
    run, counts = _run(c, shots, "qrng")
    bits = "".join(o * k for o, k in counts.items())
    return _record("qrng", c, "Entropy for FN-DSA / SLH-DSA key generation (mixed with OS CSPRNG via OpenSSL -rand)",
                   "decision input", run, {"health": Q.health_tests(bits, counts)})


def qaoa():
    """Re-build the QAOA ansatz with the optimised angles from the last schedule run."""
    from . import qaoa as QA
    plan = json.loads((config.EVIDENCE / "plan.json").read_text())
    risks = json.loads((config.EVIDENCE / "risk.json").read_text())["tasks"]
    var, lin, quad, const, _, _ = QA.sub_qubo(plan["plan"], risks)
    h, J = QA.to_ising(len(var), lin, quad)
    q = plan.get("qaoa", {})
    params = q.get("params") or [0.4, 0.4, 0.3, 0.3]
    reps = q.get("reps", len(params) // 2)
    c = QA.qaoa_circuit(len(var), h, J, params[:reps], params[reps:])
    run, counts = _run(c, 2048, "qaoa")
    return _record("qaoa", c, f"QAOA (p={reps}) for schedule cluster {QA.CLUSTER}: Ising cost RZZ/RZ layers + RX mixer",
                   "decision input", run, {"variables": [f"{t}@w{w}" for t, w in var], "params": params,
                                           "brute_force_energy": q.get("brute_force", {}).get("energy"),
                                           "qaoa_best_energy": q.get("qaoa_best", {}).get("energy")})


def shor(N=15, a=7, precision=4):
    from qpiai_quantum import ShorsAlgorithm
    s = ShorsAlgorithm(N)
    c = s.build_circuit(a, precision)
    run, counts = _run(c, 1024, "shor")
    t0 = time.time()
    factors = s.factor(max_attempts=10)
    phases = []
    for bitstr, k in sorted(counts.items(), key=lambda kv: -kv[1])[:6]:
        meas = int(bitstr[-precision:], 2) if len(bitstr) >= precision else int(bitstr, 2)
        phases.append({"outcome": bitstr, "count": k, "phase": round(meas / 2 ** precision, 4)})
    return _record("shor", c, f"Shor period finding: factor N={N} with a={a} ({precision} counting qubits)",
                   "threat evidence (context only)", run,
                   {"N": N, "a": a, "factors_found": list(factors) if factors else None,
                    "factor_s": round(time.time() - t0, 3), "top_phases": phases,
                    "scale_note": "RSA-2048 is estimated to need under one million noisy qubits for under a week "
                                  "(Gidney, 2025). A CRQC breaks every RSA/ECC key in this bank, which is why the "
                                  "inventory treats them as quantum-vulnerable."})


TOY_SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]   # PRESENT S-box


def toy_encrypt(p, k):
    return TOY_SBOX[p ^ k] ^ k


def grover(n=4):
    from qpiai_quantum import GroverSearch
    secret = 0b1011
    # choose a known plaintext whose ciphertext pins down a unique key
    p = next(x for x in range(2 ** n)
             if sum(toy_encrypt(x, k) == toy_encrypt(x, secret) for k in range(2 ** n)) == 1)
    ct = toy_encrypt(p, secret)
    keys = [k for k in range(2 ** n) if toy_encrypt(p, k) == ct]
    target = format(keys[0], f"0{n}b")
    g = GroverSearch(n, target)
    c = g.build_circuit()
    run, counts = _run(c, 1024, "grover")
    k_opt = math.floor(math.pi / 4 * math.sqrt(2 ** n))
    # GroverSearch takes the target with qubit 0 leftmost; counts are little-endian (qubit 0 rightmost)
    hit = counts.get(target[::-1], 0) / 1024
    return _record("grover", c, "Grover key search on a 4-bit toy cipher (PRESENT S-box, known plaintext/ciphertext)",
                   "policy evidence (context only)", run,
                   {"plaintext": p, "ciphertext": ct, "consistent_keys": keys, "target": target,
                    "optimal_iterations": k_opt, "measured_success": round(hit, 4),
                    "predicted_success": round(g.get_success_probability(), 4),
                    "classical_expected_tries": 2 ** n / 2,
                    "scale_note": "Grover needs ~pi/4*2^(n/2) sequential AES evaluations: ~2^64 for AES-128 and "
                                  "~2^128 for AES-256. A full AES-128 oracle needs thousands of logical qubits "
                                  "(Grassl et al., 2016). The policy therefore keeps symmetric crypto but requires "
                                  "AES-256-GCM and SHA-384+. The toy oracle here marks the known key "
                                  "(textbook construction)."})


def run_all(log=print):
    out = {}
    for fn in (qrng, qaoa, shor, grover):
        try:
            out[fn.__name__] = fn()
            r = out[fn.__name__]
            log(f"circuit {fn.__name__}: {r['qubits']} qubits, depth {r['depth']}, {r['size']} gates, on {r['device']}")
        except Exception as e:
            out[fn.__name__] = {"name": fn.__name__, "error": str(e)[:300]}
            log(f"circuit {fn.__name__} failed: {e}")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "index.json").write_text(json.dumps(out, indent=1))
    return out


if __name__ == "__main__":
    if "--devices" in sys.argv:
        from qpiai_quantum import QpiAIQuantumAuth
        _login()
        print(QpiAIQuantumAuth.list_compute_resources())
    else:
        print(json.dumps(run_all(), indent=1, default=str)[:4000])
