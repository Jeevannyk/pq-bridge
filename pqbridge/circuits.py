"""QpiAI QCloud circuit designs used by PQ-Bridge (both fit the 6-qubit free tier).

  qrng    6-qubit H+measure entropy source -> seeds for FN-DSA / SLH-DSA keys
  qaoa    QAOA ansatz for the migration-schedule cluster sub-QUBO (settlement rollout)

Each design is built gate-by-gate with the QpiAI Quantum SDK, exported as OpenQASM 2.0, drawn by the
SDK's own renderer, and run once on CIRCUIT_DEVICE (QpiAI QCloud). Metrics (qubits, depth, gate counts)
and results are recorded in evidence/circuits/.
    python -m pqbridge.circuits            design + run both
    python -m pqbridge.circuits --devices  list QCloud compute resources (needs QCLOUD_API_KEY)
"""
import json
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
           "device": config.CIRCUIT_DEVICE, **(run or {}), **(extra or {})}
    (OUT / f"{name}.json").write_text(json.dumps(rec, indent=1))
    return rec


def _run(circuit, shots, name):
    _login()
    t0 = time.time()
    device, cloud_error = config.CIRCUIT_DEVICE, None
    try:
        r = circuit.run(shots=shots, experiment_name=config.QCLOUD_EXPERIMENT, device_name=device)
    except Exception as e:                      # e.g. account without an active QCloud subscription
        cloud_error = next((l.strip() for l in str(e).splitlines() if "error" in l.lower() and "Server response" in l), str(e).splitlines()[0])[:200]
        device = "QpiAI-QSV-Local"
        r = circuit.run(shots=shots, experiment_name=config.QCLOUD_EXPERIMENT, device_name=device)
    counts = r.get_counts()
    top = dict(sorted(counts.items(), key=lambda kv: -kv[1])[:8])
    return {"device": device, "cloud_error": cloud_error, "shots": shots, "job_id": getattr(r, "job_id", None), "run_s": round(time.time() - t0, 3),
            "distinct_outcomes": len(counts), "top_counts": top}, counts


# ------------------------------------------------------------------ designs
def qrng(shots=256):
    from qpiai_quantum import Circuit
    from . import qrng as Q
    n = Q.N_QUBITS
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


def run_all(log=print):
    out = {}
    for fn in (qrng, qaoa):
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
