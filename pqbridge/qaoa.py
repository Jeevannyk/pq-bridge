"""QAOA cross-check of the schedule on QpiAI QCloud.

The full schedule (82 binaries) is solved by QpiAI Opt. Here one dependency
cluster (the settlement rollout: KMS key, clearing-house trust, SLH-DSA signer; 6 qubits, the QCloud
free-tier cap) is re-optimised with every
other task fixed to the Opt plan. The cluster sub-QUBO is mapped to an Ising
Hamiltonian and solved with a QAOA circuit built gate-by-gate in the QpiAI
Quantum SDK. The result is compared with the brute-force optimum.
"""
import itertools
import json
import time

import numpy as np
from scipy.optimize import minimize

from . import config
from .qubo import CAP, PEN, WINDOWS, blackout_cost, domains
from .tasks import TASK_BY_ID, TASKS

MAX_QUBITS = 6
CLUSTER = ["kms.key-settlement", "partner.clearing", "settle.sign-slhdsa"]   # 3 tasks x 2 windows = 6 qubits


def sub_qubo(plan, risks, cluster=CLUSTER):
    fixed = {t: w for t, w in plan.items() if t not in cluster}
    load = [sum(TASK_BY_ID[t]["effort"] for t, w in fixed.items() if w == k) for k in range(WINDOWS)]
    # allowed windows per free task: respect fixed prerequisites and fixed dependents
    allowed, dom = {}, domains()                     # domains(): exact pruning by dependency chains
    for t in cluster:
        lo = max([fixed[d] + 1 for d in TASK_BY_ID[t]["deps"] if d in fixed], default=0)
        hi = min([fixed[s["id"]] - 1 for s in TASKS if t in s["deps"] and s["id"] in fixed], default=WINDOWS - 1)
        allowed[t] = [w for w in range(lo, hi + 1) if w in dom[t] and load[w] + TASK_BY_ID[t]["effort"] <= CAP]
    var = [(t, w) for t in cluster for w in allowed[t]]
    idx = {v: i for i, v in enumerate(var)}
    lin = np.zeros(len(var))
    quad = {}
    const = 0.0

    def q(a, b, c):
        key = (min(a, b), max(a, b))
        quad[key] = quad.get(key, 0.0) + c
    A, B, C = PEN["A"], PEN["B"], PEN["C"]
    for t in cluster:                                 # one-hot
        vs = [idx[(t, w)] for w in allowed[t]]
        const += A
        for i in vs:
            lin[i] -= A
        for i, j in itertools.combinations(vs, 2):
            q(i, j, 2 * A)
    for s in cluster:                                 # precedence inside the cluster
        for d in TASK_BY_ID[s]["deps"]:
            if d in cluster:
                for ws in allowed[s]:
                    for wd in allowed[d]:
                        if wd >= ws:
                            q(idx[(s, ws)], idx[(d, wd)], B)
    for w in range(WINDOWS):                          # pairwise capacity
        free = [t for t in cluster if w in allowed[t]]
        for a, b in itertools.combinations(free, 2):
            if load[w] + TASK_BY_ID[a]["effort"] + TASK_BY_ID[b]["effort"] > CAP:
                q(idx[(a, w)], idx[(b, w)], C)
    for (t, w), i in idx.items():                     # objective
        lin[i] += risks[t] * w + blackout_cost(t, w)
    return var, lin, quad, const, allowed, load


def qubo_energy(bits, lin, quad, const):
    e = const + float(np.dot(lin, bits))
    for (i, j), c in quad.items():
        e += c * bits[i] * bits[j]
    return e


def brute_force(n, lin, quad, const):
    best, best_e, energies = None, float("inf"), []
    for k in range(2 ** n):
        bits = [(k >> i) & 1 for i in range(n)]
        e = qubo_energy(bits, lin, quad, const)
        energies.append(e)
        if e < best_e:
            best, best_e = bits, e
    return best, best_e, energies


def to_ising(n, lin, quad):
    """x = (1 - z) / 2  ->  H = sum h_i z_i + sum J_ij z_i z_j (+ const)."""
    h = -np.asarray(lin, dtype=float) / 2
    J = {}
    for (i, j), b in quad.items():
        h[i] -= b / 4
        h[j] -= b / 4
        J[(i, j)] = b / 4
    scale = max([abs(v) for v in h] + [abs(v) for v in J.values()] + [1e-9])
    return h / scale, {k: v / scale for k, v in J.items()}


def qaoa_circuit(n, h, J, gammas, betas):
    from qpiai_quantum import Circuit
    c = Circuit(n, n)
    for i in range(n):
        c.h(i)
    for g, b in zip(gammas, betas):
        for (i, j), v in J.items():
            c.rzz(i, j, 2 * g * v)
        for i in range(n):
            if h[i]:
                c.rz(i, 2 * g * h[i])
        for i in range(n):
            c.rx(i, 2 * b)
    c.measure(list(range(n)), list(range(n)))
    return c


def run(plan, risks, reps=2, shots=2048, maxiter=50, restarts=4, seed=7, log=print):
    var, lin, quad, const, allowed, load = sub_qubo(plan, risks)
    n = len(var)
    if n > MAX_QUBITS:
        raise RuntimeError(f"QAOA cluster needs {n} qubits; the QCloud free tier allows {MAX_QUBITS}")
    opt_bits, opt_e, all_e = brute_force(n, lin, quad, const)
    h, J = to_ising(n, lin, quad)
    rng = np.random.default_rng(seed)
    history = []
    runs = {"count": 0}

    def sample(params):
        c = qaoa_circuit(n, h, J, params[:reps], params[reps:])
        res = c.run(shots=shots, experiment_name="pqbridge-qaoa", device_name=config.QCLOUD_DEVICE)
        runs["count"] += 1
        return res.get_counts()

    def cvar(params, alpha=0.25):
        counts = sample(params)
        es = sorted((qubo_energy([int(s[-1 - i]) for i in range(n)], lin, quad, const), k) for s, k in counts.items())
        take, acc, tot = alpha * shots, 0.0, 0.0
        for e, k in es:
            m = min(k, take - tot)
            acc += e * m
            tot += m
            if tot >= take:
                break
        val = acc / tot
        history.append(round(val, 3))
        return val

    t0 = time.time()
    # Multi-start: QAOA landscapes are rugged, so take the best of several COBYLA runs.
    res = None
    for _ in range(restarts):
        x0 = np.concatenate([rng.uniform(0.05, 1.0, reps), rng.uniform(0.05, 0.8, reps)])
        r = minimize(cvar, x0, method="COBYLA", options={"maxiter": maxiter, "rhobeg": 0.3})
        if res is None or r.fun < res.fun:
            res = r
    counts = sample(res.x)
    decoded = []
    for s, k in counts.items():
        bits = [int(s[-1 - i]) for i in range(n)]
        decoded.append((qubo_energy(bits, lin, quad, const), k, bits))
    decoded.sort(key=lambda d: d[0])
    best_e, _, best_bits = decoded[0]
    p_opt = sum(k for e, k, _ in decoded if abs(e - opt_e) < 1e-6) / shots
    worst = max(all_e)
    mean_e = sum(e * k for e, k, _ in decoded) / shots
    random_p_opt = sum(1 for e in all_e if abs(e - opt_e) < 1e-6) / len(all_e)

    def assignment(bits):
        return {t: w for (t, w), b in zip(var, bits) if b}
    opt_plan_cluster = {t: plan[t] for t in CLUSTER}
    plan_bits = [1 if plan[t] == w else 0 for (t, w) in var]
    plan_e = qubo_energy(plan_bits, lin, quad, const)
    out = {
        "cluster": CLUSTER, "qubits": n, "reps": reps, "shots": shots, "device": config.QCLOUD_DEVICE,
        "circuit_runs": runs["count"], "restarts": restarts, "wall_s": round(time.time() - t0, 2),
        "allowed_windows": allowed, "fixed_window_load": load,
        "terms": {"linear": int(np.count_nonzero(lin)), "quadratic": len(quad)},
        "brute_force": {"energy": round(opt_e, 3), "assignment": assignment(opt_bits)},
        "qaoa_best": {"energy": round(best_e, 3), "assignment": assignment(best_bits)},
        "opt_plan_cluster": {"energy": round(plan_e, 3), "assignment": opt_plan_cluster},
        "qaoa_improves_plan": best_e < plan_e - 1e-6,
        "found_optimum": abs(best_e - opt_e) < 1e-6,
        "p_optimal": round(p_opt, 4), "p_optimal_uniform_random": round(random_p_opt, 4),
        "approx_ratio_mean": round((worst - mean_e) / (worst - opt_e), 4) if worst != opt_e else 1.0,
        "cvar_history": history,
        "params": [round(float(v), 4) for v in res.x],
    }
    config.EVIDENCE.mkdir(parents=True, exist_ok=True)
    (config.EVIDENCE / "qaoa.json").write_text(json.dumps(out, indent=1))
    return out


def run_qpiai_opt_qaoa(plan, risks, reps=2, shots=1024):
    """Same sub-QUBO through qpiai_opt's built-in QAOA (needs QCLOUD_API_KEY)."""
    from qpiai_opt.opt_modeller import Binary, Model
    from qpiai_opt.opt_solvers import solve
    from qpiai_opt.quantum import QAOA, QpiAIQuantumAuth, QuantumRun
    if not config.QCLOUD_API_KEY:
        raise RuntimeError("QCLOUD_API_KEY missing")
    QpiAIQuantumAuth.login(api_key=config.QCLOUD_API_KEY)
    var, lin, quad, const, _, _ = sub_qubo(plan, risks)
    b = [Binary(f"x{i}") for i in range(len(var))]
    expr = sum(float(lin[i]) * b[i] for i in range(len(var)))
    for (i, j), c in quad.items():
        expr = expr + c * b[i] * b[j]
    m = Model("cluster")
    m.minimize(expr + const)
    t0 = time.time()
    r = solve(m, algorithm=QAOA(reps=reps, max_iterations=60), execution=QuantumRun(shots=shots, seed=7), mode="local")
    d = r.model_dump(mode="json") if hasattr(r, "model_dump") else {}
    return {"wall_s": round(time.time() - t0, 2), "result": d}
