"""Migration schedule as a HUBO, solved on QpiAI Opt.

Decision: x|t|w = 1  <=>  migration task t runs in change window w.

H =  A * sum_t (1 - sum_w x[t,w])^2                          each task in exactly one window
  +  B * sum_(d->s) sum_w sum_(w' >= w) x[s,w] x[d,w']        prerequisite d strictly before s
  +  K * sum_w sum_(a<b) e_a e_b x[a,w] x[b,w]                crowding: spread engineer effort across windows
  +  E * sum_(a,b,c) sum_w x[a,w] x[b,w] x[c,w]               native cubic: never change all 3 payment-path hops at once
  +  sum_t sum_w (r_t * w + blackout_(t,w)) x[t,w]             risk-weighted delay + settlement-freeze cost

The cubic term is passed to QpiAI Opt as-is (native HUBO, no quadratisation). The hard per-window
capacity (effort <= CAP) is enforced by the validator and by the exact CP-SAT baseline. An earlier
slack-variable encoding of capacity made QpiAI Opt's local annealer return infeasible plans in every
run (2-5 violations); the crowding term keeps the landscape smooth and leaves capacity to the validator.
QpiAI Opt is run multi-start (several seeds) and the best feasible plan is kept.
"""
import itertools
import json
import math
import random
import time
from collections import defaultdict

from . import config
from .tasks import BLACKOUT, BLAST_TRIPLES, TASK_BY_ID, TASKS

WINDOWS = 4
CAP = 5
SLACK = [1, 2, 2]
PEN = {"A": 80.0, "B": 80.0, "C": 40.0, "E": 80.0, "K": 4.0}   # C: pairwise capacity penalty in the QAOA sub-QUBO
QPIAI_SEEDS = 8
QPIAI_SAMPLING = {"num_reads": 8, "num_sweeps": 600}   # within QpiAI's local annealing-work limit
BLACKOUT_COST = 25.0


def xv(t, w):
    return f"x|{t}|{w}"


def sv(w, k):
    return f"s|{w}|{k}"


def blackout_cost(task_id, w):
    t = TASK_BY_ID[task_id]
    return BLACKOUT_COST if (w == BLACKOUT["window"] and t["service"] in BLACKOUT["services"]) else 0.0


def build(risks, pen=None):
    pen = {**PEN, **(pen or {})}
    P = defaultdict(float)

    def add(vars_, c):
        P[tuple(sorted(set(vars_)))] += c

    ids = [t["id"] for t in TASKS]
    for t in ids:                                       # one-hot
        xs = [xv(t, w) for w in range(WINDOWS)]
        add((), pen["A"])
        for v in xs:
            add((v,), -pen["A"])
        for a, b in itertools.combinations(xs, 2):
            add((a, b), 2 * pen["A"])
    for s in ids:                                       # precedence
        for d in TASK_BY_ID[s]["deps"]:
            for w in range(WINDOWS):
                for w2 in range(w, WINDOWS):
                    add((xv(s, w), xv(d, w2)), pen["B"])
    for w in range(WINDOWS):                            # crowding (capacity enforced by the validator)
        for a, b in itertools.combinations(ids, 2):
            add((xv(a, w), xv(b, w)), pen["K"] * TASK_BY_ID[a]["effort"] * TASK_BY_ID[b]["effort"])
    for trip in BLAST_TRIPLES:                          # cubic blast-radius
        for w in range(WINDOWS):
            add(tuple(xv(t, w) for t in trip), pen["E"])
    for t in ids:                                       # objective
        for w in range(WINDOWS):
            c = risks[t] * w + blackout_cost(t, w)
            if c:
                add((xv(t, w),), c)
    P = {k: v for k, v in P.items() if v != 0.0}
    names = sorted({v for k in P for v in k})
    return P, names


def energy(P, assign):
    return sum(c * math.prod(assign.get(v, 0) for v in k) for k, c in P.items())


def stats(P, names):
    deg = defaultdict(int)
    for k in P:
        deg[len(k)] += 1
    return {"variables": len(names), "terms": len(P), "terms_by_degree": dict(sorted(deg.items()))}


# --------------------------------------------------------------- decode/validate
def decode(assign):
    plan = {}
    for t in TASKS:
        ws = [w for w in range(WINDOWS) if assign.get(xv(t["id"], w), 0)]
        plan[t["id"]] = ws[0] if len(ws) == 1 else (ws if ws else None)
    return plan


def validate(plan):
    v = []
    for tid, w in plan.items():
        if not isinstance(w, int):
            v.append(f"{tid}: assigned to {w} (must be exactly one window)")
    ok = {t: w for t, w in plan.items() if isinstance(w, int)}
    for s, w in ok.items():
        for d in TASK_BY_ID[s]["deps"]:
            if d in ok and ok[d] >= w:
                v.append(f"precedence: {d} (w{ok[d]}) must finish before {s} (w{w})")
    for w in range(WINDOWS):
        load = sum(TASK_BY_ID[t]["effort"] for t, ww in ok.items() if ww == w)
        if load > CAP:
            v.append(f"capacity: window {w} effort {load} > {CAP}")
        for trip in BLAST_TRIPLES:
            if all(ok.get(t) == w for t in trip):
                v.append(f"blast radius: {trip} all in window {w}")
    return v


def business(plan, risks):
    ok = {t: w for t, w in plan.items() if isinstance(w, int)}
    delay = sum(risks[t] * w for t, w in ok.items())
    bo = sum(blackout_cost(t, w) for t, w in ok.items())
    total = sum(risks.values())
    curve = [round(sum(risks[t] for t, w in ok.items() if w >= k) / total * 100, 1) for k in range(WINDOWS + 1)]
    return {"risk_weighted_delay": round(delay, 2), "blackout_cost": bo, "objective": round(delay + bo, 2),
            "exposure_curve_pct": curve}


def waves(plan):
    out = [[] for _ in range(WINDOWS)]
    for t in TASKS:
        w = plan[t["id"]]
        if isinstance(w, int):
            out[w].append(t["id"])
    return out


# ---------------------------------------------------------------- solvers
def solve_qpiai(P, names, log=print, seed=0):
    """Native HUBO on QpiAI Opt. Needs QPIAI_OPT_API_KEY."""
    from qpiai_opt.opt_solvers import Client, solve
    from qpiai_opt.opt_solvers.hubo.models import HUBOProblem
    if not config.QPIAI_OPT_API_KEY:
        raise RuntimeError("QPIAI_OPT_API_KEY missing: register at https://opt.qpiai.tech and put it in .env")
    prob = HUBOProblem(num_variables=len(names), polynomial_dict={k: v for k, v in P.items()},
                       variable_names=tuple(names), solver_config={**QPIAI_SAMPLING, "seed": seed})
    client = Client(api_key=config.QPIAI_OPT_API_KEY)
    t0 = time.time()
    r = solve(prob, client=client)
    raw = r.model_dump(mode="json")
    assign = {k: int(v) for k, v in r.variable_assignment.items()}
    return assign, {"solver": "QpiAI Opt (native HUBO, local)", "seed": seed, "wall_s": round(time.time() - t0, 3),
                    "objective": raw.get("objective"), "solver_time_s": raw.get("solver_time_s"),
                    "job_id": raw.get("job_id"), "execution_mode": raw.get("execution_mode")}


def solve_sa(P, names, reads=8, sweeps=1500, seed=0):
    """Classical simulated annealing on the same HUBO (baseline / offline fallback)."""
    rnd = random.Random(seed)
    touch = defaultdict(list)
    for k, c in P.items():
        for v in k:
            touch[v].append((k, c))

    def delta(a, v):
        cur = a[v]
        d = 0.0
        for k, c in touch[v]:
            rest = math.prod(a[u] for u in k if u != v)
            d += c * rest * ((1 - cur) - cur)
        return d
    best, best_e = None, float("inf")
    t0 = time.time()
    for _ in range(reads):
        a = {v: rnd.randint(0, 1) for v in names}
        e = energy(P, a)
        for s in range(sweeps):
            T = 50.0 * (0.01 / 50.0) ** (s / sweeps)
            for v in names:
                d = delta(a, v)
                if d <= 0 or rnd.random() < math.exp(-d / T):
                    a[v] ^= 1
                    e += d
        if e < best_e:
            best, best_e = dict(a), e
    return best, {"solver": "Simulated annealing (classical baseline)", "wall_s": round(time.time() - t0, 3),
                  "objective": round(best_e, 3)}


def solve_cpsat(risks, time_limit=20):
    """Exact optimum of the same scheduling problem with hard constraints (OR-Tools CP-SAT)."""
    from ortools.sat.python import cp_model
    m = cp_model.CpModel()
    x = {(t["id"], w): m.NewBoolVar(xv(t["id"], w)) for t in TASKS for w in range(WINDOWS)}
    win = {}
    for t in TASKS:
        m.AddExactlyOne(x[t["id"], w] for w in range(WINDOWS))
        win[t["id"]] = sum(w * x[t["id"], w] for w in range(WINDOWS))
    for t in TASKS:
        for d in t["deps"]:
            m.Add(win[t["id"]] >= win[d] + 1)
    for w in range(WINDOWS):
        m.Add(sum(t["effort"] * x[t["id"], w] for t in TASKS) <= CAP)
        for trip in BLAST_TRIPLES:
            m.Add(sum(x[t, w] for t in trip) <= 2)
    m.Minimize(sum(int(round(100 * (risks[t["id"]] * w + blackout_cost(t["id"], w)))) * x[t["id"], w]
                   for t in TASKS for w in range(WINDOWS)))
    s = cp_model.CpSolver()
    s.parameters.max_time_in_seconds = time_limit
    t0 = time.time()
    status = s.Solve(m)
    plan = {t["id"]: next(w for w in range(WINDOWS) if s.Value(x[t["id"], w])) for t in TASKS}
    return plan, {"solver": "OR-Tools CP-SAT (exact)", "wall_s": round(time.time() - t0, 3),
                  "status": s.StatusName(status)}


def solve_greedy(risks):
    """What a team would do by hand: highest risk first, earliest window that respects deps + capacity."""
    plan, load = {}, [0] * WINDOWS
    remaining = sorted(TASKS, key=lambda t: -risks[t["id"]])
    while remaining:
        for t in remaining:
            if all(d in plan for d in t["deps"]):
                break
        earliest = max([plan[d] + 1 for d in t["deps"]], default=0)
        for w in range(earliest, WINDOWS):
            blast = any(t["id"] in trip and sum(plan.get(o) == w for o in trip if o != t["id"]) == 2
                        for trip in BLAST_TRIPLES)
            if load[w] + t["effort"] <= CAP and not blast and not blackout_cost(t["id"], w):
                break
        else:
            w = WINDOWS - 1
        plan[t["id"]] = w
        load[w] += t["effort"]
        remaining.remove(t)
    return plan, {"solver": "Greedy (risk-first, manual-style)"}


def optimise(risks, log=print, use_qpiai=True):
    """Build the HUBO, solve on QpiAI Opt (retrying with stronger penalties if infeasible), compare baselines."""
    result = {"windows": WINDOWS, "capacity": CAP, "penalties": dict(PEN), "risks": risks, "attempts": []}
    best = None                                    # (objective, plan, meta)
    for scale in (1.0, 0.75):                      # penalty 80, then 60 if nothing feasible
        pen = {k: (v * scale if k in "ABE" else v) for k, v in PEN.items()}
        P, names = build(risks, pen)
        result["hubo"] = stats(P, names)
        for seed in range(QPIAI_SEEDS):
            try:
                if not use_qpiai:
                    raise RuntimeError("QpiAI disabled")
                assign, meta = solve_qpiai(P, names, log, seed=seed)
            except Exception as e:
                if seed == 0:
                    log(f"QpiAI Opt unavailable ({str(e)[:120]}); using classical SA fallback")
                assign, meta = solve_sa(P, names, seed=seed)
                meta["fallback_reason"] = str(e)[:200]
            plan = decode(assign)
            viol = validate(plan)
            obj = business(plan, risks)["objective"] if not viol else None
            meta.update({"energy": round(energy(P, assign), 3), "violations": viol, "penalties": dict(pen),
                         "plan_objective": obj})
            result["attempts"].append(meta)
            if not viol and (best is None or obj < best[0]):
                best = (obj, plan, meta)
            if meta.get("fallback_reason"):
                break                              # SA fallback is slow; one run per setting
        feasible = sum(1 for a in result["attempts"] if not a["violations"])
        log(f"{result['attempts'][-1]['solver']}: {feasible}/{len(result['attempts'])} runs feasible so far "
            f"(penalty x{scale})")
        if best:
            break
    if best is None:
        raise RuntimeError("no feasible plan from any solver run; see attempts in plan.json")
    primary = (best[1], best[2])
    plan, meta = primary
    result["plan"] = plan
    result["waves"] = waves(plan)
    result["primary"] = {**meta, **business(plan, risks)}
    base = {}
    for fn in (solve_cpsat, solve_greedy):
        p, m = fn(risks)
        base[m["solver"]] = {**m, **business(p, risks), "violations": validate(p), "plan": p}
    result["baselines"] = base
    exact = base["OR-Tools CP-SAT (exact)"]["objective"]
    result["primary"]["optimality_gap_pct"] = round(100 * (result["primary"]["objective"] - exact) / exact, 2) if exact else 0.0
    result["polynomial"] = {"|".join(k) if k else "const": v for k, v in P.items()}
    config.EVIDENCE.mkdir(parents=True, exist_ok=True)
    (config.EVIDENCE / "plan.json").write_text(json.dumps(result, indent=1))
    return result

