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
The bank has 37 tasks x 4 windows = 148 binaries. Exact pruning removes windows a task can never use (it needs
its whole prerequisite chain before it and its dependents' chain after it), leaving 82 binaries / ~1,090 terms,
which fits QpiAI Opt's local HUBO solver (100 variables, 1,500 terms). QpiAI Opt solves the whole HUBO natively,
cubic terms included, from 8 starts; a task an annealer sample leaves in 0 or 2+ windows is one-hot decoded
(lowest-energy window); the best plan that passes the validator is kept. The crowding weight K is small (0.1): it
only breaks ties toward spreading work, so the HUBO optimum stays close to the business optimum. A larger bank
falls back to decomposition (large-neighbourhood search over 20-task blocks). The cloud HUBO solver is not enabled
for our QpiAI organisation.
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
CAP = 12
SLACK = [1, 2, 2]
PEN = {"A": 80.0, "B": 80.0, "C": 40.0, "E": 80.0, "K": 0.1}   # C: pairwise capacity penalty in the QAOA sub-QUBO
QPIAI_SEEDS = 2                                       # per decomposition round (fallback path)
QPIAI_SAMPLING = {"num_reads": 2, "num_sweeps": 2000}  # within QpiAI's local annealing-work limit
LNS_BLOCK, LNS_ROUNDS = 20, 20
BLACKOUT_COST = 25.0


def xv(t, w):
    return f"x|{t}|{w}"


def sv(w, k):
    return f"s|{w}|{k}"


def blackout_cost(task_id, w):
    t = TASK_BY_ID[task_id]
    return BLACKOUT_COST if (w == BLACKOUT["window"] and t["service"] in BLACKOUT["services"]) else 0.0


def domains():
    """Exact pruning: a task can only sit in windows [longest prerequisite chain above it,
    WINDOWS-1 - longest chain of dependents below it]. Removing other windows loses no feasible plan."""
    kids = {t["id"]: [s["id"] for s in TASKS if t["id"] in s["deps"]] for t in TASKS}
    memo_d, memo_h = {}, {}

    def depth(t):
        if t not in memo_d:
            memo_d[t] = max([depth(d) + 1 for d in TASK_BY_ID[t]["deps"]], default=0)
        return memo_d[t]

    def height(t):
        if t not in memo_h:
            memo_h[t] = max([height(k) + 1 for k in kids[t]], default=0)
        return memo_h[t]
    return {t["id"]: list(range(depth(t["id"]), WINDOWS - height(t["id"]))) for t in TASKS}


def build(risks, pen=None):
    pen = {**PEN, **(pen or {})}
    P = defaultdict(float)
    dom = domains()

    def add(vars_, c):
        P[tuple(sorted(set(vars_)))] += c

    ids = [t["id"] for t in TASKS]
    for t in ids:                                       # one-hot (over the task's allowed windows)
        xs = [xv(t, w) for w in dom[t]]
        add((), pen["A"])
        for v in xs:
            add((v,), -pen["A"])
        for a, b in itertools.combinations(xs, 2):
            add((a, b), 2 * pen["A"])
    for s in ids:                                       # precedence
        for d in TASK_BY_ID[s]["deps"]:
            for w in dom[s]:
                for w2 in dom[d]:
                    if w2 >= w:
                        add((xv(s, w), xv(d, w2)), pen["B"])
    for w in range(WINDOWS):                            # crowding (capacity enforced by the validator)
        here = [t for t in ids if w in dom[t]]
        for a, b in itertools.combinations(here, 2):
            add((xv(a, w), xv(b, w)), pen["K"] * TASK_BY_ID[a]["effort"] * TASK_BY_ID[b]["effort"])
    for trip in BLAST_TRIPLES:                          # cubic blast-radius
        for w in range(WINDOWS):
            if all(w in dom[t] for t in trip):
                add(tuple(xv(t, w) for t in trip), pen["E"])
    for t in ids:                                       # objective
        for w in dom[t]:
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

        def fits(w, freeze_ok):
            blast = any(t["id"] in trip and sum(plan.get(o) == w for o in trip if o != t["id"]) == 2
                        for trip in BLAST_TRIPLES)
            return load[w] + t["effort"] <= CAP and not blast and (freeze_ok or not blackout_cost(t["id"], w))
        # earliest window that respects capacity, blast radius and the freeze; then relax only the freeze (a cost)
        w = next((w for w in range(earliest, WINDOWS) if fits(w, False)),
                 next((w for w in range(earliest, WINDOWS) if fits(w, True)), WINDOWS - 1))
        plan[t["id"]] = w
        load[w] += t["effort"]
        remaining.remove(t)
    return plan, {"solver": "Greedy (risk-first, manual-style)"}


def restrict(P, fixed):
    """Substitute fixed binaries (var -> 0/1) into a polynomial; returns the sub-polynomial over the free ones."""
    Q = defaultdict(float)
    for k, c in P.items():
        rest = []
        for v in k:
            if v in fixed:
                if not fixed[v]:
                    c = 0.0
                    break
            else:
                rest.append(v)
        if c:
            Q[tuple(rest)] += c
    Q = {k: v for k, v in Q.items() if v}
    return Q, sorted({v for k in Q for v in k})


def _onehot_decode(P, plan, block):
    """Standard one-hot decoding of an annealer sample: a task the sample left in 0 or 2+ windows gets the window
    with the lowest HUBO energy given every other assignment. Returns how many tasks needed it."""
    ids = [t["id"] for t in TASKS]
    dom = domains()
    bad = [t for t in block if not isinstance(plan[t], int)]
    for t in bad:
        plan[t] = None
    for t in bad:
        best = None
        for w in dom[t]:
            plan[t] = w
            e = energy(P, {xv(u, ww): int(plan[u] == ww) for u in ids if isinstance(plan[u], int) for ww in range(WINDOWS)})
            if best is None or e < best[0]:
                best = (e, w)
        plan[t] = best[1]
    return len(bad)


def _score(plan, risks):
    v = validate(plan)
    return (len(v), business(plan, risks)["objective"] if not v else float("inf"))


LOCAL_HUBO = {"variables": 100, "terms": 1500}          # qpiai_opt LOCAL_LIMITS["HUBO"]


def optimise(risks, log=print, use_qpiai=True):
    """Build the (pruned) HUBO and solve it on QpiAI Opt: the whole HUBO natively, multi-start, when it fits the
    local solver; otherwise block by block (LNS). Compare with exact CP-SAT and greedy."""
    P, names = build(risks)
    if len(names) <= LOCAL_HUBO["variables"] and len(P) <= LOCAL_HUBO["terms"]:
        return _optimise_native(risks, P, names, log, use_qpiai)
    return _optimise_lns(risks, log, use_qpiai)


def _finish(result, risks, plan, meta, P, log):
    result["plan"] = plan
    result["waves"] = waves(plan)
    result["blackout"] = BLACKOUT
    result["primary"] = {**meta, **business(plan, risks)}
    base = {}
    for fn in (solve_cpsat, solve_greedy):
        bp, m = fn(risks)
        base[m["solver"]] = {**m, **business(bp, risks), "violations": validate(bp), "plan": bp}
    result["baselines"] = base
    exact = base["OR-Tools CP-SAT (exact)"]["objective"]
    result["primary"]["optimality_gap_pct"] = round(100 * (result["primary"]["objective"] - exact) / exact, 2) if exact else 0.0
    result["polynomial"] = {"|".join(k) if k else "const": v for k, v in P.items()}
    config.EVIDENCE.mkdir(parents=True, exist_ok=True)
    (config.EVIDENCE / "plan.json").write_text(json.dumps(result, indent=1))
    return result


def _optimise_native(risks, P, names, log, use_qpiai, seeds=16):
    dom = domains()
    result = {"windows": WINDOWS, "capacity": CAP, "penalties": dict(PEN), "risks": risks, "attempts": [],
              "hubo": stats(P, names), "domains": dom,
              "method": f"QpiAI Opt native HUBO over {len(names)} binaries (windows pruned by dependency chains), "
                        f"{seeds} starts, best feasible kept"}
    log(f"HUBO {len(names)} binaries / {len(P)} terms ({result['hubo']['terms_by_degree'].get(3, 0)} cubic) after exact "
        f"pruning from {len(TASKS) * WINDOWS}: fits QpiAI Opt's local solver")
    best, used_fallback = None, None
    for seed in range(seeds):
        try:
            if not use_qpiai:
                raise RuntimeError("QpiAI disabled")
            assign, meta = solve_qpiai(P, names, log, seed=seed)
        except Exception as e:
            used_fallback = str(e)[:200]
            assign, meta = solve_sa(P, names, reads=2, sweeps=800, seed=seed)
        plan = decode(assign)
        n_dec = _onehot_decode(P, plan, list(plan))
        viol = validate(plan)
        obj = business(plan, risks)["objective"] if not viol else None
        meta.update({"energy": round(energy(P, assign), 3), "violations": viol, "plan_objective": obj, "onehot_decoded": n_dec})
        result["attempts"].append(meta)
        if not viol and (best is None or obj < best[0]):
            best = (obj, plan, meta)
    feas = sum(1 for a in result["attempts"] if not a["violations"])
    log(f"{result['attempts'][0]['solver']}: {feas}/{seeds} starts feasible")
    if best is None:
        log("no feasible start; falling back to decomposition")
        return _optimise_lns(risks, log, use_qpiai)
    meta = {**best[2], "solver": "QpiAI Opt (native HUBO, local)" if not used_fallback else "Simulated annealing (classical fallback)",
            "starts": seeds, "feasible_starts": feas}
    if used_fallback:
        meta["fallback_reason"] = used_fallback
    return _finish(result, risks, best[1], meta, P, log)


def _optimise_lns(risks, log=print, use_qpiai=True):
    """Decomposition (large-neighbourhood search) for HUBOs larger than the local solver's limit."""
    import random as _r
    result = {"windows": WINDOWS, "capacity": CAP, "penalties": dict(PEN), "risks": risks, "attempts": [],
              "method": f"QpiAI Opt native HUBO, decomposed: {LNS_ROUNDS} rounds x {LNS_BLOCK}-task blocks"}
    P, names = build(risks)
    result["hubo"] = stats(P, names)
    ids = [t["id"] for t in TASKS]
    plan, _ = solve_greedy(risks)
    start_obj = business(plan, risks)["objective"]
    cur = _score(plan, risks)
    log(f"HUBO {result['hubo']['variables']} binaries / {result['hubo']['terms']} terms; start (greedy): cost {start_obj}, "
        f"{cur[0]} violations")
    rng = _r.Random(7)
    t0, qtime, used_fallback = time.time(), 0.0, None
    for rnd in range(LNS_ROUNDS):
        # tasks named in a current violation are always freed; the rest of the block is random, or (odd rounds)
        # drawn from two windows so tasks can swap windows
        bad = [t for t in ids if any(t in v for v in validate(plan))]
        pool = [t for t in ids if t not in bad]
        if rnd % 2:
            w1, w2 = rng.sample(range(WINDOWS), 2)
            pool = [t for t in pool if plan[t] in (w1, w2)] or pool
        block = bad[:LNS_BLOCK] + rng.sample(pool, max(0, min(len(pool), LNS_BLOCK - len(bad))))
        fixed = {xv(t, w): int(plan[t] == w) for t in ids if t not in block for w in range(WINDOWS)}
        sub, sub_names = restrict(P, fixed)
        for seed in range(QPIAI_SEEDS):
            try:
                if not use_qpiai:
                    raise RuntimeError("QpiAI disabled")
                assign, meta = solve_qpiai(sub, sub_names, log, seed=rnd * 10 + seed)
            except Exception as e:
                used_fallback = str(e)[:200]
                assign, meta = solve_sa(sub, sub_names, reads=2, sweeps=400, seed=rnd * 10 + seed)
            qtime += meta.get("solver_time_s") or meta.get("wall_s") or 0
            cand = dict(plan)
            for t in block:
                ws = [w for w in range(WINDOWS) if assign.get(xv(t, w), 0)]
                cand[t] = ws[0] if len(ws) == 1 else None
            fixed_onehot = _onehot_decode(P, cand, block)
            sc = _score(cand, risks)
            accepted = sc < cur
            if accepted:
                plan, cur = cand, sc
            result["attempts"].append({"round": rnd, "seed": seed, "solver": meta["solver"], "onehot_decoded": fixed_onehot,
                                       "sub_variables": len(sub_names),
                                       "sub_terms": len(sub), "violations": validate(cand), "plan_objective": None if sc[0] else sc[1],
                                       "accepted": accepted, "wall_s": meta.get("wall_s"), "solver_time_s": meta.get("solver_time_s")})
    acc = sum(a["accepted"] for a in result["attempts"])
    solver = "QpiAI Opt (native HUBO, decomposed)" if not used_fallback else "Simulated annealing (classical fallback, decomposed)"
    log(f"{solver}: {len(result['attempts'])} sub-solves, {acc} improvements accepted; cost {start_obj} -> {cur[1]}")
    meta = {"solver": solver, "wall_s": round(time.time() - t0, 2), "solver_time_s": round(qtime, 2),
            "start": "greedy (risk-first)", "start_objective": start_obj, "sub_solves": len(result["attempts"]),
            "accepted": acc, "violations": validate(plan), "energy": round(energy(P, {xv(t, w): int(plan[t] == w)
                                                                                    for t in ids for w in range(WINDOWS)}), 3)}
    if used_fallback:
        meta["fallback_reason"] = used_fallback
    return _finish(result, risks, plan, meta, P, log)
