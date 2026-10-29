"""End-to-end PQ-Bridge pipeline: scan -> risk -> plan (QpiAI Opt + QCloud QAOA) -> waves -> drill -> report."""
import json
import time

from . import bench as bench_mod
from . import circuits as circuits_mod
from . import config, detect, migrate, qaoa, qubo, risk, scanner, survey, testbed
from .tasks import DEFERRED, TASK_BY_ID, TASKS

EVID = config.EVIDENCE
LOG = []


def log(msg):
    line = f"{time.strftime('%H:%M:%S')}  {msg}"
    LOG.append(line)
    del LOG[:-300]
    print(line, flush=True)


def _load(name, default=None):
    try:
        return json.loads((EVID / name).read_text())
    except Exception:
        return default


def scan():
    log("Scanning bank estate: code, configs, certificates, dependencies, live TLS endpoints")
    findings = scanner.scan_estate()
    ev = scanner.evaluate()
    vuln = [f for f in findings if f["status"] == "quantum-vulnerable"]
    log(f"Inventory: {len(findings)} findings, {len(vuln)} quantum-vulnerable. "
        f"Corpus precision {ev['pq_bridge']['precision']} / recall {ev['pq_bridge']['recall']}")
    return {"findings": findings, "eval": ev}


def repos():
    """Hybrid detection engine (rules + ML + crypto verification) over real bank / fintech repos."""
    if not detect.REPOS.exists() or not any(detect.REPOS.iterdir()):
        raise RuntimeError("real repositories not fetched yet: run `python -m pqbridge.fetch_repos` (about 450 MB)")
    log("Evaluating detection engine leave-one-repo-out on labelled lines from real repos")
    ev = detect.evaluate()
    b = ev["methods"]["fused: balanced"]
    log(f"Fused engine: precision {b['precision']} / recall {b['recall']} (rules alone "
        f"{ev['methods']['rules only']['precision']} / {ev['methods']['rules only']['recall']})")
    detect.train()
    out = detect.analyse_all(log=lambda m: log("  " + m))
    return {"eval": ev, "summary": out["summary"]}


def tls_survey():
    log(f"Surveying public TLS posture of {len(survey.HOSTS)} bank / fintech endpoints (one normal handshake each)")
    r = survey.run(log=lambda m: None)
    s = r["summary"]
    log(f"Survey: {s['pq_hybrid_kex']}/{s['reachable']} negotiate PQ hybrid key exchange, "
        f"{s['pq_signature_leaf']}/{s['reachable']} use PQ certificates, {s['hqc_kex']} support HQC")
    return r


def benchmarks():
    return bench_mod.run(log=log)


def circuits():
    log(f"Designing and running QpiAI QCloud circuits on {config.QCLOUD_DEVICE}")
    return circuits_mod.run_all(log=log)


def assess(overrides=None):
    """Score criticality. `overrides` = operator-edited assumptions from the Risk page (persisted)."""
    if overrides:
        risk.set_params(overrides)
        log(f"Risk assumptions updated: CRQC in {config.CRQC_YEARS} y, migration takes {config.MIGRATION_YEARS} y")
    findings = _load("inventory.json", [])
    out = {"services": risk.service_risk(findings), "tasks": risk.task_risks(findings),
           "crqc_years": config.CRQC_YEARS, "migration_years": config.MIGRATION_YEARS, "params": risk.params()}
    (EVID / "risk.json").write_text(json.dumps(out, indent=1))
    log("Risk model scored " + ", ".join(f"{s}={v['score']}" for s, v in out["services"].items()))
    return out


def plan(use_qpiai=True):
    r = _load("risk.json") or assess()
    risks = r["tasks"]
    log("Building migration HUBO (tasks x change windows) and solving on QpiAI Opt")
    res = qubo.optimise(risks, log=log, use_qpiai=use_qpiai)
    p = res["primary"]
    log(f"{p['solver']}: objective {p['objective']}, {len(p['violations'])} violations, "
        f"gap vs exact {p['optimality_gap_pct']}%")
    log(f"QAOA cross-check on QpiAI QCloud ({config.QCLOUD_DEVICE}) for cluster {qaoa.CLUSTER}")
    q = qaoa.run(res["plan"], risks)
    log(f"QAOA: {q['qubits']} qubits, {q['circuit_runs']} circuit runs, best {q['qaoa_best']['energy']} "
        f"vs brute-force {q['brute_force']['energy']} (plan had {q['opt_plan_cluster']['energy']})")
    res["qaoa"] = q
    final = dict(res["plan"])
    if q["qaoa_improves_plan"]:
        cand = {**final, **q["qaoa_best"]["assignment"]}
        if not qubo.validate(cand) and qubo.business(cand, risks)["objective"] < p["objective"]:
            final = cand
            log("QAOA found a better assignment for the cluster; refined plan adopted")
    res["final_plan"] = final
    res["final_waves"] = qubo.waves(final)
    res["final"] = {**qubo.business(final, risks), "violations": qubo.validate(final)}
    res["deferred"] = DEFERRED
    res["tasks"] = TASKS
    (EVID / "plan.json").write_text(json.dumps(res, indent=1))
    for i, w in enumerate(res["final_waves"]):
        log(f"  window {i}: {', '.join(w)}")
    return res


def run_wave(i):
    res = _load("plan.json")
    if not res:
        raise RuntimeError("no plan yet")
    return migrate.run_wave(i, res["final_waves"][i], label=f"wave{i}", log=log)


def drill():
    """Attempt the deferred public-cert switch: legacy customers break, gate must roll it back."""
    st = testbed.read_state()
    if not st["_pki"]["pq_root"]:
        raise RuntimeError("drill needs the PQ PKI (run the wave that issues it first)")
    log("FAULT DRILL: switching public gateway certificate to FN-DSA before legacy clients support it")
    TASK_BY_ID.setdefault("cert.gateway-public", {**DEFERRED[0], "kind": "authentication", "effort": 1, "deps": []})
    return migrate.run_wave(-1, ["cert.gateway-public"], label="drill", log=log)


def waves():
    try:
        return [json.loads(l) for l in (EVID / "waves.jsonl").read_text().splitlines() if l.strip()]
    except Exception:
        return []


def report():
    res = _load("plan.json") or {}
    ws = waves()
    ev = _load("detection_eval.json") or {}
    inv = _load("inventory.json") or []
    qr = []
    try:
        qr = [json.loads(l) for l in (EVID / "qrng_runs.jsonl").read_text().splitlines() if l.strip()]
    except Exception:
        pass
    total_pay = sum(w["traffic_delta"]["pay_ok"] for w in ws)
    failed_pay = sum(w["traffic_delta"]["pay_fail"] for w in ws)
    ml = _load("ml_eval.json") or {}
    rf = _load("repo_findings.json") or {}
    sv = _load("tls_survey.json") or {}
    bm = _load("benchmarks.json") or {}
    out = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ml_engine": {k: ml.get("methods", {}).get(k) for k in ("rules only", "fused: balanced", "fused: audit (high recall)")},
        "real_repos": {k: {"findings": v["findings"], "confirmed": v["confirmed"]} for k, v in rf.get("summary", {}).items()},
        "tls_survey": sv.get("summary"),
        "benchmarks_tls": [{k: r[k] for k in ("mode", "bytes_total", "median_ms", "handshakes_per_wall_sec")} for r in bm.get("tls", [])],
        "inventory": {"findings": len(inv), "quantum_vulnerable": sum(f["status"] == "quantum-vulnerable" for f in inv)},
        "detection_eval": {k: {m: ev[k][m] for m in ("precision", "recall", "f1", "tp", "fp", "fn")}
                           for k in ("pq_bridge", "naive_grep")} if ev else {},
        "plan": {"solver": res.get("primary", {}).get("solver"), "objective": res.get("final", {}).get("objective"),
                 "violations": res.get("final", {}).get("violations"), "hubo": res.get("hubo"),
                 "baselines": {k: v["objective"] for k, v in res.get("baselines", {}).items()},
                 "exposure_curve_pct": res.get("final", {}).get("exposure_curve_pct")},
        "qaoa": {k: res.get("qaoa", {}).get(k) for k in ("qubits", "circuit_runs", "found_optimum", "p_optimal",
                                                         "p_optimal_uniform_random", "approx_ratio_mean")},
        "qrng": [{"purpose": q["purpose"], "device": q["run"]["device"], "shots": q["run"]["shots"],
                  "health": q["health"]} for q in qr],
        "waves": [{"label": w["label"], "tasks": w["tasks"], "passed": w["passed"],
                   "checks_passed": sum(c["passed"] for c in w["checks"]), "checks": len(w["checks"]),
                   "rollback_s": (w["rollback"] or {}).get("restore_s"), "traffic": w["traffic_delta"]} for w in ws],
        "payments_during_migration": {"settled": total_pay, "failed": failed_pay},
    }
    (EVID / "report.json").write_text(json.dumps(out, indent=1))
    return out


def reset(keep_analysis=False):
    """Fresh, fully classical bank. keep_analysis=True (console button) keeps scans, plan, repos, survey,
    benchmarks and circuits, and clears only the migration history, so a live demo can start over quickly."""
    log("Resetting testbed to the classical baseline" + (" (keeping analysis evidence)" if keep_analysis else ""))
    testbed.down(wipe=True)
    if EVID.exists():
        keep = {"inventory.json", "detection_eval.json", "risk.json", "risk_params.json", "plan.json", "qaoa.json",
                "qrng_runs.jsonl", "ml_eval.json", "repo_findings.json", "tls_survey.json", "benchmarks.json"}
        for p in sorted(EVID.rglob("*"), reverse=True):
            if keep_analysis and (p.name in keep or "circuits" in p.parts):
                continue
            try:
                p.unlink() if p.is_file() else p.rmdir()
            except OSError:
                pass
    testbed.up()
    log("Testbed up: payments flowing, every service classical (RSA-2048 / X25519)")


# ---------------------------------------------------------------- manual operator controls
def tasks_view():
    """Every migration task with live status, dependencies, risk and planned window."""
    st = testbed.read_state()
    plan = _load("plan.json") or {}
    risks = (_load("risk.json") or {}).get("tasks", {})
    final = plan.get("final_plan", {})
    rows = []
    for t in TASKS + [{**DEFERRED[0], "kind": "authentication", "effort": 1, "deps": []}]:
        done = migrate.task_done(t["id"], st)
        missing = [d for d in t["deps"] if not migrate.task_done(d, st)]
        rows.append({"id": t["id"], "title": t["title"], "service": t["service"], "kind": t["kind"],
                     "effort": t["effort"], "deps": t["deps"], "missing_deps": missing, "done": done,
                     "risk": risks.get(t["id"]), "window": final.get(t["id"]),
                     "deferred": t["id"] == DEFERRED[0]["id"],
                     "status": "applied" if done else ("deferred" if t["id"] == DEFERRED[0]["id"]
                                                       else "blocked" if missing else "ready")})
    return {"state": st, "tasks": rows, "history": [{k: h[k] for k in ("label", "tasks", "ts")} for h in migrate.history()]}


def apply_tasks(task_ids, auto_rollback=True, force=False):
    """Operator applies one or more tasks now. Without force, unmet prerequisites are refused up front."""
    st = testbed.read_state()
    TASK_BY_ID.setdefault("cert.gateway-public", {**DEFERRED[0], "kind": "authentication", "effort": 1, "deps": []})
    unknown = [t for t in task_ids if t not in TASK_BY_ID]
    if unknown:
        raise RuntimeError(f"unknown task(s): {unknown}")
    if not force:
        missing = {t: [d for d in TASK_BY_ID[t]["deps"] if not migrate.task_done(d, st) and d not in task_ids]
                   for t in task_ids}
        missing = {t: m for t, m in missing.items() if m}
        if missing:
            raise RuntimeError("prerequisites not applied: " + "; ".join(f"{t} needs {', '.join(m)}" for t, m in missing.items())
                               + ". Apply them first, or use Force to demonstrate what the gate does.")
    label = f"manual-{time.strftime('%H%M%S')}"
    log(f"OPERATOR: apply {task_ids} (auto-rollback {'on' if auto_rollback else 'off'}{', FORCED' if force else ''})")
    return migrate.run_wave(-1, task_ids, label=label, log=log, auto_rollback=auto_rollback)


def rollback_last():
    return migrate.rollback_last(log=log)


def gate_now():
    return migrate.gate_now(log=log)


def probe(svc, mode="default"):
    groups = {"default": None, "classical": "X25519:P-256", "pq-only": config.PQ["pq_group"]}[mode]
    r = migrate.probe(svc, groups)
    log(f"probe {svc} ({mode} client): {r['group']} / {r['peer_sig']} / {'ok' if r['ok'] else 'HANDSHAKE FAILED'}")
    return r
