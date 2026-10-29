"""Quantum risk model: turns scan evidence + service facts into a risk score per migration task.

Mosca's inequality: data is at risk if X + Y > Z, where
  X = how long the data must stay confidential (shelf life)
  Y = how long migration takes
  Z = years until a cryptographically relevant quantum computer (CRQC)
Key exchange protects confidentiality and is exposed to harvest-now-decrypt-later,
so it is scored by Mosca urgency. Signatures/certificates can only be forged after
Q-day (no retroactive harm), so they score lower for the same service.
"""
import json

from . import config
from .tasks import TASKS

PARAMS_FILE = config.EVIDENCE / "risk_params.json"


def params():
    """Current risk assumptions (editable from the console's Risk page)."""
    return {"crqc_years": config.CRQC_YEARS, "migration_years": config.MIGRATION_YEARS,
            "services": {s: {k: m[k] for k in ("shelf_life_years", "exposure", "criticality")}
                         for s, m in config.SERVICES.items()}}


def set_params(p):
    """Apply operator overrides (years to CRQC, migration time, per-service shelf life / exposure / criticality)."""
    if "crqc_years" in p:
        config.CRQC_YEARS = float(p["crqc_years"])
    if "migration_years" in p:
        config.MIGRATION_YEARS = float(p["migration_years"])
    for s, vals in (p.get("services") or {}).items():
        if s in config.SERVICES:
            for k in ("shelf_life_years", "exposure", "criticality"):
                if k in vals:
                    config.SERVICES[s][k] = float(vals[k])
    config.EVIDENCE.mkdir(parents=True, exist_ok=True)
    PARAMS_FILE.write_text(json.dumps(params(), indent=1))


def load_params():
    if PARAMS_FILE.exists():
        set_params(json.loads(PARAMS_FILE.read_text()))


def mosca(service):
    x = config.SERVICES[service]["shelf_life_years"]
    return {"X": x, "Y": config.MIGRATION_YEARS, "Z": config.CRQC_YEARS,
            "urgency": round(min(1.0, (x + config.MIGRATION_YEARS) / config.CRQC_YEARS), 3),
            "at_risk": x + config.MIGRATION_YEARS > config.CRQC_YEARS}


def service_risk(findings):
    """Per-service summary used by the dashboard heatmap."""
    out = {}
    for s, meta in config.SERVICES.items():
        vuln = [f for f in findings if f.get("service") == s and f["status"] == "quantum-vulnerable"]
        m = mosca(s)
        score = 10 * m["urgency"] * (0.5 + 0.5 * meta["exposure"]) * meta["criticality"]
        score *= min(1.3, 1 + 0.03 * len(vuln))
        out[s] = {"score": round(min(score, 10), 2), "findings": len(vuln), "mosca": m, **meta}
    return out


def task_risk(task, findings):
    s = task["service"]
    if task["kind"] == "enabler" or s not in config.SERVICES:
        return 1.0
    meta = config.SERVICES[s]
    vuln = sum(1 for f in findings if f.get("service") == s and f["status"] == "quantum-vulnerable")
    evidence = min(1.3, 1 + 0.03 * vuln)
    if task["kind"] == "confidentiality":
        r = 10 * mosca(s)["urgency"] * (0.5 + 0.5 * meta["exposure"])
        if task["id"].startswith("pqonly."):
            r *= 0.5          # hybrid already removed most exposure; this closes the downgrade path
    else:
        r = 8 * meta["criticality"] * (0.6 + 0.4 * meta["exposure"])
    return round(min(10.0, r * evidence), 2)


def task_risks(findings):
    return {t["id"]: task_risk(t, findings) for t in TASKS}
