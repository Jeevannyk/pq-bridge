"""PQ-Bridge console API. Run: python -m pqbridge.api  ->  http://localhost:8000"""
import json
import threading
import traceback

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import config, detect, migrate, pipeline, risk, testbed

app = FastAPI(title="PQ-Bridge")
risk.load_params()      # operator-edited risk assumptions survive restarts
_busy = threading.Lock()
_current = {"op": None}


def _job(name, fn, *a):
    if not _busy.acquire(blocking=False):
        raise HTTPException(409, f"busy: {_current['op']}")
    _current["op"] = name
    try:
        return fn(*a)
    except HTTPException:
        raise
    except RuntimeError as e:          # expected refusals, e.g. unmet prerequisites, nothing to roll back
        pipeline.log(f"REFUSED {name}: {e}")
        raise HTTPException(409, str(e))
    except Exception as e:
        pipeline.log(f"ERROR in {name}: {e}")
        traceback.print_exc()
        raise HTTPException(500, str(e))
    finally:
        _current["op"] = None
        _busy.release()


def _ev(name, default=None):
    try:
        return json.loads((config.EVIDENCE / name).read_text())
    except Exception:
        return default


@app.get("/api/status")
def status():
    try:
        tr = testbed.traffic()
        st = testbed.read_state()
    except Exception as e:
        tr, st = {"error": str(e)}, {}
    ui_version = max((p.stat().st_mtime for p in (config.ROOT / "console").glob("*") if p.is_file()), default=0)
    return {"busy": _current["op"], "traffic": tr, "state": st, "log": pipeline.LOG[-60:], "ui_version": ui_version,
            "keys": {"opt": bool(config.QPIAI_OPT_API_KEY), "qcloud": bool(config.QCLOUD_API_KEY)},
            "qcloud_device": config.QCLOUD_DEVICE, "waves_done": len(pipeline.waves())}


@app.post("/api/scan")
def scan():
    return _job("scan", lambda: (pipeline.scan(), pipeline.assess())[0] and {"ok": True})


@app.get("/api/inventory")
def inventory():
    return {"findings": _ev("inventory.json", []), "eval": _ev("detection_eval.json"), "risk": _ev("risk.json")}


@app.post("/api/plan")
def plan():
    return _job("plan", lambda: pipeline.plan() and {"ok": True})


@app.get("/api/plan")
def get_plan():
    p = _ev("plan.json")
    if p:
        p.pop("polynomial", None)
    return p or {}


@app.post("/api/wave/{i}")
def wave(i: int):
    return _job(f"wave {i}", pipeline.run_wave, i)


@app.post("/api/drill")
def drill():
    return _job("fault drill", pipeline.drill)


@app.get("/api/waves")
def waves():
    return pipeline.waves()


@app.get("/api/trace/{label}/{svc}", response_class=PlainTextResponse)
def trace(label: str, svc: str):
    p = config.EVIDENCE / "traces" / label / f"{svc}.txt"
    if not p.resolve().is_relative_to(config.EVIDENCE.resolve()) or not p.exists():
        raise HTTPException(404)
    return p.read_text(encoding="utf-8")


@app.post("/api/repos")
def run_repos():
    return _job("real-repo analysis", lambda: pipeline.repos() and {"ok": True})


@app.get("/api/repos")
def repos(limit: int = 300):
    rf = _ev("repo_findings.json", {}) or {}
    findings = sorted(rf.get("findings", []),
                      key=lambda f: (["critical", "high", "medium", "low", "info"].index(f["severity"]), f["is_test"]))
    return {"eval": _ev("ml_eval.json"), "summary": rf.get("summary", {}), "findings": findings[:limit],
            "total": len(rf.get("findings", []))}


@app.post("/api/survey")
def run_survey():
    return _job("TLS survey", lambda: pipeline.tls_survey() and {"ok": True})


@app.get("/api/survey")
def get_survey():
    return _ev("tls_survey.json", {}) or {}


@app.post("/api/bench")
def run_bench():
    return _job("benchmarks", lambda: pipeline.benchmarks() and {"ok": True})


@app.get("/api/bench")
def get_bench():
    return _ev("benchmarks.json", {}) or {}


@app.post("/api/circuits")
def run_circuits():
    return _job("QCloud circuits", lambda: pipeline.circuits() and {"ok": True})


@app.get("/api/circuits")
def get_circuits():
    return _ev("circuits/index.json", {}) or {}


@app.get("/api/circuits/file/{name}")
def circuit_file(name: str):
    p = (config.EVIDENCE / "circuits" / name).resolve()
    if not p.is_relative_to((config.EVIDENCE / "circuits").resolve()) or not p.exists():
        raise HTTPException(404)
    return FileResponse(p)


@app.get("/api/qrng")
def qrng_runs():
    try:
        return [json.loads(l) for l in (config.EVIDENCE / "qrng_runs.jsonl").read_text().splitlines() if l.strip()]
    except Exception:
        return []


@app.get("/api/report")
def report():
    return pipeline.report()


@app.post("/api/reset")
def reset(keep: bool = True):
    """keep=True: reset the bank to classical but keep scans, plan, survey, benchmarks (demo restart)."""
    return _job("reset", lambda: pipeline.reset(keep_analysis=keep) or {"ok": True})


# ---------------------------------------------------------------- manual operator controls
@app.get("/api/tasks")
def tasks():
    return pipeline.tasks_view()


@app.post("/api/apply")
def apply(payload: dict = Body(...)):
    """{"tasks": [...], "auto_rollback": true, "force": false}"""
    t = payload.get("tasks") or []
    if not t:
        raise HTTPException(400, "no tasks given")
    return _job(f"apply {', '.join(t)}", pipeline.apply_tasks, t, bool(payload.get("auto_rollback", True)),
                bool(payload.get("force", False)), bool(payload.get("with_deps", False)))


@app.post("/api/rollback")
def rollback():
    return _job("rollback last change", pipeline.rollback_last)


@app.post("/api/gate")
def gate():
    return _job("verification gate", pipeline.gate_now)


@app.post("/api/probe/{svc}")
def probe(svc: str, mode: str = "default"):
    if svc not in testbed.ROLES or mode not in ("default", "classical", "pq-only"):
        raise HTTPException(400, "unknown service or mode")
    return _job(f"probe {svc}", pipeline.probe, svc, mode)


@app.get("/api/events")
def events():
    return migrate.events()


@app.post("/api/analyse")
def analyse(payload: dict = Body(...)):
    """{"code": "...", "filename": "Foo.java", "mode": "balanced" | "audit"}"""
    code = payload.get("code", "")
    if not code.strip():
        raise HTTPException(400, "paste some code first")
    return detect.analyse_text(code[:200_000], payload.get("filename") or "snippet.py", payload.get("mode", "balanced"))


@app.get("/api/risk/params")
def risk_params():
    return risk.params()


@app.post("/api/risk/params")
def set_risk_params(payload: dict = Body(...)):
    return _job("re-score risk", lambda: pipeline.assess(payload))


app.mount("/", StaticFiles(directory=config.ROOT / "console", html=True), name="console")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
