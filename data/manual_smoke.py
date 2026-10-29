"""Smoke test of the manual operator controls through the console API (http://127.0.0.1:8000)."""
import json
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8000"


def call(method, path, body=None):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def status_of(ids):
    _, tv = call("GET", "/api/tasks")
    return {t["id"]: t["status"] for t in tv["tasks"] if t["id"] in ids}


def gate_summary(r):
    failed = [c["name"] for c in r.get("checks", []) if not c["passed"]]
    return f"passed={r.get('passed')} failed={failed} rollback={(r.get('rollback') or {}).get('restore_s')}"


print("1 reset", call("POST", "/api/reset?keep=true")[0])
print("  ", status_of(["kex.payments", "jwt.accept-payments", "jwt.sign-fndsa", "cert.ledger"]))
print("2 apply without prerequisites (expect 409 refusal):", call("POST", "/api/apply", {"tasks": ["cert.ledger"]}))
c, r = call("POST", "/api/apply", {"tasks": ["kex.payments"], "auto_rollback": True})
print("3 apply kex.payments:", c, gate_summary(r))
c, r = call("POST", "/api/apply", {"tasks": ["jwt.sign-fndsa"], "auto_rollback": True, "force": True})
print("4 FORCE jwt.sign-fndsa (auto-rollback on):", c, gate_summary(r), r.get("traffic_delta"))
c, r = call("POST", "/api/apply", {"tasks": ["kms.key-jwt"], "auto_rollback": False})
print("5 apply kms.key-jwt (auto-rollback off):", c, gate_summary(r))
print("   status:", status_of(["kms.key-jwt"]))
c, r = call("POST", "/api/rollback")
print("6 manual rollback:", c, r.get("label"), r.get("rollback"))
print("   status:", status_of(["kms.key-jwt"]))
c, r = call("POST", "/api/gate")
print("7 gate now:", c, gate_summary(r))
c, r = call("POST", "/api/probe/payments?mode=classical")
print("8 probe payments classical:", c, r.get("ok"), r.get("group"), r.get("peer_sig"))
c, r = call("POST", "/api/probe/payments?mode=default")
print("  probe payments modern:", c, r.get("ok"), r.get("group"), r.get("peer_sig"))
_, ev = call("GET", "/api/events")
print("9 events:", [(e["type"], e.get("label"), e.get("passed")) for e in ev[:6]])
