"""Verify every migration task against the live console API (http://127.0.0.1:8000).

  python data/verify_all_tasks.py ordered   A: apply every task in dependency order (each gated), then roll all back
  python data/verify_all_tasks.py forced    B: force every task on a fresh bank; each must end in a clean, consistent state
  python data/verify_all_tasks.py chain     C: refusal message + 'Apply + prerequisites' chains
  python data/verify_all_tasks.py           all three

After EVERY step it checks that no nginx config references a /pki file that does not exist, and that JWT keys
referenced by the state exist (the half-applied state bug).
"""
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNTIME = ROOT / "testbed" / "runtime"
BASE = "http://127.0.0.1:8000"
FAILS = []


def call(method, path, body=None, timeout=900):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {"detail": "non-JSON error body"}


def consistency():
    problems = []
    for conf in sorted((RUNTIME / "conf").glob("*.conf")):
        for p in sorted(set(re.findall(r"/pki/[^\s;]+", conf.read_text()))):
            if not (RUNTIME / p.lstrip("/")).exists():
                problems.append(f"{conf.name} references missing {p}")
    st = json.loads((RUNTIME / "state" / "services.json").read_text())
    if st["card-auth"].get("jwt_alg") == "FN-DSA-512" and not (RUNTIME / "pki/jwt/fndsa512.key").exists():
        problems.append("card-auth signs FN-DSA-512 but the key does not exist")
    if "FN-DSA-512" in st["payment-switch"].get("jwt_accept", []) and not (RUNTIME / "pki/jwt/fndsa512.pub").exists():
        problems.append("payment-switch accepts FN-DSA-512 but the public key does not exist")
    return problems


def check(ok, what):
    if not ok:
        FAILS.append(what)
    return "OK  " if ok else "FAIL"


def tasks():
    return call("GET", "/api/tasks")[1]["tasks"]


def toposort(ts):
    by = {t["id"]: t for t in ts}
    out, seen = [], set()

    def visit(i):
        if i in seen:
            return
        seen.add(i)
        for d in by[i]["deps"]:
            visit(d)
        out.append(i)
    for t in ts:
        visit(t["id"])
    return out


def reset():
    c, r = call("POST", "/api/reset?keep=true", timeout=900)
    assert c == 200, (c, r)
    time.sleep(3)


def failed_names(rec):
    return [c["name"] for c in rec["checks"] if not c["passed"]]


# --------------------------------------------------------------------------- A
def ordered():
    print("\n=== A. every task in dependency order, then roll everything back")
    reset()
    order = [t for t in toposort(tasks()) if t != "cert.gateway-public"]
    base_state = json.loads((RUNTIME / "state" / "services.json").read_text())
    applied = 0
    for t in order:
        c, r = call("POST", "/api/apply", {"tasks": [t]})
        ok = c == 200 and r.get("passed") is True and r["traffic_delta"]["pay_fail"] == 0
        cons = consistency()
        done = next(x for x in tasks() if x["id"] == t)["status"] == "applied"
        print(f"{check(ok and not cons and done, 'ordered ' + t)} apply {t:22s} http={c} passed={r.get('passed')} "
              f"checks={sum(x['passed'] for x in r.get('checks', []))}/{len(r.get('checks', []))} pay_fail={r.get('traffic_delta', {}).get('pay_fail')} "
              f"status={'applied' if done else 'NOT applied'}" + (f"  !! {cons}" if cons else "") + ("" if ok else f"  !! {failed_names(r) if c == 200 else r}"))
        applied += ok
    c, r = call("POST", "/api/gate")
    print(f"{check(c == 200 and r['passed'], 'ordered final gate')} full gate on the fully migrated bank: {sum(x['passed'] for x in r['checks'])}/{len(r['checks'])}")
    n = 0
    while True:
        c, r = call("POST", "/api/rollback")
        if c == 409:
            break
        n += 1
        ok = c == 200 and r["rollback"]["healthy"] and not consistency()
        print(f"{check(ok, 'rollback #' + str(n))} rollback #{n:<2d} {r.get('label', r)}  restore={r.get('rollback', {}).get('restore_s')} s healthy={r.get('rollback', {}).get('healthy')}")
        if n > 40:
            break
    st = json.loads((RUNTIME / "state" / "services.json").read_text())
    same = all(st[s][k] == base_state[s][k] for s in ("gateway", "card-auth", "payment-switch", "ledger") for k in base_state[s])
    print(f"{check(same, 'rollback restores baseline')} after {n} rollbacks the crypto state equals the classical baseline: {same}")
    c, r = call("POST", "/api/gate")
    print(f"{check(c == 200 and r['passed'], 'baseline gate')} gate on the restored bank: {sum(x['passed'] for x in r['checks'])}/{len(r['checks'])}")


# --------------------------------------------------------------------------- B
def forced():
    print("\n=== B. every task FORCED on a fresh bank (no prerequisites): clean outcome + consistent state")
    reset()
    ids = [t["id"] for t in tasks()]
    first = [i for i in ids if i not in ("jwt.dual-verify", "pki.pq-root")]
    for t in first + ["jwt.dual-verify", "pki.pq-root"]:
        c, r = call("POST", "/api/apply", {"tasks": [t], "force": True, "auto_rollback": True})
        clean_http = c == 200 and "checks" in r
        cons = consistency()
        if not clean_http:
            print(f"{check(False, 'forced ' + t)} {t:22s} HTTP {c}: {str(r)[:200]}")
            continue
        kind = "PASSED" if r["passed"] else ("PREFLIGHT refused (files restored)" if any(x["category"] == "preflight" for x in r["checks"] if not x["passed"]) else "gate failed -> rolled back")
        rb = (r.get("rollback") or {}).get("restore_s")
        msg = next((x["name"] for x in r["checks"] if not x["passed"]), "")[:120]
        extra = ""
        if r["passed"] and t != "pki.pq-root":
            c2, r2 = call("POST", "/api/rollback")
            extra = f" -> manual rollback http={c2} healthy={r2.get('rollback', {}).get('healthy')}"
            cons += consistency()
            still = next(x for x in tasks() if x["id"] == t)["status"] == "applied"
            if still and t != "jwt.dual-verify":
                cons.append("still applied after rollback")
        print(f"{check(not cons, 'forced ' + t)} force {t:22s} {kind:34s} rollback={rb} s pay_fail={r['traffic_delta']['pay_fail']}{extra}"
              + (f"\n        reason: {msg}" if msg else "") + (f"  !! {cons}" if cons else ""))


# --------------------------------------------------------------------------- C
def chain():
    print("\n=== C. refusal message and 'Apply + prerequisites' chains")
    reset()
    c, r = call("POST", "/api/apply", {"tasks": ["cert.ledger"]})
    ok = c == 409 and "Apply + prerequisites" in r.get("detail", "") and "pki.pq-root" in r.get("detail", "")
    print(f"{check(ok, 'refusal message')} plain apply of cert.ledger on a fresh bank -> http {c}: {r.get('detail', '')[:230]}")
    for target in ["cert.ledger", "cert.gateway", "pqonly.ledger", "jwt.sign-fndsa", "cert.card-auth", "cert.payment-switch"]:
        c, r = call("POST", "/api/apply", {"tasks": [target], "with_deps": True})
        if c == 409:
            print(f"{check('already' in r.get('detail', ''), 'chain ' + target)} chain {target:20s} http 409: {r['detail'][:100]}")
            continue
        done = next(x for x in tasks() if x["id"] == target)["status"] == "applied"
        cons = consistency()
        print(f"{check(c == 200 and r.get('passed') and done and not cons, 'chain ' + target)} chain {target:20s} steps={' -> '.join(r.get('chain', []))} "
              f"last_passed={r.get('passed')} applied={done}" + (f" !! {cons or failed_names(r)}" if cons or not r.get('passed') else ""))
    c, r = call("POST", "/api/apply", {"tasks": ["cert.gateway-public"], "with_deps": True})
    print(f"{check(c == 200 and r['passed'] is False and r['rollback'], 'gateway-public chain')} cert.gateway-public (needs PKI, then breaks legacy by design): "
          f"passed={r.get('passed')} failed={failed_names(r)[:1]} rolled_back={bool(r.get('rollback'))} consistent={not consistency()}")
    c, r = call("POST", "/api/gate")
    print(f"{check(c == 200 and r['passed'], 'final gate')} full gate after all chains: {sum(x['passed'] for x in r['checks'])}/{len(r['checks'])}")


if __name__ == "__main__":
    which = sys.argv[1:] or ["ordered", "forced", "chain"]
    t0 = time.time()
    for w in which:
        {"ordered": ordered, "forced": forced, "chain": chain}[w]()
    print(f"\nRESULT: {'ALL OK' if not FAILS else str(len(FAILS)) + ' FAILURES: ' + ', '.join(FAILS)}  ({time.time() - t0:.0f} s)")
    sys.exit(1 if FAILS else 0)
