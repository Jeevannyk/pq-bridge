"""Live end-to-end test: a real NetBank customer keeps paying while crypto migrations are applied, fail and roll back.

Needs the bank running (python -m pqbridge / dev.ps1) and a fresh classical state. Run:  python tests/live_payments.py

  A  baseline        a payment posts, the same Idempotency-Key replays instead of paying twice
  B  good migration  customer pays continuously while kex.gateway is applied: every payment succeeds
  C  bad migration   pki.pq-root, then cert.payments is FORCED out of order with auto-rollback on: the canary rolls it
                     back at once, the customer's payments all still succeed
  D  bad migration   the same forced change (cert.payments, then cert.ledger) with auto-rollback OFF (the bank stays broken for a while), then the operator
                     rolls it back: payments made while it was broken FAIL CLEANLY (NetBank shows the red cross); a payment
                     the customer was told failed is never posted afterwards, none is left pending, none paid twice
  E  integrity       money conserved, journal balanced, audit chain verifies, posted transfers == audit entries

The customer behaves exactly like NetBank (netbank/frontend/app.js): retry quietly for at most 20 s while the bank does
not answer (connection lost, 502/503/504) with the same Idempotency-Key, re-ask while the answer is "processing", then
show "failed" (confirmed by the bank, or unconfirmed when the bank never answered).
"""
import json
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BANK = "https://localhost:8443"
CONSOLE = "http://127.0.0.1:8000"
CTX = ssl.create_default_context(cafile=str(ROOT / "testbed/runtime/pki/rsa-root.crt"))
USER, PASS, SRC, DST = "vamsh", "vamsh", "ACC-0004", "ACC-0006"     # Vamsh's savings -> Rahul's savings
results = []
MEMO = "live test " + uuid.uuid4().hex[:8]


def check(name, ok, detail=""):
    results.append(bool(ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail else ""), flush=True)


def call(method, url, body=None, headers=None, ctx=CTX, timeout=100):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {"error": f"HTTP {e.code}"}
    except Exception as e:                                   # connection lost / reset / timeout
        return 0, {"error": type(e).__name__}


def console(method, path, body=None):
    return call(method, CONSOLE + path, body, ctx=None, timeout=900)


class Customer:
    """NetBank's client rules, in Python."""

    def __init__(self):
        self.tok = None
        self.keys, self.log, self.stop, self.lock = [], [], threading.Event(), threading.Lock()

    def sign_in(self):
        c, r = self.retry(lambda: call("POST", BANK + "/api/auth/login", {"username": USER, "password": PASS}))
        assert c == 200, (c, r)
        self.tok = r["access_token"]

    def retry(self, fn, until=None):
        until = until or time.time() + 45
        delay = 0.4
        while True:
            c, r = fn()
            if c not in (0, 502, 503, 504) or time.time() > until:
                return c, r
            time.sleep(delay)
            delay = min(delay * 1.6, 2.5)

    def pay(self, amount=100):
        key = uuid.uuid4().hex
        body = {"from_account": SRC, "to_account": DST, "amount": amount, "memo": MEMO}
        t0 = time.time()

        until = t0 + 20

        def go():
            return call("POST", BANK + "/api/payments/transfers", body, {"Authorization": "Bearer " + self.tok, "Idempotency-Key": key})
        c, r = self.retry(go, until)
        if c == 401:                                         # token expired: refresh by signing in again
            self.sign_in()
            c, r = self.retry(go, until)
        while r.get("status") == "processing" and time.time() < until:
            time.sleep(1.5)
            c, r = self.retry(go, until)
        st = r.get("status")
        outcome = "posted" if st == "posted" else "failed" if st == "failed" else "unconfirmed" if (c == 0 or c >= 500 or st == "processing") else (st or "error")
        with self.lock:
            self.keys.append(key)
            self.log.append({"key": key, "code": c, "status": st, "outcome": outcome, "secs": round(time.time() - t0, 2)})
        return c, r

    def run(self, every=0.4):
        while not self.stop.is_set():
            self.pay()
            time.sleep(every)

    def summary(self):
        ok = [x for x in self.log if x["outcome"] == "posted"]
        told_failed = [x for x in self.log if x["outcome"] in ("failed", "unconfirmed")]
        return {"payments": len(self.log), "succeeded": len(ok), "failed": [x for x in self.log if x not in ok],
                "told_failed": told_failed, "confirmed_failed": sum(x["outcome"] == "failed" for x in self.log),
                "slow": sum(x["secs"] > 3 for x in self.log), "slowest": max([x["secs"] for x in self.log] or [0])}


def with_customer(action):
    """Run `action()` while a customer pays continuously; return (action result, summary)."""
    cust = Customer()
    cust.sign_in()
    t = threading.Thread(target=cust.run, daemon=True)
    t.start()
    time.sleep(3)                                           # some payments before the change
    out = action()
    time.sleep(3)                                           # and some after
    cust.stop.set()
    t.join(timeout=130)
    return out, cust


def bank_state():
    return json.loads((ROOT / "testbed/runtime/state/services.json").read_text())


def sql(q):
    import subprocess
    p = subprocess.run(["docker", "compose", "-f", str(ROOT / "testbed/docker-compose.yml"), "exec", "-T", "postgres", "psql", "-h",
                        "/run/postgresql", "-p", "5433", "-U", "bank", "-d", "bank", "-At", "-c", q], capture_output=True, text=True)
    return p.stdout.strip()


def main():
    st = console("GET", "/api/status")[1]
    if st.get("busy"):
        sys.exit(f"console is busy: {st['busy']}")
    print("A. baseline: one real payment and its replay")
    cust = Customer()
    cust.sign_in()
    key = uuid.uuid4().hex
    h = {"Authorization": "Bearer " + cust.tok, "Idempotency-Key": key}
    body = {"from_account": SRC, "to_account": DST, "amount": 12345, "memo": MEMO}
    c1, r1 = call("POST", BANK + "/api/payments/transfers", body, h)
    c2, r2 = call("POST", BANK + "/api/payments/transfers", body, h)
    check("payment posts (201)", c1 == 201 and r1.get("status") == "posted", f"{c1} {r1.get('reference')}")
    check("same Idempotency-Key replays (200, same transfer), not a second payment",
          c2 == 200 and r2.get("replayed") and r2.get("transfer_id") == r1.get("transfer_id"))
    check("no customer traffic needed to run the bank: no load generator container",
          "loadgen" not in json.dumps(console("GET", "/api/dashboard")[1]["containers"]))

    tasks = {t["id"]: t["status"] for t in console("GET", "/api/tasks")[1]["tasks"]}
    good = "kex.gateway" if tasks.get("kex.gateway") == "ready" else next(t for t, st in tasks.items() if st == "ready" and t.startswith(("kex.", "trust.")))
    print(f"B. good migration ({good}) while the customer pays")
    (rec, cust) = with_customer(lambda: console("POST", "/api/apply", {"tasks": [good], "auto_rollback": True})[1])
    s = cust.summary()
    check("migration promoted by the gate", rec.get("passed") is True, f"{len(rec.get('checks', []))} checks")
    check("every payment during the change succeeded", not s["failed"] and s["succeeded"] > 0,
          f"{s['succeeded']}/{s['payments']} ok, {s['slow']} slow, slowest {s['slowest']} s")
    check("gate saw no customer-visible failure", rec["traffic_delta"]["probe_failed"] == 0 and rec["traffic_delta"]["customer_5xx"] == 0,
          f"probe {rec['traffic_delta']['probe_ok']}/{rec['traffic_delta']['probe_ops']}, real customers {rec['traffic_delta']['customer_requests']}")
    keys = [key] + list(cust.keys)

    print("C. bad migration, auto-rollback ON: cert.payments forced before its trust prerequisites")
    if tasks.get("pki.pq-root") != "applied":
        r, _ = console("POST", "/api/apply", {"tasks": ["pki.pq-root"], "auto_rollback": True})
        check("prerequisite pki.pq-root promoted", r == 200)
    before = bank_state()["payments"]["cert"]
    (rec, cust) = with_customer(lambda: console("POST", "/api/apply", {"tasks": ["cert.payments"], "auto_rollback": True, "force": True})[1])
    s = cust.summary()
    check("the broken change was stopped by the customer-path canary and rolled back",
          rec.get("passed") is False and rec.get("rollback") and rec.get("stopped_by") == "canary", f"restored in {(rec.get('rollback') or {}).get('restore_s')} s")
    check("payments config is back to the original", bank_state()["payments"]["cert"] == before)
    check("every payment made while the bank was broken still succeeded", not s["failed"] and s["succeeded"] > 0,
          f"{s['succeeded']}/{s['payments']} ok, {s['slow']} slow, slowest {s['slowest']} s")
    check("the gate recorded zero customer-visible failures through the failure and rollback",
          rec["traffic_delta"]["probe_failed"] == 0, f"{rec['traffic_delta']['probe_ok']}/{rec['traffic_delta']['probe_ops']} ok, "
          f"{rec['traffic_delta']['probe_retried']} retried")
    keys += cust.keys

    for task in ("cert.payments", "cert.ledger"):        # bank unreachable / bank reachable but ledger broken
        print(f"D. bad migration {task}, auto-rollback OFF, operator rolls it back")
        holder = {}

        def broken_then_fixed():
            t = threading.Thread(target=lambda: holder.update(rec=console("POST", "/api/apply",
                                 {"tasks": [task], "auto_rollback": False, "force": True})[1]))
            t.start()
            t.join(timeout=300)
            holder["rb"] = console("POST", "/api/rollback")[1]
            return holder
        (_, cust) = with_customer(broken_then_fixed)
        s = cust.summary()
        check("the bad change was left in place until the operator rolled it back", holder["rec"].get("rollback") is None and holder["rec"].get("passed") is False)
        check("operator rollback restored the customer path", holder["rb"].get("rollback", {}).get("healthy") is True,
              f"{holder['rb'].get('rollback', {}).get('restore_s')} s")
        time.sleep(16)                                           # the bank settles or fails anything still pending within 13 s
        done = sql("SELECT count(*) FROM transfers WHERE status='pending'")
        check("no payment is left pending after recovery", done == "0", f"pending={done}")
        check(f"{task}: payments made while the bank was broken failed cleanly (red cross shown to the customer)", len(s["told_failed"]) > 0,
              f"{s['succeeded']} ok, {len(s['told_failed'])} shown as failed ({s['confirmed_failed']} confirmed by the bank), slowest {s['slowest']} s")
        bykey = dict(r.split("|") for r in sql(f"SELECT idem_key, status FROM transfers WHERE memo='{MEMO}'").splitlines())
        leaked = [x["key"] for x in s["told_failed"] if bykey.get(x["key"]) == "posted"]
        check("a payment the customer was told failed never posted afterwards", not leaked, f"{len(leaked)} of {len(s['told_failed'])} posted anyway")
        lost = [x["key"] for x in cust.log if x["outcome"] == "posted" and bykey.get(x["key"]) != "posted"]
        check("every payment the customer saw succeed is posted", not lost, f"{len(lost)} missing")
        keys += cust.keys
    

    print("E. integrity")
    dash = console("GET", "/api/dashboard")[1]
    check("money conserved, journal balanced", dash["ledger"].get("money_conserved") and dash["ledger"].get("journal_balanced"))
    check("audit chain and signatures verify", console("POST", "/api/audit/verify")[1].get("ok") is True)
    posted = sql(f"SELECT count(*) FROM transfers WHERE memo='{MEMO}' AND status='posted'")
    stored = sql(f"SELECT count(*) FROM transfers WHERE memo='{MEMO}'")
    rejected = sql(f"SELECT count(*) FROM transfers WHERE memo='{MEMO}' AND status='rejected'")
    check("every stored payment is either posted or cleanly failed", int(posted) + int(rejected) == int(stored), f"{posted} posted + {rejected} failed = {stored} stored")
    check("nothing paid twice: at most one transfer per payment attempt", int(stored) <= len(keys), f"{stored} stored for {len(keys)} attempts")
    ledger_rows = sql(f"SELECT count(*) FROM audit_log a JOIN transfers t ON t.id=a.transfer_id WHERE t.memo='{MEMO}'")
    check("every posted payment has exactly one audit entry, failed ones have none", ledger_rows == posted, f"{ledger_rows} audit entries")

    ok = all(results)
    print(f"\n{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
