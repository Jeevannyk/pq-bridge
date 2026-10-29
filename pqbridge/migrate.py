"""Wave executor + verification gate + automatic rollback.

A change is promoted only if every gate check passes:
  trace        real TLS handshake per node (incl. postgres:5432 and the clearing house): expected group / signature / chain
  compat       classical-only clients still connect (unless PQ-only is intended); legacy customer app still works
  business     login issues tokens with the expected algorithm, JWKS, accounts, a transfer posts and its retry is a
               replay, money conserved, journal balanced, audit chain verifies, settlement accepted by the clearing house
  negative     forged / alg=none / expired / foreign-issuer / under-scoped tokens, someone else's account, overdraft,
               missing Idempotency-Key, unauthorised KMS and ledger calls, missing or rogue client certs: all refused
  overhead     handshake p95 within budget
  availability a customer using the bank DURING the change (sign-in, balance reads, payments, with NetBank's own
               retry rules) loses nothing; real customers' requests served by the gateway show no server errors
A fast end-to-end canary runs right after the reload: if the customer path is broken the change is rolled back at once,
without waiting for the full gate. Otherwise the previous configuration is restored and the rollback time is recorded.
Payments survive the broken window: the payments service stores a transfer first and keeps retrying the ledger (see
testbed/apps/payments.py), and NetBank retries with the same Idempotency-Key, so a customer's payment still completes.
"""
import copy
import json
import re
import subprocess
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from . import config, tasks, testbed

EVID = config.EVIDENCE
P95_BUDGET_MS = 50.0
SETTLE_S = 2      # customers keep paying through the change; the gate's own checks take a few more seconds on top


def _ca():
    return 'CA=/pki/trust/both.pem; [ -f $CA ] || CA=/pki/trust/rsa.pem; '


def _s_client(svc, g, sink=""):
    port = 5432 if svc == "postgres" else 443
    return (f"echo | timeout 10 openssl s_client -connect {svc}:{port} -servername {svc} -CAfile $CA "
            f"-cert /pki/certs/probe.rsa.crt -key /pki/certs/probe.rsa.key {g}-trace {sink}2>&1")


def handshake(svc, groups=None):
    """Real openssl s_client handshake from the toolbox. Returns parsed facts + raw trace."""
    g = f"-groups {groups} " if groups else ""
    return _parse_handshake(svc, testbed.tool(_ca() + _s_client(svc, g), check=False).stdout)


def handshakes(services, groups=None):
    """The same real handshakes to many services at once: one toolbox exec, every openssl s_client side by side.
    A docker exec costs ~0.25 s, so this beats one exec per service by a wide margin. Returns {service: facts + raw}."""
    g = f"-groups {groups} " if groups else ""
    tag = uuid.uuid4().hex[:8]                      # batches run at the same time: each needs its own scratch files
    run = "".join(f"( {_s_client(s, g, f'> /tmp/hs.{tag}.{s} ')} ) & " for s in services)
    show = "".join(f"echo '@@@{s}'; cat /tmp/hs.{tag}.{s}; " for s in services)
    out = testbed.tool(_ca() + run + "wait; " + show + f"rm -f /tmp/hs.{tag}.*", check=False).stdout
    chunks = dict(re.findall(r"@@@(\S+)\n(.*?)(?=@@@\S+\n|\Z)", out, re.S))
    return {s: _parse_handshake(s, chunks.get(s, "")) for s in services}


def _parse_handshake(svc, out):
    def find(rx):
        m = re.search(rx, out)
        return m.group(1) if m else None
    rd = re.search(r"handshake has read (\d+) bytes and written (\d+) bytes", out)
    return {
        "service": svc,
        "group": find(r"Negotiated TLS1\.3 group: (\S+)") or find(r"(?:Peer|Server) Temp Key: (\w+)"),
        "peer_sig": find(r"Peer signature type: (\S+)"),
        "protocol": find(r"Protocol: (\S+)"),
        "verify": find(r"Verify return code: (\d+)"),
        "bytes_read": int(rd.group(1)) if rd else None,
        "bytes_written": int(rd.group(2)) if rd else None,
        "ok": "Verify return code: 0" in out and "Cipher is (NONE)" not in out and "Peer signature type" in out,
        "raw": out,
    }


def capture_traces(label, services):
    d = EVID / "traces" / label
    d.mkdir(parents=True, exist_ok=True)
    facts = {}
    for s, h in handshakes(services).items():
        (d / f"{s}.txt").write_text(h.pop("raw"), encoding="utf-8")
        facts[s] = h
    return facts


def _expected(st, svc):
    s = st[svc]
    group = {"classical": "X25519", "hybrid": config.PQ["hybrid_group"], "pq-only": config.PQ["pq_group"]}[s["kex"]]
    cert = s["public_cert"] if svc == "gateway" else s["cert"]
    return group, (config.PQ["leaf_sig"] if cert == "pq" else "rsa_pss_rsae_sha256")


def timings(services, n=20, parallel=3):
    """Handshake latency per service. One exec, `parallel` services at a time: a few at once, so the latency measured stays honest."""
    out = testbed.tool(f"printf '%s\\n' {' '.join(services)} | xargs -P{parallel} -I{{}} python3 /apps/probe.py timing {{}} {n}", check=False).stdout
    found = {}
    for line in out.splitlines():
        try:
            d = json.loads(line)
            found[d["service"]] = d
        except Exception:
            pass
    return {s: found.get(s) or {"service": s, "error": out[-200:]} for s in services}


def negative_tests():
    out = testbed.tool("python3 /apps/probe.py negative", check=False, timeout=240).stdout
    return json.loads(out.strip().splitlines()[-1])


def business_tests(st):
    exp = {"jwt_alg": st["identity"]["jwt_alg"], "jwt_publish": st["identity"]["jwt_publish"],
           "audit_alg": st["ledger"]["audit_alg"], "settle_alg": st["settlement"]["settle_alg"]}
    out = testbed.tool(f"python3 /apps/probe.py business '{json.dumps(exp)}'", check=False, timeout=240).stdout
    try:
        return json.loads(out.strip().splitlines()[-1])
    except Exception:
        return [{"case": "business checks ran", "passed": False, "detail": out[-300:]}]


def _legacy():
    l = testbed.read_json("legacy.json")
    return {"legacy_ok": l.get("ok", 0), "legacy_fail": l.get("fail", 0)}


class Window:
    """A customer using the bank while a change happens: balance reads and one-paisa payments through the public
    gateway, with NetBank's own retry rules (see probe.py window). Runs only for the length of a change."""

    def __init__(self, wait=True):
        self.wait = wait

    def __enter__(self):
        testbed.tool("rm -f /tmp/window.stop /tmp/window.json", check=False)
        self.t0, self.final = time.time(), None
        self.p = subprocess.Popen(testbed.COMPOSE + ["exec", "-T", "toolbox", "python3", "/apps/probe.py", "window", "900"],
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace")
        if self.wait:
            self.ready()
        return self

    def ready(self):
        """Block until the customer is signed in and running (first progress file)."""
        for _ in range(60):
            if self.snapshot().get("ops") is not None:
                break
            time.sleep(0.1)

    def snapshot(self):
        p = testbed.tool("cat /tmp/window.json", check=False, timeout=30)
        try:
            return json.loads(p.stdout)
        except Exception:
            return {}

    def stop(self):
        if self.final is None:
            testbed.tool("touch /tmp/window.stop", check=False)
            try:
                out, _ = self.p.communicate(timeout=100)
            except subprocess.TimeoutExpired:
                self.p.kill()
                out = ""
            try:
                self.final = json.loads(out.strip().splitlines()[-1])
            except Exception:
                self.final = self.snapshot()
        return self.final

    def __exit__(self, *exc):
        self.stop()


def canary(tries=3, pause=1.0):
    """Fast end-to-end customer path (sign in, read, pay one paisa, retry it). Retried briefly to ride out the reload."""
    last = {}
    for i in range(tries):
        p = testbed.tool("python3 /apps/probe.py canary", check=False, timeout=90)
        try:
            last = json.loads(p.stdout.strip().splitlines()[-1])
        except Exception:
            last = {"ok": False, "steps": [{"name": "canary ran", "ok": False, "detail": (p.stdout + p.stderr)[-200:]}]}
        if last.get("ok"):
            return last
        if i < tries - 1:
            time.sleep(pause)
    return last


def _canary_checks(cv):
    return [{"category": "canary", "name": x["name"], "passed": x["ok"], "detail": x["detail"]} for x in cv["steps"]]


def _availability_checks(snap, cust, label="during the change"):
    ops, bad, errs = snap.get("ops", 0), snap.get("failed", 0), snap.get("errors") or {}
    return [
        {"category": "availability", "passed": ops > 0 and bad == 0,
         "name": f"customer path {label}: {snap.get('ok', 0)} of {ops} requests succeeded ({snap.get('payments', 0)} payments, "
                 f"{snap.get('retried', 0)} needed a retry, slowest {snap.get('max_s', 0)} s)",
         "detail": "; ".join(f"{k} x{v}" for k, v in errs.items()) or "no customer-visible failure"},
        {"category": "availability", "passed": cust["errors_5xx"] == 0,
         "name": f"real customers {label}: {cust['requests']} requests served, {cust['errors_5xx']} server errors",
         "detail": "; ".join(f"{k} x{v}" for k, v in cust["failed"].items()) or "no server errors"}]


def _traffic_delta(final, cust, legacy_pre):
    l = _legacy()
    return {"probe_ops": final.get("ops", 0), "probe_ok": final.get("ok", 0), "probe_failed": final.get("failed", 0),
            "probe_retried": final.get("retried", 0), "probe_max_s": final.get("max_s", 0), "probe_payments": final.get("payments", 0),
            "customer_requests": cust["requests"], "customer_payments": cust["payments"], "customer_5xx": cust["errors_5xx"],
            "legacy_ok": l["legacy_ok"] - legacy_pre["legacy_ok"], "legacy_fail": l["legacy_fail"] - legacy_pre["legacy_fail"]}


def run_gate(st, legacy_pre, label, win):
    checks = []

    def add(category, name, passed, detail=""):
        checks.append({"category": category, "name": name, "passed": bool(passed), "detail": detail})

    # Four independent probes (each one docker exec) run side by side; the timing check goes last, on a quiet bank.
    with ThreadPoolExecutor(max_workers=4) as ex:
        f_after = ex.submit(capture_traces, label + "-after", testbed.ROLES)
        f_legacy = ex.submit(handshakes, testbed.ROLES, "X25519:P-256")
        f_biz, f_neg = ex.submit(business_tests, st), ex.submit(negative_tests)
        after, legacy, biz, neg = f_after.result(), f_legacy.result(), f_biz.result(), f_neg.result()
    for svc, h in after.items():
        g, sig = _expected(st, svc)
        add("trace", f"{svc}: {h['group']} / {h['peer_sig']}",
            h["ok"] and h["group"] == g and h["peer_sig"] == sig,
            f"expected {g} / {sig}; verify={h['verify']}; {h['bytes_read']}B read")

    for svc in testbed.ROLES:
        legacy_h = legacy[svc]
        if st[svc]["kex"] == "pq-only":
            add("negative", f"{svc}: classical-only client refused (PQ-only)", not legacy_h["ok"],
                "downgrade attempt rejected" if not legacy_h["ok"] else "classical handshake still accepted")
        else:
            add("compat", f"{svc}: classical-only client still connects", legacy_h["ok"],
                f"negotiated {legacy_h['group']}")

    for c in biz:
        add("business", c["case"], c["passed"], c["detail"])
    for c in neg:
        add("negative", f"{c['target']}: {c['case']} refused", c["rejected"], c["detail"])

    times = timings(testbed.ROLES)
    for s, t in times.items():
        add("overhead", f"{s}: handshake p95 {t.get('p95_ms')} ms", t.get("p95_ms", 1e9) <= P95_BUDGET_MS,
            f"median {t.get('median_ms')} ms, budget {P95_BUDGET_MS} ms")

    l = _legacy()
    d_ok, d_fail = l["legacy_ok"] - legacy_pre["legacy_ok"], l["legacy_fail"] - legacy_pre["legacy_fail"]
    add("compat", f"legacy customer client: {d_ok} ok / {d_fail} failed", d_fail == 0 and d_ok > 0)
    checks.extend(_availability_checks(win.snapshot(), testbed.customer_traffic(win.t0)))
    return checks, after, times


def _record(rec):
    EVID.mkdir(parents=True, exist_ok=True)
    with open(EVID / "waves.jsonl", "a") as f:
        f.write(json.dumps(rec) + "\n")


def _event(rec):
    """Every operator action (wave, manual apply, gate run, rollback, probe) for the activity log."""
    EVID.mkdir(parents=True, exist_ok=True)
    with open(EVID / "events.jsonl", "a") as f:
        f.write(json.dumps({**rec, "ts": time.time()}) + "\n")


# ---------------------------------------------------------------- change history (manual rollback)
def _hist_path():
    return config.STATE / "history.json"


def history():
    try:
        return json.loads(_hist_path().read_text())
    except Exception:
        return []


def _push_history(label, task_ids, pre_state):
    h = history()
    h.append({"label": label, "tasks": task_ids, "pre_state": pre_state, "ts": time.time()})
    _hist_path().write_text(json.dumps(h))


def task_done(task_id, st):
    """Whether a migration task is in effect, from the live crypto state and the key material on disk."""
    t = tasks.TASK_BY_ID.get(task_id) or (tasks.DEFERRED_TASK if task_id == tasks.DEFERRED_TASK["id"] else None)
    return bool(t) and tasks.done(t, st)


def run_wave(index, task_ids, label=None, log=print, auto_rollback=True):
    with Window(wait=False) as win:
        return _run_wave(index, task_ids, label, log, auto_rollback, win)


def _finish(rec, label):
    if label.startswith("wave") or label == "drill":
        _record(rec)
    _event({"type": "apply", **rec})
    return rec


def _run_wave(index, task_ids, label, log, auto_rollback, win):
    label = label or f"wave{index}"
    pre_state = testbed.read_state()
    legacy_pre = _legacy()
    defs = [tasks.TASK_BY_ID.get(t) or tasks.DEFERRED_TASK for t in task_ids]
    touched = sorted({svc for d in defs for svc in list(d["sets"]) + list(d["adds"])} & set(testbed.ROLES))
    before = capture_traces(label + "-before", touched or testbed.ROLES)       # runs while the customer signs in
    win.ready()
    log(f"[{label}] applying {task_ids}")

    st = copy.deepcopy(pre_state)
    changed = set()
    t0 = time.time()
    try:
        for t in task_ids:
            changed.update(tasks.apply(t, st))
        testbed.apply_state(st, sorted(changed))
    except Exception as e:
        # Preflight failure: nginx -t (or openssl) refused the change, e.g. a certificate file that does not
        # exist because its prerequisite was never applied. The running nginx kept its old config, but the
        # state and .conf files on disk were already rewritten, so put every service's files back.
        reason = str(e).strip().splitlines()
        reason = next((l for l in reason if "emerg" in l or "Error" in l or "error" in l), reason[-1] if reason else str(e))
        m = re.search(r'cannot load certificate "(/pki/[^"]+)"', str(e))
        if m:
            reason = (f"{m.group(1)} does not exist yet. Apply pki.pq-root first: it issues the SLH-DSA root, "
                      "the FN-DSA certificates and the trust bundle")
        log(f"[{label}] PREFLIGHT FAILED: {reason[:200]} -> restoring files, running config was never replaced")
        t_r = time.time()
        restored = copy.deepcopy(pre_state)
        restored["_pki"] = st["_pki"]
        testbed.apply_state(restored, list(testbed.ROLES))
        final = win.stop()
        rec = {"label": label, "index": index, "tasks": task_ids, "started": t0, "apply_s": round(time.time() - t0, 2),
               "passed": False, "auto_rollback": auto_rollback, "before": before, "after": {}, "timing": {},
               "checks": [{"category": "preflight",
                           "name": f"nginx rejected the new config before reload: {reason[:160]}",
                           "passed": False, "detail": str(e)[-600:]}]
                         + _availability_checks(final, testbed.customer_traffic(win.t0), "while the change was refused"),
               "traffic_delta": _traffic_delta(final, testbed.customer_traffic(win.t0), legacy_pre),
               "rollback": {"restore_s": round(time.time() - t_r, 2), "healthy": True, "services": sorted(testbed.ROLES),
                            "note": "files restored; running nginx was never changed, so no traffic was affected"}}
        return _finish(rec, label)

    # Fast canary before the slow gate: if the customer path is broken, every second counts.
    cv = canary()
    canary_checks = _canary_checks(cv)
    if not cv["ok"] and auto_rollback:
        failed = [c["name"] for c in canary_checks if not c["passed"]]
        log(f"[{label}] customer-path canary FAILED right after the change: {failed} -> rolling back at once")
        rb = rollback(pre_state, st, changed)
        log(f"[{label}] rollback done in {rb['restore_s']} s, customer path healthy: {rb['healthy']}")
        final = win.stop()
        cust = testbed.customer_traffic(win.t0)
        rec = {"label": label, "index": index, "tasks": task_ids, "started": t0, "apply_s": round(time.time() - t0, 2),
               "passed": False, "checks": canary_checks + _availability_checks(final, cust, "through the failed change and its rollback"),
               "before": before, "after": {}, "timing": {}, "traffic_delta": _traffic_delta(final, cust, legacy_pre),
               "rollback": rb, "auto_rollback": True, "stopped_by": "canary"}
        return _finish(rec, label)

    time.sleep(SETTLE_S)
    checks, after, times = run_gate(st, legacy_pre, label, win)
    checks = canary_checks + checks
    passed = all(c["passed"] for c in checks)
    rb = None
    if passed:
        log(f"[{label}] gate PASSED ({len(checks)} checks) -> promoted")
        _push_history(label, task_ids, pre_state)
    else:
        failed = [c["name"] for c in checks if not c["passed"]]
        if auto_rollback:
            log(f"[{label}] gate FAILED: {failed} -> rolling back")
            rb = rollback(pre_state, st, changed)
            log(f"[{label}] rollback done in {rb['restore_s']} s")
        else:
            log(f"[{label}] gate FAILED: {failed} -> LEFT IN PLACE (auto-rollback off); use Rollback last change")
            _push_history(label, task_ids, pre_state)
    final = win.stop()
    cust = testbed.customer_traffic(win.t0)
    if rb:
        checks = checks + _availability_checks(final, cust, "through the failed change and its rollback")
    rec = {"label": label, "index": index, "tasks": task_ids, "started": t0, "apply_s": round(time.time() - t0, 2),
           "passed": passed, "checks": checks, "before": before, "after": after, "timing": times,
           "traffic_delta": _traffic_delta(final, cust, legacy_pre), "rollback": rb, "auto_rollback": auto_rollback}
    return _finish(rec, label)


def rollback_last(log=print):
    """Operator-triggered rollback: restore the crypto state from before the most recent change."""
    h = history()
    if not h:
        raise RuntimeError("nothing to roll back: no applied change in history")
    entry = h.pop()
    cur = testbed.read_state()
    changed = [s for s in testbed.ROLES if cur.get(s) != entry["pre_state"].get(s)]
    log(f"[rollback] restoring state from before '{entry['label']}' ({', '.join(entry['tasks'])}); services: {changed}")
    info = rollback(entry["pre_state"], cur, changed or testbed.ROLES)
    _hist_path().write_text(json.dumps(h))
    log(f"[rollback] done in {info['restore_s']} s, customer path healthy: {info['healthy']}")
    rec = {"type": "rollback", "label": f"rollback of {entry['label']}", "tasks": entry["tasks"], "rollback": info}
    _event(rec)
    return rec


def gate_now(log=print, window_s=SETTLE_S):
    """Run every gate check against the CURRENT state, without changing anything."""
    st = testbed.read_state()
    legacy_pre = _legacy()
    label = f"gate-{time.strftime('%H%M%S')}"
    log(f"[{label}] running verification gate on current state ({window_s}s customer window)")
    with Window() as win:
        time.sleep(window_s)
        checks, after, times = run_gate(st, legacy_pre, label, win)
        final = win.stop()
    canary_checks = _canary_checks(canary(tries=1))
    checks = canary_checks + checks
    passed = all(c["passed"] for c in checks)
    log(f"[{label}] {'ALL PASS' if passed else 'FAILURES: ' + str([c['name'] for c in checks if not c['passed']])}")
    rec = {"type": "gate", "label": label, "tasks": [], "passed": passed, "checks": checks, "before": {},
           "after": after, "timing": times, "traffic_delta": _traffic_delta(final, testbed.customer_traffic(win.t0), legacy_pre),
           "rollback": None}
    _event(rec)
    return rec


def probe(svc, groups=None):
    """One live handshake against a service; saves the full trace."""
    h = handshake(svc, groups=groups)
    label = f"probe-{time.strftime('%H%M%S')}"
    d = EVID / "traces" / label
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{svc}.txt").write_text(h.pop("raw"), encoding="utf-8")
    return {**h, "trace_label": label, "offered_groups": groups or "client default (x25519_hqc1:X25519:P-256:hqc1)"}


def events(limit=40):
    try:
        rows = [json.loads(l) for l in (EVID / "events.jsonl").read_text().splitlines() if l.strip()]
    except Exception:
        rows = []
    return rows[-limit:][::-1]


def rollback(pre_state, st, changed):
    t0 = time.time()
    restored = copy.deepcopy(pre_state)
    restored["_pki"] = st["_pki"]          # new PKI material is additive; keep it
    testbed.apply_state(restored, sorted(changed))
    healthy_at = None
    while time.time() - t0 < 40:
        if canary(tries=1)["ok"]:           # a customer can sign in, read and pay again
            healthy_at = time.time()
            break
        time.sleep(0.5)
    return {"restore_s": round((healthy_at or time.time()) - t0, 2), "healthy": healthy_at is not None,
            "services": sorted(changed)}
