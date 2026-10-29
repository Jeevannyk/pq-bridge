"""Wave executor + verification gate + automatic rollback.

A wave is promoted only if every gate check passes:
  trace        real TLS handshake per service: expected group / signature / chain
  compat       legacy client and classical-only probes still connect (unless PQ-only is intended)
  functional   payments keep settling, ledger keeps posting
  negative     forged / alg=none / expired JWTs and missing / rogue client certs are rejected
  overhead     handshake p95 within budget
  availability zero failed payments during the wave
Otherwise the previous configuration is restored and the rollback time is recorded.
"""
import copy
import json
import re
import time

from . import config, tasks, testbed

EVID = config.EVIDENCE
P95_BUDGET_MS = 50.0
SETTLE_S = 4


def _ca():
    return 'CA=/pki/trust/both.pem; [ -f $CA ] || CA=/pki/trust/rsa.pem; '


def handshake(svc, groups=None):
    """Real openssl s_client handshake from the toolbox. Returns parsed facts + raw trace."""
    g = f"-groups {groups} " if groups else ""
    out = testbed.tool(
        _ca() + f"echo | timeout 10 openssl s_client -connect {svc}:443 -servername {svc} -CAfile $CA "
        f"-cert /pki/certs/probe.rsa.crt -key /pki/certs/probe.rsa.key {g}-trace 2>&1", check=False).stdout

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
    for s in services:
        h = handshake(s)
        (d / f"{s}.txt").write_text(h.pop("raw"), encoding="utf-8")
        facts[s] = h
    return facts


def _expected(st, svc):
    s = st[svc]
    group = {"classical": "X25519", "hybrid": config.PQ["hybrid_group"], "pq-only": config.PQ["pq_group"]}[s["kex"]]
    cert = s["public_cert"] if svc == "gateway" else s["cert"]
    return group, (config.PQ["leaf_sig"] if cert == "pq" else "rsa_pss_rsae_sha256")


def timing(svc, n=20):
    out = testbed.tool(f"python3 /apps/probe.py timing {svc} {n}", check=False).stdout
    try:
        return json.loads(out.strip().splitlines()[-1])
    except Exception:
        return {"service": svc, "error": out[-200:]}


def negative_tests():
    out = testbed.tool("python3 /apps/probe.py negative", check=False, timeout=180).stdout
    return json.loads(out.strip().splitlines()[-1])


def _counts(tr):
    p, l, g = tr["payments"], tr["legacy"], tr["ledger"]
    return {"pay_ok": p.get("ok", 0), "pay_fail": p.get("fail", 0), "legacy_ok": l.get("ok", 0),
            "legacy_fail": l.get("fail", 0), "ledger_tx": g.get("tx_count", 0)}


def run_gate(st, pre, label):
    checks = []

    def add(category, name, passed, detail=""):
        checks.append({"category": category, "name": name, "passed": bool(passed), "detail": detail})

    after = capture_traces(label + "-after", testbed.ROLES)
    for svc, h in after.items():
        g, sig = _expected(st, svc)
        add("trace", f"{svc}: {h['group']} / {h['peer_sig']}",
            h["ok"] and h["group"] == g and h["peer_sig"] == sig,
            f"expected {g} / {sig}; verify={h['verify']}; {h['bytes_read']}B read")

    for svc in testbed.ROLES:
        legacy_h = handshake(svc, groups="X25519:P-256")
        if st[svc]["kex"] == "pq-only":
            add("negative", f"{svc}: classical-only client refused (PQ-only)", not legacy_h["ok"],
                "downgrade attempt rejected" if not legacy_h["ok"] else "classical handshake still accepted")
        else:
            add("compat", f"{svc}: classical-only client still connects", legacy_h["ok"],
                f"negotiated {legacy_h['group']}")

    for c in negative_tests():
        add("negative", f"{c['target']}: {c['case']} rejected", c["rejected"], f"{c['result']} {c['detail']}")

    times = {s: timing(s) for s in testbed.ROLES}
    for s, t in times.items():
        add("overhead", f"{s}: handshake p95 {t.get('p95_ms')} ms", t.get("p95_ms", 1e9) <= P95_BUDGET_MS,
            f"median {t.get('median_ms')} ms, budget {P95_BUDGET_MS} ms")

    post = _counts(testbed.traffic())
    d = {k: post[k] - pre[k] for k in post}
    add("compat", f"legacy customer client: {d['legacy_ok']} ok / {d['legacy_fail']} failed",
        d["legacy_fail"] == 0 and d["legacy_ok"] > 0)
    add("functional", f"payments settled during wave: {d['pay_ok']}", d["pay_ok"] > 0,
        f"ledger posted {d['ledger_tx']} tx")
    add("availability", f"failed payments during wave: {d['pay_fail']}", d["pay_fail"] == 0)
    return checks, after, times, d


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
    """Derive whether a migration task is in effect from the live crypto state."""
    kind, svc = task_id.split(".", 1)
    if task_id == "pki.pq-root":
        return st["_pki"]["pq_root"]
    if task_id == "jwt.dual-verify":
        return config.PQ["jwt_alg"] in st["payment-switch"].get("jwt_accept", [])
    if task_id == "jwt.sign-fndsa":
        return st["card-auth"].get("jwt_alg") == config.PQ["jwt_alg"]
    if task_id == "cert.gateway-public":
        return st["gateway"]["public_cert"] == "pq"
    return {"trust": st[svc]["trust"] == "both" if svc in st else False,
            "kex": st[svc]["kex"] in ("hybrid", "pq-only") if svc in st else False,
            "pqonly": st[svc]["kex"] == "pq-only" if svc in st else False,
            "cert": st[svc]["cert"] == "pq" if svc in st else False}.get(kind, False)


def run_wave(index, task_ids, label=None, log=print, auto_rollback=True):
    label = label or f"wave{index}"
    pre_state = testbed.read_state()
    pre = _counts(testbed.traffic())
    touched = sorted({tasks.TASK_BY_ID.get(t, {"service": "gateway"})["service"] for t in task_ids} & set(testbed.ROLES))
    before = capture_traces(label + "-before", touched or testbed.ROLES)
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
        rec = {"label": label, "index": index, "tasks": task_ids, "started": t0, "apply_s": round(time.time() - t0, 2),
               "passed": False, "auto_rollback": auto_rollback, "before": before, "after": {}, "timing": {},
               "checks": [{"category": "preflight",
                           "name": f"nginx rejected the new config before reload: {reason[:160]}",
                           "passed": False, "detail": str(e)[-600:]}],
               "traffic_delta": {"pay_ok": 0, "pay_fail": 0, "legacy_ok": 0, "legacy_fail": 0, "ledger_tx": 0},
               "rollback": {"restore_s": round(time.time() - t_r, 2), "healthy": True, "services": sorted(testbed.ROLES),
                            "note": "files restored; running nginx was never changed, so no traffic was affected"}}
        if label.startswith("wave") or label == "drill":
            _record(rec)
        _event({"type": "apply", **rec})
        return rec
    time.sleep(SETTLE_S)
    checks, after, times, delta = run_gate(st, pre, label)
    passed = all(c["passed"] for c in checks)
    rec = {"label": label, "index": index, "tasks": task_ids, "started": t0, "apply_s": round(time.time() - t0, 2),
           "passed": passed, "checks": checks, "before": before, "after": after, "timing": times,
           "traffic_delta": delta, "rollback": None}
    rec["auto_rollback"] = auto_rollback
    if passed:
        log(f"[{label}] gate PASSED ({len(checks)} checks) -> promoted")
        _push_history(label, task_ids, pre_state)
    else:
        failed = [c["name"] for c in checks if not c["passed"]]
        if auto_rollback:
            log(f"[{label}] gate FAILED: {failed} -> rolling back")
            rec["rollback"] = rollback(pre_state, st, changed)
            log(f"[{label}] rollback done in {rec['rollback']['restore_s']} s")
        else:
            log(f"[{label}] gate FAILED: {failed} -> LEFT IN PLACE (auto-rollback off); use Rollback last change")
            _push_history(label, task_ids, pre_state)
    if label.startswith("wave") or label == "drill":
        _record(rec)
    _event({"type": "apply", **rec})
    return rec


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
    log(f"[rollback] done in {info['restore_s']} s, traffic healthy: {info['healthy']}")
    rec = {"type": "rollback", "label": f"rollback of {entry['label']}", "tasks": entry["tasks"], "rollback": info}
    _event(rec)
    return rec


def gate_now(log=print, window_s=SETTLE_S):
    """Run every gate check against the CURRENT state, without changing anything."""
    st = testbed.read_state()
    pre = _counts(testbed.traffic())
    label = f"gate-{time.strftime('%H%M%S')}"
    log(f"[{label}] running verification gate on current state ({window_s}s traffic window)")
    time.sleep(window_s)
    checks, after, times, delta = run_gate(st, pre, label)
    passed = all(c["passed"] for c in checks)
    log(f"[{label}] {'ALL PASS' if passed else 'FAILURES: ' + str([c['name'] for c in checks if not c['passed']])}")
    rec = {"type": "gate", "label": label, "tasks": [], "passed": passed, "checks": checks, "before": {},
           "after": after, "timing": times, "traffic_delta": delta, "rollback": None}
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
    base = _counts(testbed.traffic())
    healthy_at = None
    while time.time() - t0 < 20:
        now = _counts(testbed.traffic())
        if now["legacy_ok"] > base["legacy_ok"] and now["pay_ok"] > base["pay_ok"]:
            healthy_at = time.time()
            break
        time.sleep(0.5)
    return {"restore_s": round((healthy_at or time.time()) - t0, 2), "healthy": healthy_at is not None,
            "services": sorted(changed)}
