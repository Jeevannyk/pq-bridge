"""Security-admin dashboard: one live view of the bank (services, customers, money, crypto posture, migration
progress, integrity, alerts). Read-only. Every number comes from the running bank: container status, the bank
database, the ledger and the live service crypto state. Automated test accounts are excluded."""
import base64
import json
import time

from . import migrate, pipeline, testbed

CACHE_S = 3
_cache = (0.0, None)

# service -> (title, what it does, group)
ROLES = {
    "gateway": ("Public gateway", "TLS for customers, rate limiting, routing, hosts NetBank", "bank"),
    "identity": ("Identity", "Sign-in, access and refresh tokens, JWKS", "bank"),
    "accounts": ("Accounts", "Balances, statements, payees, profile", "bank"),
    "payments": ("Payments", "Transfers, limits, fraud rule, idempotency", "bank"),
    "ledger": ("Ledger", "Double-entry books, signed audit log", "bank"),
    "kms": ("KMS", "Holds and uses every signing key", "bank"),
    "settlement": ("Settlement", "Signed end-of-day batches to the clearing house", "bank"),
    "postgres": ("Database", "PostgreSQL, reachable only over mTLS", "bank"),
}
ORDER = list(ROLES)

# The verification gate's accounts are excluded: only people using NetBank count.
BOTS = r"^gate(test|peer|poor)$"
SQL = r"""
WITH rc AS (SELECT * FROM customers WHERE username !~ '__BOTS__'),
     ra AS (SELECT a.* FROM accounts a JOIN rc ON rc.id = a.customer_id),
     rt AS (SELECT * FROM transfers WHERE customer_id IN (SELECT id FROM rc)),
     named AS (SELECT a.id AS acct, c.full_name FROM accounts a JOIN customers c ON c.id = a.customer_id)
SELECT json_build_object(
 'customers', (SELECT json_build_object(
    'total', count(*),
    'active_24h', count(*) FILTER (WHERE last_login > extract(epoch from now()) - 86400),
    'locked', count(*) FILTER (WHERE locked_until > extract(epoch from now())),
    'failed_attempts', COALESCE(sum(failed), 0)) FROM rc),
 'sessions', (SELECT count(*) FROM refresh_tokens WHERE expires > extract(epoch from now()) AND customer_id IN (SELECT id FROM rc)),
 'payees', (SELECT count(*) FROM payees WHERE customer_id IN (SELECT id FROM rc)),
 'excluded_bots', (SELECT count(*) FROM customers WHERE username ~ '__BOTS__'),
 'accounts', (SELECT json_build_object('total', count(*),
    'savings', count(*) FILTER (WHERE type = 'Savings'), 'current', count(*) FILTER (WHERE type = 'Current'),
    'balance', COALESCE(sum(balance), 0)::bigint) FROM ra),
 'transfers', (SELECT json_build_object(
    'posted', count(*) FILTER (WHERE status = 'posted'), 'held', count(*) FILTER (WHERE status = 'held'),
    'rejected', count(*) FILTER (WHERE status = 'rejected'),
    'volume', COALESCE(sum(amount) FILTER (WHERE status = 'posted'), 0)::bigint,
    'largest', COALESCE(max(amount) FILTER (WHERE status = 'posted'), 0)::bigint,
    'last_hour', count(*) FILTER (WHERE status = 'posted' AND created > extract(epoch from now()) - 3600),
    'volume_last_hour', COALESCE(sum(amount) FILTER (WHERE status = 'posted' AND created > extract(epoch from now()) - 3600), 0)::bigint
    ) FROM rt),
 'buckets', (SELECT COALESCE(json_agg(json_build_object('t', b, 'n', n, 'v', v)), '[]') FROM (
    SELECT floor(created / 300) * 300 AS b, count(*) AS n, sum(amount)::bigint AS v FROM rt
    WHERE status = 'posted' AND created > extract(epoch from now()) - 3900 GROUP BY 1) q),
 'recent', (SELECT COALESCE(json_agg(r), '[]') FROM (
    SELECT t.id, t.created, t.amount, t.status, t.from_account, t.to_account, nf.full_name AS from_name, nt.full_name AS to_name
    FROM rt t LEFT JOIN named nf ON nf.acct = t.from_account LEFT JOIN named nt ON nt.acct = t.to_account
    WHERE t.status IN ('posted', 'held', 'rejected') ORDER BY t.id DESC LIMIT 8) r),
 'held', (SELECT COALESCE(json_agg(r), '[]') FROM (
    SELECT t.id, t.created, t.amount, t.from_account, t.to_account, nf.full_name AS from_name, nt.full_name AS to_name
    FROM rt t LEFT JOIN named nf ON nf.acct = t.from_account LEFT JOIN named nt ON nt.acct = t.to_account
    WHERE t.status = 'held' ORDER BY t.id DESC LIMIT 5) r),
 'audit', (SELECT json_build_object('entries', count(*),
    'by_alg', (SELECT COALESCE(json_object_agg(alg, c), '{}') FROM (SELECT alg, count(*) AS c FROM audit_log
      WHERE transfer_id IN (SELECT id FROM rt) GROUP BY alg) z))
    FROM audit_log WHERE transfer_id IN (SELECT id FROM rt)),
 'settlement', (SELECT json_build_object('last_ts', created, 'last_alg', alg, 'last_status', status, 'last_reason', reason)
    FROM batches ORDER BY id DESC LIMIT 1)
);
""".replace("__BOTS__", BOTS)


def _db():
    script = f"echo {base64.b64encode(SQL.encode()).decode()} | base64 -d | psql -h /run/postgresql -p 5433 -U bank -d bank -At -f -"
    p = testbed.exec_in("postgres", script, check=False, timeout=30)
    try:
        return json.loads(p.stdout)
    except Exception:
        return {}


def _containers():
    p = testbed.compose("ps", "-a", "--format", "json", check=False, timeout=30)
    rows = []
    for line in p.stdout.splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        for x in (j if isinstance(j, list) else [j]):
            if x.get("Service") in ROLES:
                rows.append({"service": x.get("Service"), "state": x.get("State"), "status": x.get("Status", "")})
    return rows


def _buckets(rows, now):
    start = int(now // 300) * 300 - 11 * 300
    by = {int(r["t"]): r for r in rows}
    return [{"t": start + i * 300, "n": by.get(start + i * 300, {}).get("n", 0), "v": by.get(start + i * 300, {}).get("v", 0)}
            for i in range(12)]


def _exposure(state):
    """Quantum-vulnerable crypto each service uses right now, read from the live service state."""
    per, kinds = {}, {"key exchange": 0, "TLS identity": 0, "trust store": 0, "signatures": 0}
    for name in ORDER:
        st, items = state.get(name) or {}, []
        if st.get("kex") == "classical":
            items.append(("key exchange", "X25519 key exchange"))
        if st.get("cert") == "rsa":
            items.append(("TLS identity", "RSA-2048 certificate"))
        if st.get("public_cert") == "rsa":
            items.append(("TLS identity", "public RSA-2048 certificate"))
        if st.get("trust") == "rsa":
            items.append(("trust store", "trusts only the RSA root"))
        for key, what in (("jwt_alg", "tokens"), ("audit_alg", "audit log"), ("settle_alg", "settlement batches")):
            if (st.get(key) or "").startswith("RS"):
                items.append(("signatures", f"signs {what} with {st[key]}"))
        for k, _ in items:
            kinds[k] += 1
        per[name] = [t for _, t in items]
    return {"per_service": per, "by_kind": kinds, "services_exposed": sum(bool(v) for v in per.values()),
            "items": sum(len(v) for v in per.values()), "services": len(ORDER)}


def _migration():
    tv = pipeline.tasks_view()
    core = [t for t in tv["tasks"] if not t["deferred"]]
    kinds = {}
    for t in core:
        k = kinds.setdefault(t["kind"], {"done": 0, "total": 0})
        k["total"] += 1
        k["done"] += bool(t["done"])
    ready = sorted((t for t in core if t["status"] == "ready"), key=lambda t: (t["window"] if t["window"] is not None else 9, -(t["risk"] or 0)))
    return {"done": sum(bool(t["done"]) for t in core), "total": len(core), "by_kind": kinds, "history": len(tv["history"]),
            "blocked": sum(t["status"] == "blocked" for t in core),
            "next": [{k: t[k] for k in ("id", "title", "service", "window", "risk")} for t in ready[:4]], "state": tv["state"]}


def _events():
    out = []
    for e in migrate.events()[:6]:
        failed = [c["name"] for c in e.get("checks", []) if not c.get("passed")]
        out.append({"label": e.get("label"), "type": e.get("type"), "tasks": e.get("tasks") or [], "ts": e.get("ts"),
                    "result": "undone by operator" if e.get("type") == "rollback" else "rolled back" if e.get("rollback")
                    else "passed" if e.get("passed") else "failed",
                    "failed_checks": failed[:3]})
    return out


def _alerts(d):
    a = []
    down = [c["service"] for c in d["containers"] if c["state"] != "running"]
    if down:
        a.append({"level": "bad", "text": f"Container not running: {', '.join(down)}", "href": "#migrate"})
    led = d["ledger"]
    if led and (not led.get("money_conserved") or not led.get("journal_balanced")):
        a.append({"level": "bad", "text": "Ledger integrity: money not conserved or journal unbalanced", "href": "#report"})
    ev = next((e for e in d["events"] if e["type"] != "rollback"), None)
    if ev and ev["result"] not in ("passed",):
        a.append({"level": "warn", "text": f"Last change {ev['label']} {ev['result']}: {', '.join(ev['failed_checks']) or 'see log'}", "href": "#migrate"})
    if d["transfers"].get("held"):
        a.append({"level": "warn", "text": f"{d['transfers']['held']} payment(s) held for review (large first payment to a new payee)", "href": "#overview"})
    if d["customers"].get("locked"):
        a.append({"level": "warn", "text": f"{d['customers']['locked']} customer account(s) locked after failed sign-ins", "href": "#overview"})
    x = d["exposure"]
    if x["items"]:
        a.append({"level": "info", "text": f"{x['services_exposed']} of {x['services']} services still use quantum-vulnerable crypto "
                  f"({x['items']} items); {d['migration']['done']} of {d['migration']['total']} migration tasks live", "href": "#migrate"})
    return a


def overview(force=False):
    global _cache
    if not force and _cache[1] is not None and time.time() - _cache[0] < CACHE_S:
        return _cache[1]
    now = time.time()
    state, led = testbed.read_state(), testbed.ledger_stats()
    db, containers = _db(), _containers()
    exposure, mig = _exposure(state), _migration()
    up = {c["service"]: c for c in containers}

    services = []
    for name in ORDER:
        if name not in up:
            continue
        title, desc, group = ROLES[name]
        st = state.get(name) or {}
        services.append({"name": name, "title": title, "desc": desc, "group": group, "state": up[name]["state"], "status": up[name]["status"],
                         "crypto": {k: st.get(k) for k in ("kex", "cert", "public_cert", "trust", "jwt_alg", "audit_alg", "settle_alg") if st.get(k)},
                         "exposed": exposure["per_service"].get(name, [])})

    d = {"generated": now, "containers": containers, "services": services,
         "customers": {**(db.get("customers") or {}), "sessions": db.get("sessions", 0), "payees": db.get("payees", 0),
                       "excluded_bots": db.get("excluded_bots", 0)},
         "accounts": db.get("accounts") or {}, "transfers": db.get("transfers") or {},
         "buckets": _buckets(db.get("buckets") or [], now), "recent": db.get("recent") or [], "held": db.get("held") or [],
         "audit": db.get("audit") or {}, "settlement": db.get("settlement") or {}, "ledger": led,
         "algorithms": {"token": (state.get("identity") or {}).get("jwt_alg"), "audit": (state.get("ledger") or {}).get("audit_alg"),
                        "settlement": (state.get("settlement") or {}).get("settle_alg"),
                        "public_cert": (state.get("gateway") or {}).get("public_cert"), "gateway_kex": (state.get("gateway") or {}).get("kex")},
         "exposure": exposure, "migration": mig, "events": _events()}
    d["alerts"] = _alerts(d)
    d["overall"] = ("bad" if any(a["level"] == "bad" for a in d["alerts"]) else "warn" if any(a["level"] == "warn" for a in d["alerts"]) else "ok")
    _cache = (now, d)
    return d


def verify_audit():
    p = testbed.exec_in("ledger", "wget -qO- http://127.0.0.1:8000/audit/verify", check=False, timeout=120)
    try:
        return {**json.loads(p.stdout), "checked_at": time.time()}
    except Exception:
        raise RuntimeError("ledger did not answer the audit verification")
