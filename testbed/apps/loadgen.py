"""Continuous payment traffic through the public gateway.

Every payment = token from card-auth (refreshed every 20 payments) + POST /pay.
Counters go to /state/loadgen.json so the verification gate can see whether a
migration wave caused a single failed payment.
"""
import json
import os
import ssl
import time
import urllib.error
import urllib.request
import uuid

GATEWAY = "https://gateway"
TRUST = "/pki/trust/client-trust.pem"   # modern client: trusts every root the bank publishes
OUT = "/state/loadgen.json"

stats = {"ok": 0, "fail": 0, "errors": {}, "recent_failures": [], "last_alg": None, "started": time.time()}


def ctx():
    return ssl.create_default_context(cafile=TRUST)


def call(path, payload, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(GATEWAY + path, data=json.dumps(payload).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, context=ctx(), timeout=10) as r:
        return json.load(r)


def flush():
    stats["updated"] = time.time()
    tmp = OUT + ".tmp"
    with open(tmp, "w") as f:
        json.dump(stats, f)
    os.replace(tmp, OUT)


def main():
    token, used = None, 0
    while True:
        try:
            if token is None or used >= 20:
                t = call("/auth/token", {"user": "loadgen"})
                token, used = t["token"], 0
                stats["last_alg"] = t["alg"]
            call("/pay", {"tx_id": uuid.uuid4().hex, "from": "ACC-1001", "to": "ACC-2002", "amount": 125}, token)
            used += 1
            stats["ok"] += 1
        except Exception as e:
            if isinstance(e, urllib.error.HTTPError):
                reason = f"HTTP {e.code}: {e.read().decode(errors='ignore')[:120]}"
                token = None
            else:
                reason = f"{type(e).__name__}: {str(e)[:120]}"
            stats["fail"] += 1
            stats["errors"][reason] = stats["errors"].get(reason, 0) + 1
            stats["recent_failures"] = (stats["recent_failures"] + [{"t": time.time(), "reason": reason}])[-20:]
            time.sleep(0.2)
        if (stats["ok"] + stats["fail"]) % 5 == 0:
            flush()


if __name__ == "__main__":
    while not os.path.exists(TRUST):
        time.sleep(1)
    while True:   # don't count boot-time "connection refused" as failed payments
        try:
            urllib.request.urlopen(GATEWAY + "/health", context=ctx(), timeout=3).read()
            break
        except Exception:
            time.sleep(1)
    stats["started"] = time.time()
    main()
