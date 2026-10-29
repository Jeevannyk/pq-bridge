"""Customer mobile/web app traffic: 20 customers, all through the public gateway over TLS.

Each customer logs in (OAuth2 password grant), refreshes its token every ~15 actions, checks balances and makes
small transfers to other customers with an Idempotency-Key; 3% of transfers are retried with the same key (as a
phone would after a timeout) and must come back as replays, not second transfers.
Counters go to /state/loadgen.json for the verification gate.
"""
import json
import os
import random
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

GATEWAY = "https://gateway"
TRUST = "/pki/trust/client-trust.pem"      # modern client: trusts every root the bank publishes
OUT = "/state/loadgen.json"
CUSTOMERS = [(f"cust{i:03d}", f"Passw0rd!{i:03d}", f"ACC-{i:04d}") for i in range(1, 21)]

stats = {"ok": 0, "fail": 0, "errors": {}, "recent_failures": [], "last_alg": None, "logins": 0, "refreshes": 0,
         "transfers": 0, "replays_ok": 0, "balance_checks": 0, "business_rejects": 0, "started": time.time()}


def ctx():
    return ssl.create_default_context(cafile=TRUST)


def call(method, path, body=None, token=None, headers=None, form=False):
    h = dict(headers or {})
    if token:
        h["Authorization"] = f"Bearer {token}"
    if form:
        data, h["Content-Type"] = urllib.parse.urlencode(body).encode(), "application/x-www-form-urlencoded"
    else:
        data, h["Content-Type"] = (json.dumps(body).encode() if body is not None else None), "application/json"
    req = urllib.request.Request(GATEWAY + path, data=data, headers=h, method=method)
    with urllib.request.urlopen(req, context=ctx(), timeout=15) as r:
        return r.status, json.load(r)


def alg_of(token):
    import base64
    h = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4))).get("alg")


class Session:
    def __init__(self, user, pw, acct):
        self.user, self.pw, self.acct, self.access, self.refresh, self.used = user, pw, acct, None, None, 0

    def ensure(self):
        if self.access is None:
            _, t = call("POST", "/oauth/token", {"grant_type": "password", "username": self.user, "password": self.pw}, form=True)
            stats["logins"] += 1
        elif self.used >= 15:
            _, t = call("POST", "/oauth/token", {"grant_type": "refresh_token", "refresh_token": self.refresh}, form=True)
            stats["refreshes"] += 1
        else:
            return
        self.access, self.refresh, self.used = t["access_token"], t["refresh_token"], 0
        stats["last_alg"] = alg_of(self.access)


def flush():
    stats["updated"] = time.time()
    tmp = OUT + ".tmp"
    with open(tmp, "w") as f:
        json.dump(stats, f)
    os.replace(tmp, OUT)


def act(s):
    s.ensure()
    s.used += 1
    if random.random() < 0.15:
        call("GET", "/api/accounts", token=s.access)
        stats["balance_checks"] += 1
        return
    payee = random.choice([c for c in CUSTOMERS if c[0] != s.user])[2]
    key = uuid.uuid4().hex
    body = {"from_account": s.acct, "to_account": payee, "amount": random.randint(100, 50_000)}
    try:
        code, r = call("POST", "/api/payments/transfers", body, s.access, {"Idempotency-Key": key})
    except urllib.error.HTTPError as e:
        if e.code == 422:                         # e.g. limit reached: a correct business answer, not an outage
            stats["business_rejects"] += 1
            return
        raise
    stats["transfers"] += 1
    if random.random() < 0.03:                    # network retry with the same key
        _, r2 = call("POST", "/api/payments/transfers", body, s.access, {"Idempotency-Key": key})
        if not r2.get("replayed") or r2.get("transfer_id") != r.get("transfer_id"):
            raise RuntimeError("idempotency violated: retry created a second transfer")
        stats["replays_ok"] += 1


def main():
    sessions = [Session(*c) for c in CUSTOMERS]
    while True:
        s = random.choice(sessions)
        try:
            act(s)
            stats["ok"] += 1
        except Exception as e:
            if isinstance(e, urllib.error.HTTPError):
                reason = f"HTTP {e.code}: {e.read().decode(errors='ignore')[:120]}"
                if e.code == 401:
                    s.access = None               # token rejected: log in again next time
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
    while True:                                   # don't count boot-time failures: wait for one full login
        try:
            Session(*CUSTOMERS[0]).ensure()
            break
        except Exception:
            time.sleep(2)
    stats.update(started=time.time(), logins=0)
    main()
