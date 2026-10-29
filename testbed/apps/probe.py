"""Verification-gate probes, run inside the toolbox (bank network, OpenSSL 3.5 + oqs-provider, probe client cert).

  probe.py timing <service> <n>     handshake latency (ms)
  probe.py negative                 attacks and misuse that MUST be refused
  probe.py business '<expected>'    the bank still works: login, tokens, transfers, money, audit chain, settlement
  probe.py canary                   fast end-to-end customer path (sign in, read, pay, retry)
  probe.py window <max_s>            a customer using the bank during a change, until /tmp/window.stop
Each prints one JSON list/object.
"""
import base64
import json
import os
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

TRUST = "/pki/trust/both.pem" if os.path.exists("/pki/trust/both.pem") else "/pki/trust/rsa.pem"
PROBE = ("/pki/certs/probe.rsa.crt", "/pki/certs/probe.rsa.key")
INTERNAL = ["identity", "accounts", "payments", "ledger", "kms", "settlement"]
PORT = {"postgres": 5432}
GATE_USER, GATE_PASS, GATE_ACCT = "gatetest", "Gate-Test-Pass-1", "ACC-0001"
PEER_ACCT = "ACC-0002"
POOR_USER, POOR_PASS, POOR_ACCT = "gatepoor", "Gate-Poor-Pass-1", "ACC-0003"
UA = "pqbridge-probe"


def ctx(cert=PROBE):
    c = ssl.create_default_context(cafile=TRUST)
    if cert:
        c.load_cert_chain(*cert)
    return c


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def req(method, url, body=None, headers=None, cert=PROBE, form=False):
    h = {"User-Agent": UA, **(headers or {})}
    if form:
        data, h["Content-Type"] = urllib.parse.urlencode(body).encode(), "application/x-www-form-urlencoded"
    else:
        data, h["Content-Type"] = (json.dumps(body).encode() if body is not None else None), "application/json"
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, context=ctx(cert), timeout=20) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {"error": f"HTTP {e.code}"}
    except Exception as e:
        return 0, {"error": f"{type(e).__name__}: {str(e)[:120]}"}


def login(user, pw):
    return req("POST", "https://gateway/oauth/token", {"grant_type": "password", "username": user, "password": pw}, cert=None, form=True)


def gw(method, path, token, body=None, headers=None):
    return req(method, "https://gateway" + path, body, {"Authorization": f"Bearer {token}", **(headers or {})}, cert=None)


def jwks():
    return req("GET", "https://gateway/.well-known/jwks.json", cert=None)[1].get("keys", [])


def forge(claims, alg="RS256", sign=True):
    """A token signed with the real RSA signing key (what an insider or a leaked key could do)."""
    kid = next((k["kid"] for k in jwks() if k["alg"] == "RS256"), "none")
    head = b64u(json.dumps({"alg": alg, "typ": "JWT", "kid": kid}, separators=(",", ":")).encode())
    body = b64u(json.dumps(claims, separators=(",", ":")).encode())
    if not sign:
        return f"{head}.{body}.{b64u(os.urandom(256))}"
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(f"{head}.{body}".encode())
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", "/kms/jwt.rsa.key", f.name], capture_output=True).stdout
    return f"{head}.{body}.{b64u(sig)}"


def tls_rejects(host, port, cert):
    """True if the server refuses a TLS client (no cert / rogue cert): handshake error or HTTP 400."""
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            with ctx(cert).wrap_socket(s, server_hostname=host) as t:
                if port == 443:
                    t.sendall(f"GET /health HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                    return not t.recv(64).startswith(b"HTTP/1.1 200")
                t.sendall(b"\x00\x00\x00\x08\x04\xd2\x16\x2f")       # any byte: nginx must have refused already
                return t.recv(1) == b""
    except (ssl.SSLError, OSError):
        return True


# ------------------------------------------------------------------ timing
def timing(svc, n):
    port = PORT.get(svc, 443)
    c = ctx()
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        with socket.create_connection((svc, port), timeout=5) as s:
            with c.wrap_socket(s, server_hostname=svc):
                pass
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    return {"service": svc, "n": n, "median_ms": round(statistics.median(samples), 2), "p95_ms": round(samples[int(0.95 * (n - 1))], 2)}


# ------------------------------------------------------------------ negative
def negative():
    out = []

    def case(name, target, ok, detail):
        out.append({"case": name, "target": target, "rejected": bool(ok), "detail": str(detail)[:140]})

    now = int(time.time())
    good = {"iss": "https://pqbank/identity", "sub": "C0001", "aud": "pqbank-api", "scope": "accounts:read payments:write",
            "iat": now, "exp": now + 300}
    tokens = [("forged token signature", forge(good, sign=False), 401),
              ("alg=none token", f"{b64u(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode())}.{b64u(json.dumps(good).encode())}.", 401),
              ("expired token (validly signed)", forge({**good, "iat": now - 900, "exp": now - 600}), 401),
              ("token from a foreign issuer (validly signed)", forge({**good, "iss": "https://evil.example"}), 401)]
    for name, tok, want in tokens:
        c, r = gw("GET", "/api/accounts", tok)
        case(name, "accounts", c == want, f"{c} {r.get('error')}")
    c, r = gw("POST", "/api/payments/transfers", forge({**good, "scope": "accounts:read"}),
              {"from_account": GATE_ACCT, "to_account": PEER_ACCT, "amount": 100}, {"Idempotency-Key": uuid.uuid4().hex})
    case("token without payments:write scope", "payments", c == 403, f"{c} {r.get('error')}")

    c, t = login(GATE_USER, "wrong-password")
    case("wrong password", "identity", c == 401, c)
    c, t = login(GATE_USER, GATE_PASS)
    tok = t.get("access_token", "")
    c, r = gw("POST", "/api/payments/transfers", tok, {"from_account": PEER_ACCT, "to_account": GATE_ACCT, "amount": 100},
              {"Idempotency-Key": uuid.uuid4().hex})
    case("transfer from another customer's account", "payments", c == 403, f"{c} {r.get('error')}")
    c, r = gw("POST", "/api/payments/transfers", tok, {"from_account": GATE_ACCT, "to_account": PEER_ACCT, "amount": 100})
    case("transfer without Idempotency-Key", "payments", c == 400, f"{c} {r.get('error')}")
    c, t2 = login(POOR_USER, POOR_PASS)
    c, r = gw("POST", "/api/payments/transfers", t2.get("access_token", ""), {"from_account": POOR_ACCT, "to_account": PEER_ACCT,
              "amount": 500_00}, {"Idempotency-Key": uuid.uuid4().hex})
    case("overdraft (balance 100.00, transfer 500.00)", "ledger", c == 422 and "insufficient" in str(r), f"{c} {r}")

    c, r = req("POST", "https://kms/sign", {"purpose": "audit", "alg": "RS256", "data_b64": "YQ"})
    case("KMS signing by an unauthorised service", "kms", c == 403, f"{c} {r.get('error')}")
    c, r = req("POST", "https://ledger/post", {"transfer_id": 1, "from_account": "ACC-0001", "to_account": "ACC-0002", "amount": 1})
    case("ledger posting by a service other than payments", "ledger", c == 403, f"{c} {r.get('error')}")

    rogue = tempfile.mkdtemp()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=payments", "-keyout", f"{rogue}/k",
                    "-out", f"{rogue}/c", "-days", "1"], capture_output=True)
    for svc in INTERNAL + ["postgres"]:
        port = PORT.get(svc, 443)
        case("no client certificate", svc, tls_rejects(svc, port, None), "refused")
        case("self-signed certificate claiming CN=payments", svc, tls_rejects(svc, port, (f"{rogue}/c", f"{rogue}/k")), "refused")
    return out


# ------------------------------------------------------------------ business
def business(expected):
    out = []

    def check(name, ok, detail):
        out.append({"case": name, "passed": bool(ok), "detail": str(detail)[:160]})

    c, t = login(GATE_USER, GATE_PASS)
    tok = t.get("access_token", "")
    alg = json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "==")).get("alg") if tok else None
    check(f"customer login issues a {expected['jwt_alg']} access token", c == 200 and alg == expected["jwt_alg"], f"{c} alg={alg}")
    pub = sorted(k["alg"] for k in jwks())
    check(f"JWKS publishes {', '.join(expected['jwt_publish'])}", pub == sorted(expected["jwt_publish"]), pub)
    c, r = gw("GET", "/api/accounts", tok)
    check("accounts readable with the token", c == 200 and r.get("accounts"), f"{c} {r.get('error', '')}")
    key = uuid.uuid4().hex
    body = {"from_account": GATE_ACCT, "to_account": PEER_ACCT, "amount": 100}
    c1, r1 = gw("POST", "/api/payments/transfers", tok, body, {"Idempotency-Key": key})
    c2, r2 = gw("POST", "/api/payments/transfers", tok, body, {"Idempotency-Key": key})
    check(f"transfer posted, audit signed with {expected['audit_alg']}", c1 == 201 and r1.get("audit_alg") == expected["audit_alg"], f"{c1} {r1}")
    check("retry with the same Idempotency-Key is a replay, not a second transfer",
          c2 == 200 and r2.get("replayed") and r2.get("transfer_id") == r1.get("transfer_id"), f"{c2} {r2}")
    c, s = req("GET", "https://ledger/stats")
    check("money conserved (total balances equal the seed)", c == 200 and s.get("money_conserved"), f"{s.get('total_balance')} vs {s.get('seed_total')}")
    check("double-entry journal balanced", c == 200 and s.get("journal_balanced"), f"debits {s.get('debits')} credits {s.get('credits')}")
    c, a = req("GET", "https://ledger/audit/verify")
    check("audit hash chain intact and signatures verify", c == 200 and a.get("ok"),
          f"{a.get('entries')} entries, by alg {a.get('entries_by_alg')}, failed {a.get('signatures_failed')}")
    c, b = req("POST", "https://settlement/settle", {})
    check(f"settlement batch signed with {expected['settle_alg']} and accepted by the clearing house",
          c == 200 and b.get("accepted") and b.get("alg") == expected["settle_alg"], f"{b.get('alg')} {b.get('reason')}")
    return out


# ------------------------------------------------------------------ customer-path checks
RETRY_ON = (0, 502, 503, 504)          # what NetBank retries on: the bank did not answer, nothing was decided


def canary():
    """Fast end-to-end customer path (about a second): sign in, read accounts and limits, pay one paisa, retry it.
    The transfer asks for a zero retry budget so an unhealthy ledger link fails the canary instead of hiding it."""
    steps = []

    def step(name, ok, detail=""):
        steps.append({"name": name, "ok": bool(ok), "detail": str(detail)[:140]})
        return ok

    c, t = login(GATE_USER, GATE_PASS)
    tok = t.get("access_token", "")
    if not step("customer sign-in through the public gateway", c == 200 and tok, f"{c} {t.get('error', '')}"):
        return {"ok": False, "steps": steps}
    c, r = gw("GET", "/api/accounts", tok)
    step("accounts read (gateway, identity JWKS, accounts, database)", c == 200 and r.get("accounts"), f"{c} {r.get('error', '')}")
    c, r = gw("GET", "/api/payments/limits", tok)
    step("payment limits read (gateway, payments, database)", c == 200, f"{c} {r.get('error', '')}")
    key = uuid.uuid4().hex
    body = {"from_account": GATE_ACCT, "to_account": PEER_ACCT, "amount": 1}
    c, r = gw("POST", "/api/payments/transfers", tok, body, {"Idempotency-Key": key, "X-Retry-Budget-S": "0"})
    step("payment posts (payments, ledger, KMS, database)", c == 201, f"{c} {r.get('error') or r.get('status', '')}")
    c, r2 = gw("POST", "/api/payments/transfers", tok, body, {"Idempotency-Key": key, "X-Retry-Budget-S": "0"})
    step("retry with the same key is a replay", c in (200, 201) and r2.get("transfer_id") == r.get("transfer_id"), f"{c}")
    return {"ok": all(x["ok"] for x in steps), "steps": steps}


def retrying(fn, budget_s=45):
    """Call fn() -> (status, body) the way NetBank does: keep trying while the bank does not answer."""
    t0, attempts, delay = time.time(), 0, 0.4
    while True:
        attempts += 1
        code, body = fn()
        if code not in RETRY_ON or time.time() - t0 > budget_s:
            return code, body, attempts, time.time() - t0
        time.sleep(delay)
        delay = min(delay * 1.6, 2.5)


def window(max_s):
    """A customer using the bank while a change is applied: balance reads and one-paisa payments through the public
    gateway, with NetBank's own retry rules. Runs until /tmp/window.stop appears. Progress goes to /tmp/window.json."""
    stats = {"ops": 0, "ok": 0, "failed": 0, "retried": 0, "max_s": 0.0, "errors": {}, "payments": 0}
    state = {"tok": ""}

    def publish():
        with open("/tmp/window.json.tmp", "w") as f:
            json.dump(stats, f)
        os.replace("/tmp/window.json.tmp", "/tmp/window.json")

    def sign_in():
        c, t = login(GATE_USER, GATE_PASS)
        state["tok"] = t.get("access_token", "")
        return c, t

    def record(good, code, body, attempts, took):
        stats["ops"] += 1
        stats["ok" if good else "failed"] += 1
        stats["retried"] += attempts > 1 and good
        stats["max_s"] = round(max(stats["max_s"], took), 2)
        if not good:
            why = f"{code} {body.get('error', '')}"[:80]
            stats["errors"][why] = stats["errors"].get(why, 0) + 1

    sign_in()
    publish()
    t_end, i = time.time() + max_s, 0
    while time.time() < t_end and not os.path.exists("/tmp/window.stop"):
        i += 1
        if i % 5:
            code, body, n, took = retrying(lambda: gw("GET", "/api/accounts", state["tok"]))
            if code == 401:
                sign_in()
                code, body, n, took = retrying(lambda: gw("GET", "/api/accounts", state["tok"]))
            record(code == 200, code, body, n, took)
        else:
            key, pay = uuid.uuid4().hex, {"from_account": GATE_ACCT, "to_account": PEER_ACCT, "amount": 1}
            code, body, n, took = retrying(lambda: gw("POST", "/api/payments/transfers", state["tok"], pay, {"Idempotency-Key": key}))
            while code == 202 and took < 45:                       # "processing": ask again with the same key, as NetBank does
                time.sleep(1.5)
                code, body, n2, t2 = retrying(lambda: gw("POST", "/api/payments/transfers", state["tok"], pay, {"Idempotency-Key": key}))
                n, took = n + n2, took + t2 + 1.5
            stats["payments"] += 1
            record(code in (200, 201), code, body, n, took)
        publish()
        time.sleep(0.25)
    publish()
    return stats


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "timing":
        print(json.dumps(timing(sys.argv[2], int(sys.argv[3]))))
    elif cmd == "negative":
        print(json.dumps(negative()))
    elif cmd == "business":
        print(json.dumps(business(json.loads(sys.argv[2]))))
    elif cmd == "canary":
        print(json.dumps(canary()))
    elif cmd == "window":
        print(json.dumps(window(float(sys.argv[2]))))
