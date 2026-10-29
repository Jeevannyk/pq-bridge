"""Verification-gate probes, run inside the toolbox (bank network, OpenSSL 3.5 + oqs-provider, probe client cert).

  probe.py timing <service> <n>     handshake latency (ms)
  probe.py negative                 attacks and misuse that MUST be refused
  probe.py business '<expected>'    the bank still works: login, tokens, transfers, money, audit chain, settlement
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
GATE_USER, GATE_PASS, GATE_ACCT = "gatetest", "Gate-Test-Pass-1", "ACC-0022"
POOR_USER, POOR_PASS, POOR_ACCT = "cust099", "Passw0rd!099", "ACC-0021"


def ctx(cert=PROBE):
    c = ssl.create_default_context(cafile=TRUST)
    if cert:
        c.load_cert_chain(*cert)
    return c


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def req(method, url, body=None, headers=None, cert=PROBE, form=False):
    h = dict(headers or {})
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
    good = {"iss": "https://pqbank/identity", "sub": "C0022", "aud": "pqbank-api", "scope": "accounts:read payments:write",
            "iat": now, "exp": now + 300}
    tokens = [("forged token signature", forge(good, sign=False), 401),
              ("alg=none token", f"{b64u(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode())}.{b64u(json.dumps(good).encode())}.", 401),
              ("expired token (validly signed)", forge({**good, "iat": now - 900, "exp": now - 600}), 401),
              ("token from a foreign issuer (validly signed)", forge({**good, "iss": "https://evil.example"}), 401)]
    for name, tok, want in tokens:
        c, r = gw("GET", "/api/accounts", tok)
        case(name, "accounts", c == want, f"{c} {r.get('error')}")
    c, r = gw("POST", "/api/payments/transfers", forge({**good, "scope": "accounts:read"}),
              {"from_account": GATE_ACCT, "to_account": "ACC-0001", "amount": 100}, {"Idempotency-Key": uuid.uuid4().hex})
    case("token without payments:write scope", "payments", c == 403, f"{c} {r.get('error')}")

    c, t = login(GATE_USER, "wrong-password")
    case("wrong password", "identity", c == 401, c)
    c, t = login(GATE_USER, GATE_PASS)
    tok = t.get("access_token", "")
    c, r = gw("POST", "/api/payments/transfers", tok, {"from_account": "ACC-0001", "to_account": GATE_ACCT, "amount": 100},
              {"Idempotency-Key": uuid.uuid4().hex})
    case("transfer from another customer's account", "payments", c == 403, f"{c} {r.get('error')}")
    c, r = gw("POST", "/api/payments/transfers", tok, {"from_account": GATE_ACCT, "to_account": "ACC-0001", "amount": 100})
    case("transfer without Idempotency-Key", "payments", c == 400, f"{c} {r.get('error')}")
    c, t2 = login(POOR_USER, POOR_PASS)
    c, r = gw("POST", "/api/payments/transfers", t2.get("access_token", ""), {"from_account": POOR_ACCT, "to_account": "ACC-0001",
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
    body = {"from_account": GATE_ACCT, "to_account": "ACC-0001", "amount": 100}
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


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "timing":
        print(json.dumps(timing(sys.argv[2], int(sys.argv[3]))))
    elif cmd == "negative":
        print(json.dumps(negative()))
    elif cmd == "business":
        print(json.dumps(business(json.loads(sys.argv[2]))))
