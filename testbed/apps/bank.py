"""Shared plumbing for the PQBank services (Python stdlib + psycopg).

Every service listens on 127.0.0.1:8000 only; its nginx sidecar terminates mTLS on :443 and passes the
caller's certificate subject in X-Client-CN. Outbound calls go to the sidecar's local egress, which adds mTLS:
  HTTP  http://127.0.0.1:9001/<service>/...   (identity, kms, ledger, clearing)
  SQL   127.0.0.1:6543 -> postgres:5432        (nginx stream, mTLS)
So no service holds TLS keys or picks TLS algorithms itself: the migration changes only nginx configs, the
state file and key material. Crypto that lives in the application (JWT algorithm, audit and settlement
signature algorithms) is read from /state/services.json on every request.
"""
import base64
import hashlib
import json
import os
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE_FILE = "/state/services.json"
EGRESS = "http://127.0.0.1:9001"
DB_DSN = "host=127.0.0.1 port=6543 dbname=bank user=bank password=bank-db-pass sslmode=disable connect_timeout=5"
ALG_TAG = {"RS256": "rsa", "FN-DSA-512": "fndsa", "SLH-DSA-SHA2-128s": "slhdsa"}


# ------------------------------------------------------------------ state, encoding
def state(role):
    for _ in range(20):
        try:
            with open(STATE_FILE) as f:
                return json.load(f).get(role, {})
        except (OSError, ValueError):
            time.sleep(0.05)
    raise RuntimeError("state file unreadable")


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ------------------------------------------------------------------ OpenSSL 3.5 (+ oqs-provider) sign / verify
def openssl_sign(alg, keyfile, data):
    with tempfile.TemporaryDirectory() as d:
        m, s = os.path.join(d, "m"), os.path.join(d, "s")
        open(m, "wb").write(data)
        if alg == "RS256":
            cmd = ["openssl", "dgst", "-sha256", "-sign", keyfile, "-out", s, m]
        else:
            cmd = ["openssl", "pkeyutl", "-sign", "-inkey", keyfile, "-rawin", "-in", m, "-out", s]
        p = subprocess.run(cmd, capture_output=True)
        if p.returncode:
            raise RuntimeError(p.stderr.decode()[-200:])
        return open(s, "rb").read()


def spki_to_pem(spki_der):
    b = base64.encodebytes(spki_der).decode().replace("\n", "")
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END PUBLIC KEY-----\n"


def openssl_verify(alg, pub_pem, data, sig):
    with tempfile.TemporaryDirectory() as d:
        k, m, s = (os.path.join(d, x) for x in "kms")
        open(k, "w").write(pub_pem)
        open(m, "wb").write(data)
        open(s, "wb").write(sig)
        if alg == "RS256":
            cmd = ["openssl", "dgst", "-sha256", "-verify", k, "-signature", s, m]
        else:
            cmd = ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", k, "-rawin", "-in", m, "-sigfile", s]
        return subprocess.run(cmd, capture_output=True).returncode == 0


# ------------------------------------------------------------------ HTTP
def http_json(method, url, body=None, headers=None, timeout=10):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {"error": f"HTTP {e.code}"}


def egress(method, path, body=None, headers=None, timeout=10):
    return http_json(method, EGRESS + path, body, headers, timeout)


def db():
    import psycopg
    return psycopg.connect(DB_DSN)


# ------------------------------------------------------------------ KMS client
_keys_cache = {"t": 0, "keys": []}


def kms_keys(max_age=3):
    if time.time() - _keys_cache["t"] > max_age:
        code, r = egress("GET", "/kms/keys")
        if code == 200:
            _keys_cache.update(t=time.time(), keys=r["keys"])
    return _keys_cache["keys"]


def kms_kid(purpose, alg):
    for k in kms_keys():
        if k["purpose"] == purpose and k["alg"] == alg:
            return k["kid"]
    raise RuntimeError(f"KMS has no {alg} key for {purpose}")


def kms_sign(purpose, alg, data):
    code, r = egress("POST", "/kms/sign", {"purpose": purpose, "alg": alg, "data_b64": b64u(data)})
    if code != 200:
        raise RuntimeError(f"KMS refused: {r.get('error', code)}")
    return b64u_dec(r["sig_b64"]), r["kid"]


# ------------------------------------------------------------------ OAuth2 access tokens (JWT, signed by the KMS)
_jwks_cache = {"t": 0, "keys": {}}


def jwks(max_age=3):
    if time.time() - _jwks_cache["t"] > max_age:
        code, r = egress("GET", "/identity/.well-known/jwks.json")
        if code == 200:
            _jwks_cache.update(t=time.time(), keys={k["kid"]: k for k in r["keys"]})
    return _jwks_cache["keys"]


def verify_access_token(auth_header, accepted_algs, scope):
    """Resource-server check of a bearer token. Returns (ok, claims_or_reason, http_status)."""
    if not auth_header.startswith("Bearer "):
        return False, "missing bearer token", 401
    try:
        h, p, s = auth_header[7:].split(".")
        header, claims, sig = json.loads(b64u_dec(h)), json.loads(b64u_dec(p)), b64u_dec(s)
    except Exception:
        return False, "malformed token", 401
    alg, kid = header.get("alg"), header.get("kid")
    if alg not in accepted_algs:
        return False, f"alg {alg} not accepted (accepts {accepted_algs})", 401
    key = jwks().get(kid) or jwks(max_age=0).get(kid)
    if not key or key.get("alg") != alg:
        return False, f"unknown key id {kid}", 401
    if not openssl_verify(alg, spki_to_pem(b64u_dec(key["spki"])), f"{h}.{p}".encode(), sig):
        return False, "bad signature", 401
    if claims.get("exp", 0) < time.time():
        return False, "expired", 401
    if claims.get("iss") != "https://pqbank/identity":
        return False, "wrong issuer", 401
    if scope not in claims.get("scope", "").split():
        return False, f"token lacks scope {scope}", 403
    return True, claims, 200


# ------------------------------------------------------------------ tiny HTTP framework
class Handler(BaseHTTPRequestHandler):
    routes = {}           # (METHOD, path) -> method name

    def log_message(self, *a):
        pass

    def reply(self, code, obj, headers=None):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        if (self.headers.get("Content-Type") or "").startswith("application/x-www-form-urlencoded"):
            from urllib.parse import parse_qsl
            return dict(parse_qsl(raw.decode()))
        return json.loads(raw or b"{}")

    def client_cn(self):
        dn = self.headers.get("X-Client-CN", "")
        for part in dn.replace("/", ",").split(","):
            if part.strip().startswith("CN="):
                return part.strip()[3:]
        return ""

    def _dispatch(self, method):
        path = self.path.split("?")[0]
        if path == "/health":
            return self.reply(200, {"ok": True})
        name = self.routes.get((method, path))
        if not name:
            return self.reply(404, {"error": "not found"})
        try:
            getattr(self, name)()
        except Exception as e:                    # never leak a stack trace to a client
            self.reply(500, {"error": f"{type(e).__name__}: {str(e)[:200]}"})

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")


def serve(handler_cls, background=None):
    if background:
        threading.Thread(target=background, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", 8000), handler_cls).serve_forever()


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()
