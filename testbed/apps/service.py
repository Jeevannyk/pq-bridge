"""Mini-bank application tier. One file, three roles.

TLS is terminated by the nginx sidecar in the same container; this app listens
on 127.0.0.1:8000 only. Crypto settings that live in the application (JWT
algorithm to issue / accept) are read from /state/services.json on every
request, so the migration executor can change them without a restart.

JWT signing and verification shell out to the OpenSSL 3.5 CLI so that RS256 and
FN-DSA-512 (Falcon, via oqs-provider) go through the same real implementation.
"""
import base64
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE = sys.argv[1]
STATE_FILE = "/state/services.json"
JWT_DIR = "/pki/jwt"
JWT_KEYS = {  # alg -> (private key, public key)
    "RS256": (f"{JWT_DIR}/rs256.key", f"{JWT_DIR}/rs256.pub"),
    "FN-DSA-512": (f"{JWT_DIR}/fndsa512.key", f"{JWT_DIR}/fndsa512.pub"),
}
TOKEN_TTL = 300


def state():
    with open(STATE_FILE) as f:
        return json.load(f).get(ROLE, {})


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _openssl(args, data: bytes, sig: bytes = None):
    with tempfile.TemporaryDirectory() as d:
        msg = os.path.join(d, "msg")
        with open(msg, "wb") as f:
            f.write(data)
        sigf = os.path.join(d, "sig")
        if sig is not None:
            with open(sigf, "wb") as f:
                f.write(sig)
        args = [a.replace("{msg}", msg).replace("{sig}", sigf) for a in args]
        p = subprocess.run(["openssl", *args], capture_output=True)
        if sig is None:
            if p.returncode != 0:
                raise RuntimeError(p.stderr.decode())
            with open(sigf, "rb") as f:
                return f.read()
        return p.returncode == 0


def jwt_sign(alg: str, payload: dict) -> str:
    key = JWT_KEYS[alg][0]
    header = {"alg": alg, "typ": "JWT"}
    signing_input = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(payload).encode())}".encode()
    if alg == "RS256":
        sig = _openssl(["dgst", "-sha256", "-sign", key, "-out", "{sig}", "{msg}"], signing_input)
    else:
        sig = _openssl(["pkeyutl", "-sign", "-inkey", key, "-rawin", "-in", "{msg}", "-out", "{sig}"], signing_input)
    return f"{signing_input.decode()}.{b64u(sig)}"


def jwt_verify(token: str, accepted: list):
    """Return (ok, reason)."""
    try:
        h, p, s = token.split(".")
        header = json.loads(b64u_dec(h))
        payload = json.loads(b64u_dec(p))
        sig = b64u_dec(s)
    except Exception:
        return False, "malformed token"
    alg = header.get("alg")
    if alg not in accepted:
        return False, f"alg {alg} not accepted (accepts {accepted})"
    if alg not in JWT_KEYS or not os.path.exists(JWT_KEYS[alg][1]):
        return False, f"no verification key for {alg}"
    pub = JWT_KEYS[alg][1]
    signing_input = f"{h}.{p}".encode()
    if alg == "RS256":
        ok = _openssl(["dgst", "-sha256", "-verify", pub, "-signature", "{sig}", "{msg}"], signing_input, sig)
    else:
        ok = _openssl(["pkeyutl", "-verify", "-pubin", "-inkey", pub, "-rawin", "-in", "{msg}", "-sigfile", "{sig}"],
                      signing_input, sig)
    if not ok:
        return False, "bad signature"
    if payload.get("exp", 0) < time.time():
        return False, "expired"
    return True, alg


# ---------------------------------------------------------------- ledger ----
_db_lock = threading.Lock()


def db():
    conn = sqlite3.connect("/data/ledger.db")
    conn.execute("CREATE TABLE IF NOT EXISTS tx (id TEXT PRIMARY KEY, src TEXT, dst TEXT, amount INTEGER, ts REAL)")
    return conn


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, {"role": ROLE, "ok": True})
        if ROLE == "ledger" and self.path == "/stats":
            with _db_lock, db() as c:
                n, total = c.execute("SELECT COUNT(*), COALESCE(SUM(amount),0) FROM tx").fetchone()
            return self.reply(200, {"tx_count": n, "total_amount": total})
        self.reply(404, {"error": "not found"})

    def do_POST(self):
        if ROLE == "card-auth" and self.path.endswith("/token"):
            alg = state().get("jwt_alg", "RS256")
            now = int(time.time())
            tok = jwt_sign(alg, {"sub": self.body().get("user", "anon"), "iat": now, "exp": now + TOKEN_TTL})
            return self.reply(200, {"token": tok, "alg": alg})

        if ROLE == "payment-switch" and self.path == "/pay":
            auth = self.headers.get("Authorization", "")
            ok, why = jwt_verify(auth.removeprefix("Bearer "), state().get("jwt_accept", ["RS256"]))
            if not ok:
                return self.reply(401, {"error": why})
            tx = self.body()
            req = urllib.request.Request("http://127.0.0.1:9001/post", data=json.dumps(tx).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    return self.reply(200, {"status": "settled", "ledger": json.load(r), "jwt_alg": why})
            except Exception as e:
                return self.reply(502, {"error": f"ledger unreachable: {e}"})

        if ROLE == "ledger" and self.path == "/post":
            tx = self.body()
            with _db_lock, db() as c:
                c.execute("INSERT OR IGNORE INTO tx VALUES (?,?,?,?,?)",
                          (tx["tx_id"], tx["from"], tx["to"], int(tx["amount"]), time.time()))
            return self.reply(200, {"posted": tx["tx_id"]})

        self.reply(404, {"error": "not found"})


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
