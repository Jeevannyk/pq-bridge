"""Identity provider: customer login and OAuth2 tokens.

  POST /oauth/token            grant_type=password (username, password) or grant_type=refresh_token
                               -> access_token (JWT signed by the KMS, 5 min) + rotating refresh token (1 day)
  GET  /.well-known/jwks.json  public keys resource servers use to verify access tokens
  POST /api/auth/login         NetBank sign-in: {username, password} -> tokens + customer name (no OAuth form needed)
  POST /api/auth/refresh       {refresh_token} -> new tokens (rotating)
  POST /api/auth/logout        {refresh_token} -> the refresh token is revoked

Passwords: scrypt (N=2^14, r=8, p=1) with a per-user salt. 5 failed logins lock the account for 60 s.
The signing algorithm and the published keys come from the state file (jwt_alg, jwt_publish).
"""
import hashlib
import hmac
import secrets
import time

import bank

ROLE = "identity"
ACCESS_TTL, REFRESH_TTL = 300, 86400
SCOPES = "accounts:read accounts:write payments:write"


def check_password(row, password):
    h = hashlib.scrypt(password.encode(), salt=bytes.fromhex(row[2]), n=2 ** 14, r=8, p=1).hex()
    return hmac.compare_digest(h, row[1])


def issue(conn, customer_id):
    st = bank.state(ROLE)
    alg = st["jwt_alg"]
    now = int(time.time())
    header = {"alg": alg, "typ": "JWT", "kid": bank.kms_kid("jwt", alg)}
    claims = {"iss": "https://pqbank/identity", "sub": customer_id, "aud": "pqbank-api", "scope": SCOPES,
              "iat": now, "exp": now + ACCESS_TTL, "jti": secrets.token_hex(8)}
    signing_input = f"{bank.b64u(bank.canon(header))}.{bank.b64u(bank.canon(claims))}".encode()
    sig, kid = bank.kms_sign("jwt", alg, signing_input)
    refresh = secrets.token_urlsafe(32)
    conn.execute("INSERT INTO refresh_tokens(hash, customer_id, expires) VALUES (%s, %s, %s)",
                 (bank.sha256_hex(refresh.encode()), customer_id, now + REFRESH_TTL))
    return {"access_token": f"{signing_input.decode()}.{bank.b64u(sig)}", "token_type": "Bearer",
            "expires_in": ACCESS_TTL, "refresh_token": refresh, "scope": SCOPES}


def check_login(conn, username, password):
    """Shared by the OAuth password grant and the NetBank sign-in. Returns (http_status, customer_row or None)."""
    row = conn.execute("SELECT id, pw_hash, pw_salt, failed, locked_until, full_name, last_login FROM customers WHERE username=%s",
                       (username,)).fetchone()
    if not row:
        hashlib.scrypt(password.encode(), salt=b"0" * 16, n=2 ** 14, r=8, p=1)          # same cost as a real check
        return 401, None
    if row[4] > time.time():
        return 429, None
    if not check_password(row, password):
        failed = row[3] + 1
        conn.execute("UPDATE customers SET failed=%s, locked_until=%s WHERE id=%s",
                     (0 if failed >= 5 else failed, time.time() + 60 if failed >= 5 else 0, row[0]))
        return 401, None
    conn.execute("UPDATE customers SET failed=0, last_login=%s WHERE id=%s", (time.time(), row[0]))
    return 200, row


def rotate(conn, refresh_token):
    h = bank.sha256_hex(refresh_token.encode())
    row = conn.execute("DELETE FROM refresh_tokens WHERE hash=%s RETURNING customer_id, expires", (h,)).fetchone()
    return None if not row or row[1] < time.time() else row[0]       # rotation: the old refresh token is gone


class Identity(bank.Handler):
    routes = {("POST", "/oauth/token"): "token", ("GET", "/.well-known/jwks.json"): "jwks",
              ("POST", "/api/auth/login"): "login", ("POST", "/api/auth/refresh"): "refresh", ("POST", "/api/auth/logout"): "logout"}

    def token(self):
        b = self.body()
        grant = b.get("grant_type")
        with bank.db() as conn:
            if grant == "password":
                code, row = check_login(conn, b.get("username", ""), b.get("password", ""))
                if code == 429:
                    return self.reply(429, {"error": "account temporarily locked"})
                if not row:
                    return self.reply(401, {"error": "invalid_grant"})
                return self.reply(200, issue(conn, row[0]))
            if grant == "refresh_token":
                cid = rotate(conn, b.get("refresh_token", ""))
                if not cid:
                    return self.reply(401, {"error": "invalid_grant"})
                return self.reply(200, issue(conn, cid))
        self.reply(400, {"error": "unsupported_grant_type"})

    def login(self):
        b = self.body()
        username, password = str(b.get("username", "")), str(b.get("password", ""))
        if not username or not password or len(username) > 64 or len(password) > 200:
            return self.reply(400, {"error": "Enter your username and password."})
        with bank.db() as conn:
            code, row = check_login(conn, username, password)
            if code == 429:
                return self.reply(429, {"error": "Too many failed attempts. Try again in a minute."})
            if not row:
                return self.reply(401, {"error": "Incorrect username or password."})
            self.reply(200, {**issue(conn, row[0]), "customer": {"id": row[0], "username": username, "name": row[5]},
                             "previous_login": row[6]})

    def refresh(self):
        with bank.db() as conn:
            cid = rotate(conn, str(self.body().get("refresh_token", "")))
            if not cid:
                return self.reply(401, {"error": "Session expired. Please sign in again."})
            self.reply(200, issue(conn, cid))

    def logout(self):
        with bank.db() as conn:
            conn.execute("DELETE FROM refresh_tokens WHERE hash=%s", (bank.sha256_hex(str(self.body().get("refresh_token", "")).encode()),))
        self.reply(200, {"ok": True})

    def jwks(self):
        publish = set(bank.state(ROLE)["jwt_publish"])
        keys = [k for k in bank.kms_keys() if k["purpose"] == "jwt" and k["alg"] in publish]
        self.reply(200, {"keys": keys}, {"Cache-Control": "max-age=3"})


if __name__ == "__main__":
    bank.serve(Identity)
