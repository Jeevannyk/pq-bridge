"""Identity provider: customer login and OAuth2 tokens.

  POST /oauth/token            grant_type=password (username, password) or grant_type=refresh_token
                               -> access_token (JWT signed by the KMS, 5 min) + rotating refresh token (1 day)
  GET  /.well-known/jwks.json  public keys resource servers use to verify access tokens

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
SCOPES = "accounts:read payments:write"


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


class Identity(bank.Handler):
    routes = {("POST", "/oauth/token"): "token", ("GET", "/.well-known/jwks.json"): "jwks"}

    def token(self):
        b = self.body()
        grant = b.get("grant_type")
        with bank.db() as conn:
            if grant == "password":
                row = conn.execute("SELECT id, pw_hash, pw_salt, failed, locked_until FROM customers WHERE username=%s",
                                   (b.get("username", ""),)).fetchone()
                if not row:
                    return self.reply(401, {"error": "invalid_grant"})
                if row[4] > time.time():
                    return self.reply(429, {"error": "account temporarily locked"})
                if not check_password(row, b.get("password", "")):
                    failed = row[3] + 1
                    conn.execute("UPDATE customers SET failed=%s, locked_until=%s WHERE id=%s",
                                 (0 if failed >= 5 else failed, time.time() + 60 if failed >= 5 else 0, row[0]))
                    return self.reply(401, {"error": "invalid_grant"})
                conn.execute("UPDATE customers SET failed=0 WHERE id=%s", (row[0],))
                return self.reply(200, issue(conn, row[0]))
            if grant == "refresh_token":
                h = bank.sha256_hex(b.get("refresh_token", "").encode())
                row = conn.execute("DELETE FROM refresh_tokens WHERE hash=%s RETURNING customer_id, expires", (h,)).fetchone()
                if not row or row[1] < time.time():
                    return self.reply(401, {"error": "invalid_grant"})
                return self.reply(200, issue(conn, row[0]))       # rotation: the old refresh token is gone
        self.reply(400, {"error": "unsupported_grant_type"})

    def jwks(self):
        publish = set(bank.state(ROLE)["jwt_publish"])
        keys = [k for k in bank.kms_keys() if k["purpose"] == "jwt" and k["alg"] in publish]
        self.reply(200, {"keys": keys}, {"Cache-Control": "max-age=3"})


if __name__ == "__main__":
    bank.serve(Identity)
