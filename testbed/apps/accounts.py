"""Accounts: the customer's own banking data. Every call needs an access token (algorithms from jwt_accept).

  GET  /api/accounts                accounts and balances                          scope accounts:read
  GET  /api/accounts/transactions   ?account=&limit=&offset=&from=&to=&type=       statement with running balance
  GET  /api/accounts/lookup         ?account=    name enquiry before paying someone
  GET  /api/accounts/payees         saved payees
  POST /api/accounts/payees         {account, nickname}                            scope accounts:write
  POST /api/accounts/payees/remove  {account}                                      scope accounts:write
  GET  /api/accounts/profile        name, contact details, last sign-in
  POST /api/accounts/profile        {email, phone}                                 scope accounts:write
  POST /api/accounts/password       {current, new}                                 scope accounts:write
"""
import calendar
import hashlib
import hmac
import os
import re
import time

import bank

ROLE = "accounts"
EMAIL, PHONE = re.compile(r"^[^@\s]{1,60}@[^@\s]+\.[^@\s]{2,}$"), re.compile(r"^\+?[0-9 ]{8,15}$")


def _day(text, default):
    if not text:
        return default
    return calendar.timegm(time.strptime(text, "%Y-%m-%d"))


def _num(q, key, default, lo, hi):
    return max(lo, min(int(q.get(key) or default), hi))


class Accounts(bank.Handler):
    routes = {("GET", "/api/accounts"): "list", ("GET", "/api/accounts/transactions"): "transactions",
              ("GET", "/api/accounts/lookup"): "lookup", ("GET", "/api/accounts/payees"): "payees",
              ("POST", "/api/accounts/payees"): "add_payee", ("POST", "/api/accounts/payees/remove"): "remove_payee",
              ("GET", "/api/accounts/profile"): "profile", ("POST", "/api/accounts/profile"): "update_profile",
              ("POST", "/api/accounts/password"): "password"}

    def list(self):
        claims = self.auth(ROLE, "accounts:read")
        if not claims:
            return
        with bank.db() as conn:
            rows = conn.execute("SELECT id, balance, currency, type FROM accounts WHERE customer_id=%s ORDER BY id", (claims["sub"],)).fetchall()
            name = conn.execute("SELECT full_name FROM customers WHERE id=%s", (claims["sub"],)).fetchone()
        self.reply(200, {"customer": claims["sub"], "name": name[0] if name else None,
                         "accounts": [{"id": r[0], "balance": r[1], "currency": r[2], "type": r[3]} for r in rows]})

    def transactions(self):
        claims = self.auth(ROLE, "accounts:read")
        if not claims:
            return
        q = self.query()
        try:
            limit, offset = _num(q, "limit", 25, 1, 100), _num(q, "offset", 0, 0, 100000)
            t_from = _day(q.get("from"), 0)
            t_to = _day(q.get("to"), 0) + 86400 if q.get("to") else time.time() + 86400
        except ValueError:
            return self.reply(400, {"error": "invalid limit, offset or date (use YYYY-MM-DD)"})
        kind = q.get("type", "") if q.get("type") in ("debit", "credit") else ""
        with bank.db() as conn:
            acct = conn.execute("SELECT balance, currency, type FROM accounts WHERE id=%s AND customer_id=%s",
                                (q.get("account", ""), claims["sub"])).fetchone()
            if not acct:
                return self.reply(404, {"error": "account not found"})
            rows = conn.execute("""
                SELECT * FROM (
                  SELECT j.id, j.transfer_id, j.ts, j.debit, j.credit, t.memo,
                         CASE WHEN j.debit > 0 THEN t.to_account ELSE t.from_account END AS other,
                         (%s::bigint - COALESCE(SUM(j.credit - j.debit) OVER (ORDER BY j.id DESC
                            ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING), 0))::bigint AS bal_after
                  FROM journal j JOIN transfers t ON t.id = j.transfer_id WHERE j.account_id = %s) x
                WHERE x.ts >= %s AND x.ts < %s AND (%s = '' OR (CASE WHEN x.debit > 0 THEN 'debit' ELSE 'credit' END) = %s)
                ORDER BY x.id DESC LIMIT %s OFFSET %s""",
                (acct[0], q["account"], t_from, t_to, kind, kind, limit + 1, offset)).fetchall()
            others = list({r[6] for r in rows})
            names = dict(conn.execute("SELECT a.id, c.full_name FROM accounts a JOIN customers c ON c.id=a.customer_id "
                                      "WHERE a.id = ANY(%s)", (others,)).fetchall()) if others else {}
            held = conn.execute("SELECT id, created, to_account, amount, status, memo FROM transfers WHERE from_account=%s "
                                "AND status IN ('held','rejected') ORDER BY id DESC LIMIT 10", (q["account"],)).fetchall() if offset == 0 else []
        items = [{"id": r[1], "ref": f"TXN{r[1]:08d}", "ts": r[2], "type": "debit" if r[3] > 0 else "credit",
                  "amount": r[3] or r[4], "balance_after": r[7], "memo": r[5] or "",
                  "counterparty": {"account": r[6], "name": names.get(r[6])}} for r in rows[:limit]]
        self.reply(200, {"account": q["account"], "type": acct[2], "balance": acct[0], "currency": acct[1], "items": items,
                         "has_more": len(rows) > limit,
                         "held": [{"ref": f"TXN{h[0]:08d}", "ts": h[1], "to_account": h[2], "amount": h[3], "status": h[4],
                                   "memo": h[5] or ""} for h in held]})

    def lookup(self):
        claims = self.auth(ROLE, "accounts:read")
        if not claims:
            return
        acct = self.query().get("account", "")
        with bank.db() as conn:
            row = conn.execute("SELECT a.id, c.full_name, a.customer_id FROM accounts a JOIN customers c ON c.id=a.customer_id "
                               "WHERE a.id=%s", (acct,)).fetchone()
        if not row:
            return self.reply(404, {"error": "No account with that number."})
        self.reply(200, {"account": row[0], "name": row[1], "own": row[2] == claims["sub"]})

    def payees(self):
        claims = self.auth(ROLE, "accounts:read")
        if not claims:
            return
        with bank.db() as conn:
            rows = conn.execute("SELECT p.account_id, p.nickname, c.full_name FROM payees p JOIN accounts a ON a.id=p.account_id "
                                "JOIN customers c ON c.id=a.customer_id WHERE p.customer_id=%s ORDER BY p.added DESC",
                                (claims["sub"],)).fetchall()
        self.reply(200, {"payees": [{"account": r[0], "nickname": r[1], "name": r[2]} for r in rows]})

    def add_payee(self):
        claims = self.auth(ROLE, "accounts:write")
        if not claims:
            return
        b = self.body()
        acct, nick = str(b.get("account", "")), str(b.get("nickname", "")).strip()[:40]
        with bank.db() as conn:
            row = conn.execute("SELECT a.customer_id, c.full_name FROM accounts a JOIN customers c ON c.id=a.customer_id WHERE a.id=%s", (acct,)).fetchone()
            if not row:
                return self.reply(404, {"error": "No account with that number."})
            if row[0] == claims["sub"]:
                return self.reply(422, {"error": "That is your own account. Use it directly when you transfer."})
            conn.execute("INSERT INTO payees(customer_id, account_id, nickname, added) VALUES (%s,%s,%s,%s) "
                         "ON CONFLICT (customer_id, account_id) DO UPDATE SET nickname=EXCLUDED.nickname",
                         (claims["sub"], acct, nick or row[1], time.time()))
        self.reply(201, {"account": acct, "nickname": nick or row[1], "name": row[1]})

    def remove_payee(self):
        claims = self.auth(ROLE, "accounts:write")
        if not claims:
            return
        with bank.db() as conn:
            conn.execute("DELETE FROM payees WHERE customer_id=%s AND account_id=%s", (claims["sub"], str(self.body().get("account", ""))))
        self.reply(200, {"ok": True})

    def profile(self):
        claims = self.auth(ROLE, "accounts:read")
        if not claims:
            return
        with bank.db() as conn:
            r = conn.execute("SELECT id, username, full_name, email, phone, last_login FROM customers WHERE id=%s", (claims["sub"],)).fetchone()
        self.reply(200, dict(zip(["id", "username", "name", "email", "phone", "last_login"], r)))

    def update_profile(self):
        claims = self.auth(ROLE, "accounts:write")
        if not claims:
            return
        b = self.body()
        email, phone = str(b.get("email", "")).strip(), str(b.get("phone", "")).strip()
        if email and not EMAIL.match(email):
            return self.reply(422, {"error": "Enter a valid email address."})
        if phone and not PHONE.match(phone):
            return self.reply(422, {"error": "Enter a valid phone number."})
        with bank.db() as conn:
            conn.execute("UPDATE customers SET email=%s, phone=%s WHERE id=%s", (email or None, phone or None, claims["sub"]))
        self.reply(200, {"email": email, "phone": phone})

    def password(self):
        claims = self.auth(ROLE, "accounts:write")
        if not claims:
            return
        b = self.body()
        cur, new = str(b.get("current", "")), str(b.get("new", ""))
        if len(new) < 10 or not re.search(r"[A-Za-z]", new) or not re.search(r"[0-9]", new) or new == cur:
            return self.reply(422, {"error": "New password needs at least 10 characters with letters and digits, and must differ from the current one."})
        with bank.db() as conn:
            row = conn.execute("SELECT pw_hash, pw_salt FROM customers WHERE id=%s", (claims["sub"],)).fetchone()
            if not hmac.compare_digest(hashlib.scrypt(cur.encode(), salt=bytes.fromhex(row[1]), n=2 ** 14, r=8, p=1).hex(), row[0]):
                return self.reply(403, {"error": "Current password is incorrect."})
            salt = os.urandom(16)
            conn.execute("UPDATE customers SET pw_hash=%s, pw_salt=%s WHERE id=%s",
                         (hashlib.scrypt(new.encode(), salt=salt, n=2 ** 14, r=8, p=1).hex(), salt.hex(), claims["sub"]))
            conn.execute("DELETE FROM refresh_tokens WHERE customer_id=%s", (claims["sub"],))      # other sessions must sign in again
        self.reply(200, {"ok": True})


if __name__ == "__main__":
    bank.serve(Accounts)
