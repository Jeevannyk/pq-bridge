"""Payments: customer-initiated transfers.

  POST /api/payments/transfers   {from_account, to_account, amount}  (amount in paise, integer)
    - access token with scope payments:write; from_account must belong to the token's subject
    - Idempotency-Key header required: a retried request returns the original result, never a second transfer
    - limits: 50,000.00 per transfer, 2,00,000.00 per customer per day
    - fraud rule: more than 20,000.00 to a payee never paid before is held for review, not posted
    - posting goes to the ledger (double entry, signed audit) over mTLS
"""
import json
import time

import bank

ROLE = "payments"
PER_TX, PER_DAY, FRAUD_NEW_PAYEE = 5_000_000, 20_000_000, 2_000_000


class Payments(bank.Handler):
    routes = {("POST", "/api/payments/transfers"): "transfer"}

    def transfer(self):
        ok, claims, code = bank.verify_access_token(self.headers.get("Authorization", ""),
                                                    bank.state(ROLE)["jwt_accept"], "payments:write")
        if not ok:
            return self.reply(code, {"error": claims})
        idem = self.headers.get("Idempotency-Key", "")
        if not 8 <= len(idem) <= 80:
            return self.reply(400, {"error": "Idempotency-Key header required (8-80 chars)"})
        b = self.body()
        cust, src, dst = claims["sub"], b.get("from_account"), b.get("to_account")
        try:
            amount = int(b.get("amount"))
        except (TypeError, ValueError):
            return self.reply(400, {"error": "amount must be an integer number of paise"})

        with bank.db() as conn:
            prev = conn.execute("SELECT response FROM transfers WHERE customer_id=%s AND idem_key=%s", (cust, idem)).fetchone()
            if prev and prev[0]:
                return self.reply(200, {**prev[0], "replayed": True})
            if prev:
                return self.reply(409, {"error": "a request with this Idempotency-Key is still in progress"})
            owner = conn.execute("SELECT customer_id FROM accounts WHERE id=%s", (src,)).fetchone()
            if not owner or owner[0] != cust:
                return self.reply(403, {"error": "from_account does not belong to this customer"})
            if src == dst or not conn.execute("SELECT 1 FROM accounts WHERE id=%s", (dst,)).fetchone():
                return self.reply(422, {"error": "invalid payee account"})
            if amount <= 0 or amount > PER_TX:
                return self.reply(422, {"error": f"amount must be between 1 and {PER_TX} paise"})
            today = conn.execute("SELECT COALESCE(SUM(amount),0) FROM transfers WHERE customer_id=%s AND status='posted' "
                                 "AND created > %s", (cust, time.time() - 86400)).fetchone()[0]
            if today + amount > PER_DAY:
                return self.reply(422, {"error": "daily limit exceeded"})
            known_payee = conn.execute("SELECT 1 FROM transfers WHERE customer_id=%s AND to_account=%s AND status='posted' LIMIT 1",
                                       (cust, dst)).fetchone()
            row = conn.execute("INSERT INTO transfers(customer_id, idem_key, from_account, to_account, amount, status, created) "
                               "VALUES (%s,%s,%s,%s,%s,'pending',%s) ON CONFLICT (customer_id, idem_key) DO NOTHING RETURNING id",
                               (cust, idem, src, dst, amount, time.time())).fetchone()
            conn.commit()
            if not row:
                return self.reply(409, {"error": "concurrent request with this Idempotency-Key"})
            tid = row[0]

            if amount > FRAUD_NEW_PAYEE and not known_payee:
                status, http, resp = "held", 202, {"transfer_id": tid, "status": "held_for_review",
                                                   "reason": "large first payment to a new payee"}
            else:
                lc, lr = bank.egress("POST", "/ledger/post", {"transfer_id": tid, "from_account": src,
                                                             "to_account": dst, "amount": amount})
                if lc == 200:
                    status, http, resp = "posted", 201, {"transfer_id": tid, "status": "posted",
                                                         "audit_seq": lr["audit_seq"], "audit_alg": lr["alg"]}
                elif lc == 422:
                    status, http, resp = "rejected", 422, {"transfer_id": tid, "status": "rejected", "reason": lr.get("error")}
                else:
                    conn.execute("DELETE FROM transfers WHERE id=%s", (tid,))   # nothing posted: allow a clean retry
                    return self.reply(502, {"error": f"ledger unavailable: {lr.get('error', lc)}"})
            conn.execute("UPDATE transfers SET status=%s, response=%s WHERE id=%s", (status, json.dumps(resp), tid))
        self.reply(http, resp)


if __name__ == "__main__":
    bank.serve(Payments)
