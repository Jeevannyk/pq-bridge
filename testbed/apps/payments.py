"""Payments: customer-initiated transfers.

  GET  /api/payments/limits      per-transfer and daily limits, used and remaining today
  POST /api/payments/transfers   {from_account, to_account, amount, memo?}  (amount in paise, integer)
    - access token with scope payments:write; from_account must belong to the token's subject
    - Idempotency-Key header required: a retried request returns the original result, never a second transfer
    - limits: 50,000.00 per transfer, 2,00,000.00 per customer per day
    - fraud rule: more than 20,000.00 to a payee never paid before is held for review, not posted
    - posting goes to the ledger (double entry, signed audit) over mTLS
    - a passing outage (e.g. a crypto change being rolled back) does not lose a payment: the transfer is stored
      first and posting to the ledger is retried (the ledger posts a transfer id once, so a retry can never pay
      twice). If it cannot be posted within GIVE_UP_AFTER_S the payment FAILS CLEANLY: it is marked failed under the
      ledger's audit lock, and the ledger refuses to post a failed transfer, so a payment the customer was told
      failed can never move money later. Repeating the request with the same Idempotency-Key returns the final result.
"""
import json
import time

import bank

ROLE = "payments"
PER_TX, PER_DAY, FRAUD_NEW_PAYEE = 5_000_000, 20_000_000, 2_000_000
POST_DEADLINE_S = 10          # how long one request keeps trying the ledger before answering "processing"
GIVE_UP_AFTER_S = 12          # not posted by now: the payment fails, no money moved (NetBank shows the red cross)
RECONCILE_AFTER_S = 13        # the background worker settles or fails pending transfers older than this
HTTP_FOR = {"posted": 201, "held": 202, "rejected": 422}


def post_to_ledger(tid, src, dst, amount, deadline_s):
    """(status, body) from the ledger. Retries only while the ledger link is unavailable; 200 and 422 are final."""
    end, delay = time.time() + deadline_s, 0.25
    while True:
        try:
            code, body = bank.egress("POST", "/ledger/post", {"transfer_id": tid, "from_account": src, "to_account": dst,
                                                             "amount": amount}, timeout=10)
        except Exception as e:                               # connection refused / reset / timeout mid-change
            code, body = 0, {"error": type(e).__name__}
        if code in (200, 422) or time.time() + delay > end:
            return code, body
        time.sleep(delay)
        delay = min(delay * 1.6, 2.0)


def settle_pending(tid, deadline_s):
    """Finish a stored transfer. Returns (http, response), or None while the ledger is still unavailable."""
    with bank.db() as conn:
        row = conn.execute("SELECT from_account, to_account, amount, memo, created, status, response FROM transfers WHERE id=%s",
                           (tid,)).fetchone()
        if not row:
            return None
        src, dst, amount, memo, created, status, response = row
        if status != "pending":
            return HTTP_FOR.get(status, 200), response
        left = GIVE_UP_AFTER_S - (time.time() - created)
        lc, lr = post_to_ledger(tid, src, dst, amount, min(deadline_s, left)) if left > 0 else (0, {})
        if lc not in (200, 422):
            if time.time() - created < GIVE_UP_AFTER_S:
                return None
            # Out of time. Take the ledger's audit lock so no post can be in flight, then decide: if the ledger did post
            # (its reply was lost) the payment is posted; otherwise it is failed and the ledger will refuse it from now on.
            conn.commit()
            conn.execute("SELECT seq FROM audit_head FOR UPDATE")
            done = conn.execute("SELECT seq, alg FROM audit_log WHERE transfer_id=%s", (tid,)).fetchone()
            lc, lr = (200, {"audit_seq": done[0], "alg": done[1]}) if done else (0, None)
        name = (conn.execute("SELECT c.full_name FROM accounts a JOIN customers c ON c.id=a.customer_id WHERE a.id=%s",
                             (dst,)).fetchone() or [None])[0]
        receipt = {"transfer_id": tid, "reference": f"TXN{tid:08d}", "amount": amount, "from_account": src, "to_account": dst,
                   "to_name": name, "memo": memo, "created": created}
        if lc == 200:
            new, resp = "posted", {**receipt, "status": "posted", "audit_seq": lr["audit_seq"], "audit_alg": lr["alg"]}
        elif lc == 422:
            new, resp = "rejected", {**receipt, "status": "rejected", "reason": lr.get("error")}
        else:
            new, resp = "rejected", {**receipt, "status": "failed",
                                     "reason": "The bank could not complete this payment right now. No money has left your account."}
        conn.execute("UPDATE transfers SET status=%s, response=%s WHERE id=%s AND status='pending'", (new, json.dumps(resp), tid))
        conn.commit()
        status, response = conn.execute("SELECT status, response FROM transfers WHERE id=%s", (tid,)).fetchone()
        return HTTP_FOR.get(status, 200), response


def reconcile():
    """Background: complete transfers whose requests gave up while the ledger was unreachable."""
    while True:
        time.sleep(3)
        try:
            with bank.db() as conn:
                ids = [r[0] for r in conn.execute("SELECT id FROM transfers WHERE status='pending' AND created < %s "
                                                  "ORDER BY id LIMIT 20", (time.time() - RECONCILE_AFTER_S,)).fetchall()]
            for tid in ids:
                settle_pending(tid, 3)
        except Exception:
            pass


class Payments(bank.Handler):
    routes = {("POST", "/api/payments/transfers"): "transfer", ("GET", "/api/payments/limits"): "limits"}

    def limits(self):
        claims = self.auth(ROLE, "payments:write")
        if not claims:
            return
        with bank.db() as conn:
            used = conn.execute("SELECT COALESCE(SUM(amount),0)::bigint FROM transfers WHERE customer_id=%s AND status='posted' "
                                "AND created > %s", (claims["sub"], time.time() - 86400)).fetchone()[0]
        self.reply(200, {"per_transfer": PER_TX, "per_day": PER_DAY, "used_today": used,
                         "remaining_today": max(0, PER_DAY - used), "review_above": FRAUD_NEW_PAYEE})

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
        memo = str(b.get("memo") or "").strip()[:60]
        try:
            amount = int(b.get("amount"))
        except (TypeError, ValueError):
            return self.reply(400, {"error": "amount must be an integer number of paise"})

        with bank.db() as conn:
            prev = conn.execute("SELECT id, response FROM transfers WHERE customer_id=%s AND idem_key=%s", (cust, idem)).fetchone()
            if prev and prev[1]:
                return self.reply(200, {**prev[1], "replayed": True})
            if prev:                                              # stored but not yet posted: finish it now
                done = settle_pending(prev[0], POST_DEADLINE_S)
                if done:
                    return self.reply(200, {**done[1], "replayed": True})
                return self.reply(202, {"transfer_id": prev[0], "reference": f"TXN{prev[0]:08d}", "status": "processing"})
            owner = conn.execute("SELECT customer_id FROM accounts WHERE id=%s", (src,)).fetchone()
            if not owner or owner[0] != cust:
                return self.reply(403, {"error": "from_account does not belong to this customer"})
            dest = conn.execute("SELECT a.customer_id, c.full_name FROM accounts a JOIN customers c ON c.id=a.customer_id "
                                "WHERE a.id=%s", (dst,)).fetchone()
            if src == dst or not dest:
                return self.reply(422, {"error": "invalid payee account"})
            if amount <= 0 or amount > PER_TX:
                return self.reply(422, {"error": f"amount must be between 1 and {PER_TX} paise"})
            today = conn.execute("SELECT COALESCE(SUM(amount),0) FROM transfers WHERE customer_id=%s AND status='posted' "
                                 "AND created > %s", (cust, time.time() - 86400)).fetchone()[0]
            if today + amount > PER_DAY:
                return self.reply(422, {"error": "daily limit exceeded"})
            known_payee = dest[0] == cust or conn.execute("SELECT 1 FROM transfers WHERE customer_id=%s AND to_account=%s "
                                                          "AND status='posted' LIMIT 1", (cust, dst)).fetchone()
            now = time.time()
            row = conn.execute("INSERT INTO transfers(customer_id, idem_key, from_account, to_account, amount, status, created, memo) "
                               "VALUES (%s,%s,%s,%s,%s,'pending',%s,%s) ON CONFLICT (customer_id, idem_key) DO NOTHING RETURNING id",
                               (cust, idem, src, dst, amount, now, memo)).fetchone()
            conn.commit()
            if not row:
                return self.reply(409, {"error": "concurrent request with this Idempotency-Key"})
            tid = row[0]
            receipt = {"transfer_id": tid, "reference": f"TXN{tid:08d}", "amount": amount, "from_account": src, "to_account": dst,
                       "to_name": dest[1], "memo": memo, "created": now}

            if amount > FRAUD_NEW_PAYEE and not known_payee:
                resp = {**receipt, "status": "held_for_review", "reason": "large first payment to a new payee"}
                conn.execute("UPDATE transfers SET status='held', response=%s WHERE id=%s", (json.dumps(resp), tid))
                return self.reply(202, resp)
        try:
            budget = max(0.0, min(POST_DEADLINE_S, float(self.headers.get("X-Retry-Budget-S", POST_DEADLINE_S))))
        except ValueError:
            budget = POST_DEADLINE_S
        done = settle_pending(tid, budget)                        # stored as pending; post it, retrying while the ledger is away
        if done:
            return self.reply(*done)
        self.reply(202, {**receipt, "status": "processing"})


if __name__ == "__main__":
    bank.serve(Payments, background=reconcile)
