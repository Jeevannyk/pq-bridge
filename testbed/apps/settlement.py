"""Settlement: every 30 s (and on POST /settle) the bank sends the clearing house a batch file of the transfers
posted since the last accepted batch, signed by the KMS with the settlement algorithm (RS256 -> SLH-DSA).
If the clearing house rejects the batch (it cannot verify the signature), the transfers stay unsettled and are
retried in the next batch.

  POST /settle        build, sign and send a batch now
  GET  /batches/last  the last batch and the clearing house's verdict
"""
import threading
import time

import bank

ROLE = "settlement"
_lock = threading.Lock()


def settle():
    with _lock, bank.db() as conn:
        rows = conn.execute("SELECT id, from_account, to_account, amount FROM transfers WHERE status='posted' "
                            "AND batch_id IS NULL ORDER BY id LIMIT 5000").fetchall()
        alg = bank.state(ROLE)["settle_alg"]
        csv = "transfer_id,debit,credit,amount\n" + "".join(f"{r[0]},{r[1]},{r[2]},{r[3]}\n" for r in rows)
        data = csv.encode()
        bid = conn.execute("INSERT INTO batches(created, n, total, alg, status) VALUES (%s,%s,%s,%s,'sending') RETURNING id",
                           (time.time(), len(rows), sum(r[3] for r in rows), alg)).fetchone()[0]
        conn.commit()
        try:
            sig, kid = bank.kms_sign("settlement", alg, data)
            code, r = bank.egress("POST", "/clearing/batches", {"bank": "PQBANK", "batch_id": bid, "alg": alg, "kid": kid,
                                                                "file_b64": bank.b64u(data), "sig_b64": bank.b64u(sig)}, timeout=20)
            accepted = code == 200 and r.get("accepted")
            reason = r.get("reason") or r.get("error") or f"HTTP {code}"
        except Exception as e:
            kid, accepted, reason = None, False, str(e)[:200]
        conn.execute("UPDATE batches SET kid=%s, status=%s, reason=%s WHERE id=%s",
                     (kid, "accepted" if accepted else "rejected", reason, bid))
        if accepted and rows:
            conn.execute("UPDATE transfers SET batch_id=%s WHERE id = ANY(%s)", (bid, [r[0] for r in rows]))
        return {"batch_id": bid, "transfers": len(rows), "alg": alg, "kid": kid, "accepted": accepted, "reason": reason}


def loop():
    time.sleep(20)
    while True:
        try:
            settle()
        except Exception:
            pass
        time.sleep(30)


class Settlement(bank.Handler):
    routes = {("POST", "/settle"): "settle_now", ("GET", "/batches/last"): "last"}

    def settle_now(self):
        self.reply(200, settle())

    def last(self):
        with bank.db() as conn:
            r = conn.execute("SELECT id, created, n, total, alg, kid, status, reason FROM batches ORDER BY id DESC LIMIT 1").fetchone()
        keys = ["batch_id", "created", "transfers", "total", "alg", "kid", "status", "reason"]
        self.reply(200, dict(zip(keys, r)) if r else {})


if __name__ == "__main__":
    bank.serve(Settlement, background=loop)
