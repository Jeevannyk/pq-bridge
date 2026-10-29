"""Ledger: double-entry books and a tamper-evident audit log.

  POST /post           {transfer_id, from_account, to_account, amount}  (called by payments over mTLS)
                       one DB transaction: no overdraft, two journal lines, balances, one audit entry
  GET  /audit/verify   recompute the full hash chain; verify signatures on the newest entries + a random sample
  GET  /stats          totals: money in the system, journal balance, transfer count

Audit entry: hash = SHA-256(previous hash || canonical entry); the hash is signed by the KMS with the ledger's
audit algorithm (RS256 -> FN-DSA-512 during migration). Each entry stores its kid and alg, so entries signed
before a migration stay verifiable after it.
"""
import json
import random
import time

import bank

ROLE = "ledger"
GENESIS = "0" * 64


class Ledger(bank.Handler):
    routes = {("POST", "/post"): "post", ("GET", "/audit/verify"): "verify", ("GET", "/stats"): "stats"}

    def post(self):
        if self.client_cn() != "payments":
            return self.reply(403, {"error": "only payments may post to the ledger"})
        b = self.body()
        src, dst, amount, tid = b["from_account"], b["to_account"], int(b["amount"]), int(b["transfer_id"])
        alg = bank.state(ROLE)["audit_alg"]
        with bank.db() as conn:
            conn.execute("SELECT seq FROM audit_head FOR UPDATE")                      # serialise the chain
            done = conn.execute("SELECT seq, alg, kid FROM audit_log WHERE transfer_id=%s", (tid,)).fetchone()
            if done:                                                                   # retried request: post once
                return self.reply(200, {"transfer_id": tid, "audit_seq": done[0], "alg": done[1], "kid": done[2], "replayed": True})
            closed = conn.execute("SELECT status FROM transfers WHERE id=%s", (tid,)).fetchone()
            if closed and closed[0] == "rejected":                                     # payments told the customer it failed
                return self.reply(422, {"error": "payment was already failed; not posting"})
            bal = dict(conn.execute("SELECT id, balance FROM accounts WHERE id = ANY(%s) ORDER BY id FOR UPDATE",
                                    ([src, dst],)).fetchall())
            if len(bal) != 2:
                return self.reply(422, {"error": "unknown account"})
            if bal[src] < amount:
                return self.reply(422, {"error": "insufficient funds"})
            now = time.time()
            conn.execute("INSERT INTO journal(transfer_id, account_id, debit, credit, ts) VALUES (%s,%s,%s,0,%s),(%s,%s,0,%s,%s)",
                         (tid, src, amount, now, tid, dst, amount, now))
            conn.execute("UPDATE accounts SET balance = balance - %s WHERE id=%s", (amount, src))
            conn.execute("UPDATE accounts SET balance = balance + %s WHERE id=%s", (amount, dst))
            seq, prev = conn.execute("SELECT seq, hash FROM audit_head").fetchone()
            entry = bank.canon({"seq": seq + 1, "transfer_id": tid, "debit": src, "credit": dst, "amount": amount, "ts": now})
            h = bank.sha256_hex(bytes.fromhex(prev) + entry)
            sig, kid = bank.kms_sign("audit", alg, bytes.fromhex(h))
            conn.execute("INSERT INTO audit_log(seq, transfer_id, entry, prev_hash, hash, alg, kid, sig) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                         (seq + 1, tid, entry.decode(), prev, h, alg, kid, bank.b64u(sig)))
            conn.execute("UPDATE audit_head SET seq=%s, hash=%s", (seq + 1, h))
        self.reply(200, {"transfer_id": tid, "audit_seq": seq + 1, "alg": alg, "kid": kid})

    def verify(self):
        sample = 40
        with bank.db() as conn:
            rows = conn.execute("SELECT seq, entry, prev_hash, hash, alg, kid, sig FROM audit_log ORDER BY seq").fetchall()
        prev, broken = GENESIS, None
        for seq, entry, p, h, *_ in rows:
            if p != prev or bank.sha256_hex(bytes.fromhex(p) + entry.encode()) != h:
                broken = seq
                break
            prev = h
        keys = {k["kid"]: k for k in bank.kms_keys(max_age=0)}
        pick = rows[-sample:] + random.sample(rows[:-sample], min(sample, max(0, len(rows) - sample)))
        bad, algs = [], {}
        for seq, _, _, h, alg, kid, sig in pick:
            algs[alg] = algs.get(alg, 0) + 1
            k = keys.get(kid)
            if not k or not bank.openssl_verify(alg, bank.spki_to_pem(bank.b64u_dec(k["spki"])), bytes.fromhex(h), bank.b64u_dec(sig)):
                bad.append(seq)
        all_algs = {}
        for r in rows:
            all_algs[r[4]] = all_algs.get(r[4], 0) + 1
        self.reply(200, {"ok": broken is None and not bad, "entries": len(rows), "hash_chain_ok": broken is None,
                         "first_broken_seq": broken, "signatures_checked": len(pick), "signatures_failed": bad[:10],
                         "checked_by_alg": algs, "entries_by_alg": all_algs})

    def stats(self):
        with bank.db() as conn:
            total, n = conn.execute("SELECT COALESCE(SUM(balance),0)::bigint, COUNT(*) FROM accounts").fetchone()
            d, c = conn.execute("SELECT COALESCE(SUM(debit),0)::bigint, COALESCE(SUM(credit),0)::bigint FROM journal").fetchone()
            tx = conn.execute("SELECT COUNT(*) FROM transfers WHERE status='posted'").fetchone()[0]
            seed = conn.execute("SELECT total FROM seed_total").fetchone()[0]
        self.reply(200, {"tx_count": tx, "accounts": n, "total_balance": total, "seed_total": seed,
                         "money_conserved": total == seed, "journal_balanced": d == c, "debits": d, "credits": c})


if __name__ == "__main__":
    bank.serve(Ledger)
