"""Clearing house (external partner, simulated). Accepts a bank's settlement batch only if the signature verifies
with a bank key it has been given (/clearing-trust/*.pem) and the algorithm is on its accepted list. The bank
cannot change this side by itself: migrating the settlement signature needs the partner to trust the new key first.

  POST /batches       {bank, batch_id, alg, kid, file_b64, sig_b64}
  GET  /batches/last
"""
import glob
import json
import sqlite3
import subprocess
import threading
import time

import bank

ROLE = "clearing"
_lock = threading.Lock()


def trusted_keys():
    out = {}
    for pem in glob.glob("/clearing-trust/*.pem"):
        der = subprocess.run(["openssl", "pkey", "-pubin", "-in", pem, "-outform", "DER"], capture_output=True).stdout
        out[bank.sha256_hex(der)[:8]] = open(pem).read()
    return out


def store():
    c = sqlite3.connect("/data/clearing.db")
    c.execute("CREATE TABLE IF NOT EXISTS batches(id INTEGER PRIMARY KEY, bank TEXT, batch_id INT, alg TEXT, kid TEXT, "
              "n INT, accepted INT, reason TEXT, ts REAL)")
    return c


class Clearing(bank.Handler):
    routes = {("POST", "/batches"): "receive", ("GET", "/batches/last"): "last"}

    def receive(self):
        b = self.body()
        alg, kid = b.get("alg"), b.get("kid") or ""
        data, sig = bank.b64u_dec(b["file_b64"]), bank.b64u_dec(b["sig_b64"])
        accepted_algs = bank.state(ROLE).get("accept_settle", [])
        pem = trusted_keys().get(kid.rsplit("-", 1)[-1])
        if alg not in accepted_algs:
            ok, reason = False, f"algorithm {alg} not accepted (accepts {accepted_algs})"
        elif not pem:
            ok, reason = False, f"key {kid} is not trusted by the clearing house"
        elif not bank.openssl_verify(alg, pem, data, sig):
            ok, reason = False, "signature does not verify"
        else:
            ok, reason = True, "signature verified"
        n = max(0, data.decode().count("\n") - 1)
        with _lock:
            c = store()
            c.execute("INSERT INTO batches(bank, batch_id, alg, kid, n, accepted, reason, ts) VALUES (?,?,?,?,?,?,?,?)",
                      (b.get("bank"), b.get("batch_id"), alg, kid, n, int(ok), reason, time.time()))
            c.commit()
        self.reply(200, {"accepted": ok, "reason": reason, "transfers": n})

    def last(self):
        with _lock:
            r = store().execute("SELECT bank, batch_id, alg, kid, n, accepted, reason, ts FROM batches ORDER BY id DESC LIMIT 1").fetchone()
        keys = ["bank", "batch_id", "alg", "kid", "transfers", "accepted", "reason", "ts"]
        self.reply(200, dict(zip(keys, r)) if r else {})


if __name__ == "__main__":
    bank.serve(Clearing)
