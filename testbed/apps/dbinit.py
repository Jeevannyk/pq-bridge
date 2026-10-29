"""Create the bank database, schema and seed customers (runs inside the postgres container, local socket)."""
import hashlib
import os
import time

import psycopg

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, pw_hash TEXT NOT NULL,
  pw_salt TEXT NOT NULL, failed INT NOT NULL DEFAULT 0, locked_until DOUBLE PRECISION NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers,
  balance BIGINT NOT NULL CHECK (balance >= 0), currency TEXT NOT NULL DEFAULT 'INR');
CREATE TABLE IF NOT EXISTS refresh_tokens(hash TEXT PRIMARY KEY, customer_id TEXT NOT NULL, expires DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS transfers(id BIGSERIAL PRIMARY KEY, customer_id TEXT NOT NULL, idem_key TEXT NOT NULL,
  from_account TEXT, to_account TEXT, amount BIGINT, status TEXT NOT NULL, response JSONB, created DOUBLE PRECISION,
  batch_id BIGINT, UNIQUE(customer_id, idem_key));
CREATE TABLE IF NOT EXISTS journal(id BIGSERIAL PRIMARY KEY, transfer_id BIGINT, account_id TEXT, debit BIGINT NOT NULL,
  credit BIGINT NOT NULL, ts DOUBLE PRECISION);
CREATE TABLE IF NOT EXISTS audit_log(seq BIGINT PRIMARY KEY, transfer_id BIGINT UNIQUE, entry TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL,
  alg TEXT NOT NULL, kid TEXT NOT NULL, sig TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_head(seq BIGINT NOT NULL, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS batches(id BIGSERIAL PRIMARY KEY, created DOUBLE PRECISION, n INT, total BIGINT, alg TEXT,
  kid TEXT, status TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS seed_total(total BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS transfers_unsettled ON transfers(status, batch_id);
ALTER TABLE customers ADD COLUMN IF NOT EXISTS full_name TEXT;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS phone TEXT;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS last_login DOUBLE PRECISION;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'Savings';
ALTER TABLE transfers ADD COLUMN IF NOT EXISTS memo TEXT;
CREATE TABLE IF NOT EXISTS payees(customer_id TEXT NOT NULL, account_id TEXT NOT NULL, nickname TEXT NOT NULL,
  added DOUBLE PRECISION NOT NULL, PRIMARY KEY(customer_id, account_id));
CREATE INDEX IF NOT EXISTS journal_account ON journal(account_id, id);
"""
# The only seeded accounts are the verification gate's: a payer, a counterparty and a low-balance account for the
# overdraft check. They are automated, never people, and are excluded from the dashboard's customer figures.
# Real customers (DEMO, below) are the only ones who generate bank activity.
CUSTOMERS = [("gatetest", "Gate-Test-Pass-1", 1_000_000_00), ("gatepeer", "Gate-Peer-Pass-1", 1_000_000_00),
             ("gatepoor", "Gate-Poor-Pass-1", 100_00)]
NAMES = ["Verification gate payer", "Verification gate counterparty", "Verification gate low-balance account"]
# Named customers for hands-on use of the NetBank web app: a savings and a current account each.
DEMO = [("vamsh", "vamsh", "Vamsh Rai", 500_000_00, 50_000_00),
        ("rahul", "Rahul#Bank2026", "Rahul Verma", 300_000_00, 25_000_00),
        ("meera", "Meera#Bank2026", "Meera Iyer", 750_000_00, 100_000_00)]


def scrypt(pw, salt):
    return hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1).hex()


def main():
    admin = None
    for _ in range(60):
        try:
            admin = psycopg.connect("host=/run/postgresql port=5433 user=postgres dbname=postgres", autocommit=True)
            break
        except psycopg.OperationalError:
            time.sleep(1)
    if admin is None:
        raise SystemExit("postgres did not start; see /data/pg/server.log")
    if not admin.execute("SELECT 1 FROM pg_roles WHERE rolname='bank'").fetchone():
        admin.execute("CREATE ROLE bank LOGIN PASSWORD 'bank-db-pass'")
    if not admin.execute("SELECT 1 FROM pg_database WHERE datname='bank'").fetchone():
        admin.execute("CREATE DATABASE bank OWNER bank")
    with psycopg.connect("host=/run/postgresql port=5433 user=bank dbname=bank") as c:
        c.execute(SCHEMA)
        if not c.execute("SELECT 1 FROM customers LIMIT 1").fetchone():
            total = 0
            for i, (user, pw, bal) in enumerate(CUSTOMERS):
                salt = os.urandom(16)
                cid = f"C{i + 1:04d}"
                c.execute("INSERT INTO customers(id, username, pw_hash, pw_salt) VALUES (%s,%s,%s,%s)",
                          (cid, user, scrypt(pw, salt), salt.hex()))
                c.execute("INSERT INTO accounts(id, customer_id, balance) VALUES (%s,%s,%s)", (f"ACC-{i + 1:04d}", cid, bal))
                total += bal
            c.execute("INSERT INTO seed_total VALUES (%s)", (total,))
            c.execute("INSERT INTO audit_head VALUES (0, %s)", ("0" * 64,))
        for (user, _, _), name in zip(CUSTOMERS, NAMES):
            c.execute("UPDATE customers SET full_name=%s, email=COALESCE(email, %s) WHERE username=%s",
                      (name, f"{user}@pqbank.example", user))
        for user, pw, name, savings, current in DEMO:
            if c.execute("SELECT 1 FROM customers WHERE username=%s", (user,)).fetchone():
                continue
            n = c.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
            a = c.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
            salt = os.urandom(16)
            cid = f"C{n + 1:04d}"
            c.execute("INSERT INTO customers(id, username, pw_hash, pw_salt, full_name, email, phone) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                      (cid, user, scrypt(pw, salt), salt.hex(), name, f"{user}@pqbank.example", f"+91 98{n:08d}"))
            for k, (kind, bal) in enumerate([("Savings", savings), ("Current", current)]):
                c.execute("INSERT INTO accounts(id, customer_id, balance, type) VALUES (%s,%s,%s,%s)", (f"ACC-{a + k + 1:04d}", cid, bal, kind))
            c.execute("UPDATE seed_total SET total = total + %s", (savings + current,))
    print("bank database ready", flush=True)


if __name__ == "__main__":
    main()
