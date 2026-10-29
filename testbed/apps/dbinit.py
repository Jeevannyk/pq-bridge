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
"""
# 20 everyday customers (used by the customer app), one low-balance customer and one test customer for the gate.
CUSTOMERS = [(f"cust{i:03d}", f"Passw0rd!{i:03d}", 1_000_000_00) for i in range(1, 21)] + \
            [("cust099", "Passw0rd!099", 100_00), ("gatetest", "Gate-Test-Pass-1", 1_000_000_00)]


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
    print("bank database ready", flush=True)


if __name__ == "__main__":
    main()
