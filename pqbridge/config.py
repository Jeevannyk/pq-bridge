"""Paths, environment and the bank's service catalogue."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTBED = ROOT / "testbed"
RUNTIME = TESTBED / "runtime"
PKI = RUNTIME / "pki"
STATE = RUNTIME / "state"
CONF = RUNTIME / "conf"
EVIDENCE = ROOT / "evidence"
CORPUS = ROOT / "corpus"


def load_env():
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"'))


load_env()
QPIAI_OPT_API_KEY = os.environ.get("QPIAI_OPT_API_KEY")
QCLOUD_API_KEY = os.environ.get("QCLOUD_API_KEY")
# QpiAI-QSV-Local runs the QpiAI simulator in-process; set QCLOUD_DEVICE to a cloud device to use QCloud.
QCLOUD_DEVICE = os.environ.get("QCLOUD_DEVICE", "QpiAI-QSV-Local")

# The bank. Values feed the risk model (Module 2).
#   shelf_life_years: how long data protected by this service must stay confidential
#   exposure: 1.0 internet-facing, 0.5 internal
#   criticality: 1.0 on the money path
SERVICES = {
    "gateway":    {"desc": "Public API gateway: TLS for customers, rate limiting, routing",    "shelf_life_years": 7,  "exposure": 1.0, "criticality": 1.0},
    "identity":   {"desc": "Customer login (scrypt), OAuth2 access + refresh tokens, JWKS",      "shelf_life_years": 5,  "exposure": 0.5, "criticality": 1.0},
    "accounts":   {"desc": "Customer accounts and balances",                                     "shelf_life_years": 10, "exposure": 0.5, "criticality": 0.8},
    "payments":   {"desc": "Transfers: scopes, idempotency keys, limits, fraud rule",            "shelf_life_years": 7,  "exposure": 0.5, "criticality": 1.0},
    "ledger":     {"desc": "Double-entry books, signed hash-chained audit log",                  "shelf_life_years": 10, "exposure": 0.5, "criticality": 1.0},
    "kms":        {"desc": "Key management: holds signing keys, signs for authorised services",  "shelf_life_years": 10, "exposure": 0.5, "criticality": 1.0},
    "settlement": {"desc": "End-of-day signed batch file to the clearing house",                 "shelf_life_years": 10, "exposure": 0.5, "criticality": 0.8},
    "postgres":   {"desc": "Bank database (PostgreSQL 17) behind mTLS",                         "shelf_life_years": 10, "exposure": 0.5, "criticality": 1.0},
}
# External partner: we coordinate with it, we do not migrate it ourselves.
PARTNERS = {"clearing": {"desc": "Clearing house (external): receives signed settlement batches"}}

# Who calls whom over mTLS (client -> server). Drives nginx egress config, cert/trust dependencies,
# PQ-only prerequisites and the blast-radius rules.
CALLS = [
    ("gateway", "identity"), ("gateway", "accounts"), ("gateway", "payments"),
    ("identity", "kms"), ("identity", "postgres"),
    ("accounts", "identity"), ("accounts", "postgres"),
    ("payments", "identity"), ("payments", "ledger"), ("payments", "postgres"),
    ("ledger", "kms"), ("ledger", "postgres"),
    ("settlement", "kms"), ("settlement", "postgres"), ("settlement", "clearing"),
]

_net = {"kex": "classical", "cert": "rsa", "trust": "rsa"}
# Baseline crypto posture: everything classical.
INITIAL_STATE = {
    "gateway":    {**_net, "public_cert": "rsa"},
    "identity":   {**_net, "jwt_alg": "RS256", "jwt_publish": ["RS256"]},
    "accounts":   {**_net, "jwt_accept": ["RS256"]},
    "payments":   {**_net, "jwt_accept": ["RS256"]},
    "ledger":     {**_net, "audit_alg": "RS256"},
    "kms":        {**_net},
    "settlement": {**_net, "settle_alg": "RS256"},
    "postgres":   {**_net},
    "clearing":   {**_net, "accept_settle": ["RS256"]},
    "_pki":       {"pq_root": False},
}

# Post-quantum suite (team decision): HQC key exchange, FN-DSA-512 leaf certificates and JWTs,
# SLH-DSA root CA. ML-KEM / ML-DSA are deliberately not used.
PQ = {
    "hybrid_group": "x25519_hqc1",          # X25519 + HQC-1 (oqs-provider)
    "pq_group": "hqc1",                     # HQC-1 only
    "leaf_sig": "falcon512",                # FN-DSA-512 (Falcon) via oqs-provider
    "root_sig": "SLH-DSA-SHA2-128s",        # FIPS 205, native in OpenSSL 3.5
    "jwt_alg": "FN-DSA-512",            # OAuth2 access tokens and the audit log
    "settle_alg": "SLH-DSA-SHA2-128s",  # settlement files: low volume, long-lived, most conservative
}
GROUPS = {
    "classical": "X25519:prime256v1",
    "hybrid": f"{PQ['hybrid_group']}:X25519:prime256v1",
    "pq-only": PQ["pq_group"],
}

# Quantum-threat horizon used in Mosca's inequality (years until a CRQC; assumption, configurable).
CRQC_YEARS = float(os.environ.get("PQB_CRQC_YEARS", "8"))
MIGRATION_YEARS = float(os.environ.get("PQB_MIGRATION_YEARS", "3"))
