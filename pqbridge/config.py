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

# Bank services in the testbed. Values feed the risk model (Module 2).
#   shelf_life_years: how long data protected by this service must stay confidential
#   exposure: 1.0 internet-facing, 0.5 internal
#   criticality: 1.0 on the payment path
SERVICES = {
    "gateway":        {"desc": "Public API gateway (net-banking + mobile)", "shelf_life_years": 7,  "exposure": 1.0, "criticality": 1.0},
    "card-auth":      {"desc": "Card authorisation, issues JWTs",          "shelf_life_years": 1,  "exposure": 0.5, "criticality": 1.0},
    "payment-switch": {"desc": "Payment switch, verifies JWTs, routes tx", "shelf_life_years": 7,  "exposure": 0.5, "criticality": 1.0},
    "ledger":         {"desc": "Core ledger (account balances)",           "shelf_life_years": 10, "exposure": 0.5, "criticality": 1.0},
}

# Which service calls which (client -> server) over mTLS.
CALLS = [("gateway", "card-auth"), ("gateway", "payment-switch"), ("payment-switch", "ledger")]

# Baseline crypto posture: everything classical.
INITIAL_STATE = {
    "gateway":        {"kex": "classical", "public_cert": "rsa", "cert": "rsa", "trust": "rsa"},
    "card-auth":      {"kex": "classical", "cert": "rsa", "trust": "rsa", "jwt_alg": "RS256"},
    "payment-switch": {"kex": "classical", "cert": "rsa", "trust": "rsa", "jwt_accept": ["RS256"]},
    "ledger":         {"kex": "classical", "cert": "rsa", "trust": "rsa"},
    "_pki":           {"pq_root": False, "jwt_pq_key": False},
}

# Post-quantum suite (team decision): HQC key exchange, FN-DSA-512 leaf certificates and JWTs,
# SLH-DSA root CA. ML-KEM / ML-DSA are deliberately not used.
PQ = {
    "hybrid_group": "x25519_hqc1",          # X25519 + HQC-1 (oqs-provider)
    "pq_group": "hqc1",                     # HQC-1 only
    "leaf_sig": "falcon512",                # FN-DSA-512 (Falcon) via oqs-provider
    "root_sig": "SLH-DSA-SHA2-128s",        # FIPS 205, native in OpenSSL 3.5
    "jwt_alg": "FN-DSA-512",
}
GROUPS = {
    "classical": "X25519:prime256v1",
    "hybrid": f"{PQ['hybrid_group']}:X25519:prime256v1",
    "pq-only": PQ["pq_group"],
}

# Quantum-threat horizon used in Mosca's inequality (years until a CRQC; assumption, configurable).
CRQC_YEARS = float(os.environ.get("PQB_CRQC_YEARS", "8"))
MIGRATION_YEARS = float(os.environ.get("PQB_MIGRATION_YEARS", "3"))
