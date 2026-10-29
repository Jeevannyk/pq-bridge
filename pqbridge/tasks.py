"""Migration task catalogue for the testbed bank.

Each task is one change a bank engineer would schedule into a change window.
`deps` are hard compatibility prerequisites: the dependency must be done in an
EARLIER window, otherwise some peer cannot validate the new crypto.
"""
from . import qrng, testbed

# kind drives which risk component a task retires (see risk.task_risk):
#   confidentiality -> harvest-now-decrypt-later exposure (key exchange)
#   authentication  -> forgery after Q-day (certs, JWT signatures)
#   enabler         -> prerequisite with no direct risk reduction (PKI, trust stores)
TASKS = [
    {"id": "pki.pq-root", "service": "pki", "kind": "enabler", "effort": 2,
     "title": "Issue SLH-DSA root CA + FN-DSA-512 leaf certs (QRNG-seeded keys)", "deps": []},
    *[{"id": f"trust.{s}", "service": s, "kind": "enabler", "effort": 1,
       "title": f"Add SLH-DSA root to {s} trust store", "deps": ["pki.pq-root"]}
      for s in ["gateway", "card-auth", "payment-switch", "ledger"]],
    *[{"id": f"kex.{s}", "service": s, "kind": "confidentiality", "effort": 1,
       "title": f"Enable hybrid X25519+HQC-1 key exchange on {s}", "deps": []}
      for s in ["gateway", "card-auth", "payment-switch", "ledger"]],
    {"id": "cert.card-auth", "service": "card-auth", "kind": "authentication", "effort": 1,
     "title": "Switch card-auth TLS identity to FN-DSA-512", "deps": ["trust.gateway"]},
    {"id": "cert.payment-switch", "service": "payment-switch", "kind": "authentication", "effort": 1,
     "title": "Switch payment-switch TLS identity to FN-DSA-512", "deps": ["trust.gateway", "trust.ledger"]},
    {"id": "cert.ledger", "service": "ledger", "kind": "authentication", "effort": 1,
     "title": "Switch ledger TLS identity to FN-DSA-512", "deps": ["trust.payment-switch"]},
    {"id": "cert.gateway", "service": "gateway", "kind": "authentication", "effort": 1,
     "title": "Switch gateway internal mTLS identity to FN-DSA-512", "deps": ["trust.card-auth", "trust.payment-switch"]},
    {"id": "jwt.dual-verify", "service": "payment-switch", "kind": "enabler", "effort": 1,
     "title": "Publish FN-DSA JWT key; payment-switch accepts RS256 + FN-DSA-512", "deps": []},
    {"id": "jwt.sign-fndsa", "service": "card-auth", "kind": "authentication", "effort": 1,
     "title": "card-auth signs JWTs with FN-DSA-512", "deps": ["jwt.dual-verify"]},
    {"id": "pqonly.ledger", "service": "ledger", "kind": "confidentiality", "effort": 1,
     "title": "Enforce PQ-only HQC-1 key exchange on ledger", "deps": ["kex.payment-switch", "kex.ledger"]},
]
TASK_BY_ID = {t["id"]: t for t in TASKS}

# Kept out of the plan on purpose: legacy customers trust only the RSA root.
DEFERRED = [{"id": "cert.gateway-public", "service": "gateway",
             "title": "Switch public gateway certificate to FN-DSA-512",
             "reason": "Blocked: legacy customer clients cannot validate FN-DSA / SLH-DSA certificates yet"}]

# The deferred task as an applicable task: it needs the PQ PKI (its certificate files) like every other cert task.
DEFERRED_TASK = {**DEFERRED[0], "kind": "authentication", "effort": 1, "deps": ["pki.pq-root"]}

# Three changes on the same payment path in one window = blast radius too large to isolate a failure.
BLAST_TRIPLES = [("cert.gateway", "cert.payment-switch", "cert.ledger"),
                 ("kex.gateway", "kex.payment-switch", "kex.ledger")]
# Month-end settlement freeze: no ledger changes in this window index.
BLACKOUT = {"window": 1, "services": ["ledger"], "reason": "Month-end settlement freeze"}


def apply(task_id, st):
    """Mutate state for a task, run its side effects. Returns the list of services to reload."""
    if task_id == "pki.pq-root":
        if not st["_pki"]["pq_root"]:
            seeds, _ = qrng.key_seeds(["root"] + testbed.IDENTITIES, purpose="slhdsa-root+fndsa-leaf-pki")
            testbed.pki_issue_pq(seeds)
            st["_pki"]["pq_root"] = True
        return []
    kind, svc = task_id.split(".", 1)
    if kind == "trust":
        st[svc]["trust"] = "both"
    elif kind == "kex":
        st[svc]["kex"] = "hybrid"
    elif kind == "pqonly":
        st[svc]["kex"] = "pq-only"
    elif kind == "cert" and svc == "gateway-public":
        st["gateway"]["public_cert"] = "pq"
        svc = "gateway"
    elif kind == "cert":
        st[svc]["cert"] = "pq"
    elif task_id == "jwt.dual-verify":
        if not st["_pki"]["jwt_pq_key"]:
            seeds, _ = qrng.key_seeds(["jwt"], purpose="fndsa-jwt")
            testbed.pki_jwt_pq(seeds["jwt"])
            st["_pki"]["jwt_pq_key"] = True
        st["payment-switch"]["jwt_accept"] = ["RS256", "FN-DSA-512"]
        svc = "payment-switch"
    elif task_id == "jwt.sign-fndsa":
        st["card-auth"]["jwt_alg"] = "FN-DSA-512"
        svc = "card-auth"
    else:
        raise ValueError(task_id)
    return [svc]
