"""Migration task catalogue for PQBank, derived from the bank's call graph (config.CALLS).

A task is one change a bank engineer would put into a change window. It sets fields in the crypto state
(`sets`), adds an algorithm to an accepted/published list (`adds`), and may have a side effect (issue the PQ PKI,
create a KMS key, hand the partner a key). `deps` are hard compatibility prerequisites: they must be in effect in
an EARLIER window, or some peer cannot verify the new crypto.

Families (37 tasks):
  pki.pq-root            SLH-DSA root CA + FN-DSA leaf certificates for every node (QRNG-seeded)
  trust.<svc>     x8     add the SLH-DSA root to a service's trust store
  kex.<svc>       x8     enable hybrid X25519+HQC-1 key exchange
  cert.<svc>      x8     switch a service's mTLS identity to FN-DSA-512 (needs every peer that verifies it to trust the root)
  partner.clearing       the clearing house (external) trusts the root and the bank's SLH-DSA settlement key
  kms.key-*       x3     create FN-DSA / SLH-DSA signing keys inside the KMS
  jwt.*           x4     publish the FN-DSA key in JWKS -> verifiers accept it -> identity signs with it
  audit.sign-fndsa       ledger signs new audit entries with FN-DSA
  settle.sign-slhdsa     settlement files signed with SLH-DSA (after the partner trusts the key)
  pqonly.<svc>    x2     PQ-only key exchange on internal-only services (postgres, kms) once every client speaks HQC
"""
from . import config, qrng, testbed

J, S = config.PQ["jwt_alg"], config.PQ["settle_alg"]
BANK = list(config.SERVICES)
TASKS = []


def _task(tid, service, kind, effort, title, deps=(), sets=None, adds=None, effect=None):
    TASKS.append({"id": tid, "service": service, "kind": kind, "effort": effort, "title": title, "deps": list(deps),
                  "sets": sets or {}, "adds": adds or {}, "effect": effect})


def clients_of(svc):
    return [c for c, t in config.CALLS if t == svc]


def peers_verifying(svc):
    """Nodes that verify svc's certificate: servers svc calls (client cert) + clients that call svc (server cert)."""
    return sorted({t for c, t in config.CALLS if c == svc} | set(clients_of(svc)))


_task("pki.pq-root", "pki", "enabler", 2, "Issue SLH-DSA root CA + FN-DSA-512 certificates for every node (QRNG-seeded)",
      effect=("pki",))
for s in BANK:
    _task(f"trust.{s}", s, "enabler", 1, f"Add the SLH-DSA root to {s}'s trust store", ["pki.pq-root"],
          sets={s: {"trust": "both"}})
for s in BANK:
    _task(f"kex.{s}", s, "confidentiality", 1, f"Enable hybrid X25519+HQC-1 key exchange on {s}", sets={s: {"kex": "hybrid"}})
for s in BANK:
    deps = [f"trust.{p}" for p in peers_verifying(s) if p in BANK] + (["partner.clearing"] if "clearing" in peers_verifying(s) else [])
    _task(f"cert.{s}", s, "authentication", 1, f"Switch {s}'s mTLS identity to FN-DSA-512" + (" (internal side)" if s == "gateway" else ""),
          deps, sets={s: {"cert": "pq"}})
_task("kms.key-settlement", "kms", "enabler", 1, "KMS: create the SLH-DSA settlement signing key (QRNG-seeded)",
      effect=("kmskey", "settlement", "slhdsa"))
_task("partner.clearing", "clearing", "enabler", 2,
      "Clearing house (partner) trusts the SLH-DSA root and the bank's SLH-DSA settlement key, accepts SLH-DSA batches",
      ["pki.pq-root", "kms.key-settlement"], sets={"clearing": {"trust": "both", "kex": "hybrid"}},
      adds={"clearing": {"accept_settle": S}}, effect=("clearing-trust", "settlement", "slhdsa"))
_task("kms.key-jwt", "kms", "enabler", 1, "KMS: create the FN-DSA-512 token-signing key (QRNG-seeded)",
      effect=("kmskey", "jwt", "fndsa"))
_task("jwt.publish", "identity", "enabler", 1, "Identity publishes the FN-DSA key in JWKS, next to the RSA key", ["kms.key-jwt"],
      adds={"identity": {"jwt_publish": J}})
for v in ("accounts", "payments"):
    _task(f"jwt.accept-{v}", v, "enabler", 1, f"{v} accepts FN-DSA-512 access tokens (RS256 still accepted)", ["jwt.publish"],
          adds={v: {"jwt_accept": J}})
_task("jwt.sign-fndsa", "identity", "authentication", 1, "Identity signs new access tokens with FN-DSA-512",
      ["jwt.accept-accounts", "jwt.accept-payments"], sets={"identity": {"jwt_alg": J}})
_task("kms.key-audit", "kms", "enabler", 1, "KMS: create the FN-DSA-512 audit-log signing key (QRNG-seeded)",
      effect=("kmskey", "audit", "fndsa"))
_task("audit.sign-fndsa", "ledger", "authentication", 1, "Ledger signs new audit entries with FN-DSA-512 (old entries keep RSA)",
      ["kms.key-audit"], sets={"ledger": {"audit_alg": J}})
_task("settle.sign-slhdsa", "settlement", "authentication", 1, "Settlement batch files signed with SLH-DSA",
      ["partner.clearing"], sets={"settlement": {"settle_alg": S}})
for srv in ("postgres", "kms"):
    _task(f"pqonly.{srv}", srv, "confidentiality", 1, f"Enforce PQ-only HQC-1 key exchange on {srv} (internal only)",
          [f"kex.{srv}"] + [f"kex.{c}" for c in clients_of(srv)], sets={srv: {"kex": "pq-only"}})

TASK_BY_ID = {t["id"]: t for t in TASKS}

# Kept out of the plan on purpose: customers' apps trust only the RSA root and offer classical groups.
DEFERRED = [{"id": "cert.gateway-public", "service": "gateway",
             "title": "Switch the public gateway certificate to FN-DSA-512",
             "reason": "Blocked: customer apps cannot validate FN-DSA / SLH-DSA certificates yet"}]
DEFERRED_TASK = {**DEFERRED[0], "kind": "authentication", "effort": 1, "deps": ["pki.pq-root"],
                 "sets": {"gateway": {"public_cert": "pq"}}, "adds": {}, "effect": None}

# Never change all three of these in one window: if it breaks, you cannot tell which change did it.
BLAST_TRIPLES = [("cert.gateway", "cert.payments", "cert.ledger"),        # the money path
                 ("kex.gateway", "kex.payments", "kex.ledger"),
                 ("cert.kms", "cert.identity", "cert.ledger"),             # key custody and signers
                 ("jwt.sign-fndsa", "audit.sign-fndsa", "settle.sign-slhdsa")]  # every signature algorithm at once
# Month-end close: no changes to the books, settlement or the database in this window index.
BLACKOUT = {"window": 1, "services": ["ledger", "settlement", "postgres"], "reason": "Month-end close"}


def _effect_done(effect, st):
    if not effect:
        return True
    if effect[0] == "pki":
        return bool(st["_pki"].get("pq_root"))
    if effect[0] == "kmskey":
        return testbed.kms_has(effect[1], effect[2])
    if effect[0] == "clearing-trust":
        return (testbed.CLEARING_TRUST / f"{effect[1]}-{effect[2]}.pem").exists()
    return False


def done(task, st):
    """A task is in effect when every field it sets / adds is in the state and its side effect exists."""
    for svc, fields in task["sets"].items():
        if any(st.get(svc, {}).get(f) != v for f, v in fields.items()):
            return False
    for svc, fields in task["adds"].items():
        if any(v not in st.get(svc, {}).get(f, []) for f, v in fields.items()):
            return False
    return _effect_done(task["effect"], st)


def apply(task_id, st):
    """Run a task's side effect, mutate the state. Returns the services whose nginx config must be reloaded."""
    t = TASK_BY_ID[task_id]
    eff = t["effect"]
    if eff and not _effect_done(eff, st):
        if eff[0] == "pki":
            seeds, _ = qrng.key_seeds(["root"] + testbed.IDENTITIES, purpose="slhdsa-root+fndsa-leaf-pki")
            testbed.pki_issue_pq(seeds)
            st["_pki"]["pq_root"] = True
        elif eff[0] == "kmskey":
            seeds, _ = qrng.key_seeds([f"{eff[1]}-{eff[2]}"], purpose=f"kms-{eff[1]}-{eff[2]}")
            testbed.kms_keygen(eff[1], eff[2], seeds[f"{eff[1]}-{eff[2]}"])
        elif eff[0] == "clearing-trust":
            testbed.clearing_trust_key(eff[1], eff[2])
    changed = set()
    for svc, fields in t["sets"].items():
        st[svc].update(fields)
        changed.add(svc)
    for svc, fields in t["adds"].items():
        for f, v in fields.items():
            if v not in st[svc][f]:
                st[svc][f] = st[svc][f] + [v]
        changed.add(svc)
    return sorted(c for c in changed if c in testbed.ROLES)
