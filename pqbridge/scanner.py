"""Cryptographic discovery: code, configs, certificates/keys, dependency manifests, live endpoints.

Every finding carries evidence (file:line or endpoint) and a quantum status:
  quantum-vulnerable  broken by Shor (RSA, ECDSA, ECDH, EdDSA, X25519, DH, DSA)
  pq-safe             HQC / FN-DSA (Falcon) / SLH-DSA / ML-KEM / ML-DSA / hybrid groups (informational)
Comment lines and documentation are skipped; PQ / hybrid settings are not flagged.
"""
import json
import re
from pathlib import Path

from . import config

SKIP_DIRS = {".venv", "node_modules", ".git", "__pycache__", "evidence", "data"}
CODE_EXT = {".py", ".java", ".js", ".ts", ".go", ".sh", ".kt", ".cs", ".rb", ""}
CONF_EXT = {".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".properties"}
DOC_EXT = {".md", ".rst", ".txt", ".html"}
CERT_EXT = {".crt", ".pem", ".cer", ".key", ".pub"}

QV = "quantum-vulnerable"
PQ_NAMES = re.compile(r"HQC|falcon|FN-DSA|FNDSA|SLH-DSA|SLHDSA|SPHINCS|MLKEM|ML-KEM|ML-DSA|MLDSA|Kyber|Dilithium", re.I)

# (id, category, algorithm, regex, file-kind)
RULES = [
    ("py-rsa-keygen", "code", "RSA", r"\brsa\.generate_private_key\s*\(", "code"),
    ("py-ec-keygen", "code", "ECDSA/ECDH", r"\bec\.generate_private_key\s*\(", "code"),
    ("py-ecdh", "code", "ECDH", r"\bec\.ECDH\s*\(", "code"),
    ("py-dh", "code", "DH", r"\bdh\.generate_parameters\s*\(", "code"),
    ("py-ed-x25519", "code", "EdDSA/X25519", r"\b(Ed25519|Ed448|X25519|X448)PrivateKey\b", "code"),
    ("py-pycryptodome-rsa", "code", "RSA", r"\b(RSA|ECC|DSA)\.(generate|import_key|importKey|construct)\s*\(", "code"),
    ("jwt-asymmetric-alg", "code", "RSA/ECDSA (JWT)", r"""["'](RS|ES|PS)(256|384|512)["']""", "code"),
    ("java-keypairgen", "code", "RSA/EC/DSA/DH", r'KeyPairGenerator\.getInstance\(\s*"(RSA|EC|DSA|DH|DiffieHellman|Ed25519|X25519)"', "code"),
    ("java-signature", "code", "RSA/ECDSA signature", r'Signature\.getInstance\(\s*"\w*with(RSA|ECDSA|DSA)', "code"),
    ("java-keyagreement", "code", "ECDH/DH", r'KeyAgreement\.getInstance\(\s*"(ECDH|DH|DiffieHellman|X25519)"', "code"),
    ("java-cipher-rsa", "code", "RSA encryption", r'Cipher\.getInstance\(\s*"RSA', "code"),
    ("js-keypair", "code", "RSA/EC", r"""generateKeyPair(Sync)?\(\s*['"](rsa|ec|dsa|dh|ed25519|x25519)['"]""", "code"),
    ("js-ecdh", "code", "ECDH/DH", r"\bcreate(ECDH|DiffieHellman)\s*\(", "code"),
    ("go-asym", "code", "RSA/ECDSA", r"\b(rsa|ecdsa|ed25519)\.GenerateKey\(", "code"),
    ("go-curve", "code", "ECDH", r"\btls\.(CurveP256|CurveP384|CurveP521|X25519)\b", "code"),
    ("openssl-cli-classical", "code", "RSA/EC (OpenSSL CLI)",
     r"openssl\s+(genrsa|ecparam)\b|-newkey\s+rsa:|rsa:\d{4}|-algorithm\s+(RSA|EC)\b|rsa_keygen_bits", "code"),
    ("keytool-classical", "code", "RSA/EC keystore", r"-keyalg\s+(RSA|EC|DSA)\b", "code"),
    ("nginx-ecdh-curve", "config", "ECDH key exchange", r"\bssl_ecdh_curve\s+([^;]+);", "conf"),
    ("nginx-ciphers", "config", "ECDHE/RSA cipher suite", r"\bssl_ciphers\s+[^;]*(ECDHE|RSA)", "conf"),
    ("openssl-groups", "config", "ECDH key exchange", r"^\s*Groups\s*=\s*(.+)$", "conf"),
    ("ssh-classical", "config", "RSA/ECDSA/Ed25519 SSH", r"\b(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+|rsa-sha2-\d+)\b", "any"),
]
GROUP_RULES = {"nginx-ecdh-curve", "openssl-groups"}

DEP_LIBS = {
    "requirements": {"rsa": "RSA", "ecdsa": "ECDSA", "pycrypto": "RSA/ECC", "pycryptodome": "RSA/ECC",
                     "pycryptodomex": "RSA/ECC", "python-jose": "RSA/ECDSA JWT", "paramiko": "RSA/ECDSA SSH"},
    "package.json": {"node-rsa": "RSA", "jsonwebtoken": "RSA/ECDSA JWT", "elliptic": "ECDSA/ECDH",
                     "node-forge": "RSA", "jose": "RSA/ECDSA JWT"},
}

COMMENT = re.compile(r"^\s*(#|//|/\*|\*|--|;)")


def service_for(path: Path):
    p = path.as_posix()
    for s in config.SERVICES:
        if f"/{s}." in p or f"/{s}/" in p or p.endswith(f"/{s}.conf") or p.endswith(f"/apps/{s}.py"):
            return s
    if "/pki/" in p:
        return "pki"
    if p.endswith(("apps/bank.py", "openssl-oqs.cnf", "start.sh", "Dockerfile")):
        return "all services"
    if p.endswith("apps/dbinit.py"):
        return "postgres"
    return None


def _file_kind(path: Path):
    n = path.name.lower()
    if n in ("requirements.txt",) or n.startswith("requirements") and n.endswith(".txt") or n == "package.json":
        return "dep"
    if path.suffix in CERT_EXT:
        return "cert"
    if path.suffix in DOC_EXT:
        return "doc"
    if path.suffix in CONF_EXT or n in ("ssh_config", "sshd_config", "authorized_keys", "known_hosts"):
        return "conf"
    if path.suffix in CODE_EXT or n == "dockerfile":
        return "code"
    return None


def _finding(path, line_no, rule, category, alg, snippet, root, status=QV):
    rel = path.relative_to(root).as_posix() if root in path.parents or path == root else path.as_posix()
    return {"file": rel, "line": line_no, "rule": rule, "category": category, "algorithm": alg,
            "status": status, "snippet": snippet.strip()[:160], "service": service_for(path)}


def scan_text(path, root, kind):
    out = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return out
    for i, line in enumerate(lines, 1):
        if COMMENT.match(line):
            continue
        for rid, cat, alg, rx, fk in RULES:
            if fk not in (kind, "any"):
                continue
            m = re.search(rx, line)
            if not m:
                continue
            if rid in GROUP_RULES and PQ_NAMES.search(m.group(1)):
                out.append(_finding(path, i, rid, cat, "Hybrid/PQ key exchange", line, root, "pq-safe"))
                continue
            if rid in GROUP_RULES and "{" in m.group(1):
                continue   # templated value, resolved in rendered configs
            out.append(_finding(path, i, rid, cat, alg, line, root))
            break
    return out


def scan_deps(path, root):
    out = []
    kind = "package.json" if path.name == "package.json" else "requirements"
    libs = DEP_LIBS[kind]
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        if kind == "package.json":
            m = re.match(r'\s*"([@\w./-]+)"\s*:', line)
        else:
            m = re.match(r"\s*([A-Za-z0-9_.-]+)", line) if not COMMENT.match(line) else None
        if m and m.group(1).lower() in libs:
            out.append(_finding(path, i, f"dep-{kind}", "dependency", libs[m.group(1).lower()], line, root))
    return out


def scan_pem(path, root):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
    out = []
    data = path.read_bytes()
    blocks = re.findall(rb"-----BEGIN ([A-Z0-9 ]+)-----\s.*?-----END \1-----", data, re.S)
    if not blocks:
        return out
    text = data.decode(errors="ignore")
    for m in re.finditer(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", text, re.S):
        kind, line = m.group(1), text[:m.start()].count("\n") + 1
        pem = m.group(0).encode()
        alg, detail = None, ""
        try:
            if kind == "CERTIFICATE":
                c = x509.load_pem_x509_certificate(pem)
                detail = f"{c.subject.rfc4514_string()} sig={c.signature_algorithm_oid._name} expires {c.not_valid_after_utc.date()}"
                try:
                    k = c.public_key()
                except Exception:
                    k = None
            elif "PRIVATE KEY" in kind:
                k = load_pem_private_key(pem, None)
                detail = "private key"
            elif "PUBLIC KEY" in kind:
                k = load_pem_public_key(pem)
                detail = "public key"
            else:
                continue
            if isinstance(k, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
                alg = f"RSA-{k.key_size}"
            elif isinstance(k, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
                alg = f"ECDSA-{k.curve.name}"
            elif isinstance(k, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey, ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
                alg = "EdDSA"
            elif isinstance(k, (dsa.DSAPrivateKey, dsa.DSAPublicKey)):
                alg = "DSA"
        except Exception:
            k = None
        if alg is None:
            # NIST PQC signature OIDs 2.16.840.1.101.3.4.3.17-31 (ML-DSA 17-19, SLH-DSA 20-31);
            # Falcon / FN-DSA in oqs-provider uses 1.3.9999.3.x (DER 06 05 2B CE 0F 03 xx)
            import base64
            try:
                der = base64.b64decode("".join(m.group(2).split()))
            except Exception:
                der = b""
            pq = None
            if re.search(rb"\x06\x05\x2b\xce\x0f\x03", der):
                pq = "FN-DSA (Falcon)"
            elif re.search(rb"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03[\x14-\x1f]", der):
                pq = "SLH-DSA"
            elif re.search(rb"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x03[\x11-\x13]", der):
                pq = "ML-DSA"
            if pq:
                out.append(_finding(path, line, "pem-pq", "certificate", pq, f"{kind} {detail}".strip(), root, "pq-safe"))
            continue
        out.append(_finding(path, line, "pem-classical", "certificate", alg, f"{kind} {detail}", root))
    return out


def scan_tree(root: Path):
    root = root.resolve()
    findings = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(p in SKIP_DIRS for p in path.relative_to(root).parts):
            continue
        kind = _file_kind(path)
        if kind == "dep":
            findings += scan_deps(path, root)
        elif kind == "cert":
            findings += scan_pem(path, root)
        elif kind in ("code", "conf"):
            findings += scan_text(path, root, kind)
    return findings


def scan_endpoints():
    """Live TLS posture of every running bank service (real handshakes from the toolbox)."""
    from . import migrate, testbed
    out = []
    for s in testbed.BANK:
        h = migrate.handshake(s)
        h.pop("raw", None)
        grp = h.get("group") or "?"
        out.append({"file": f"tls://{s}:443", "line": 0, "rule": "endpoint-kex", "category": "endpoint",
                    "algorithm": f"{grp} key exchange",
                    "status": "pq-safe" if PQ_NAMES.search(grp) else QV,
                    "snippet": f"negotiated {grp}, peer signature {h.get('peer_sig')}", "service": s})
        sig = h.get("peer_sig") or "?"
        out.append({"file": f"tls://{s}:443", "line": 0, "rule": "endpoint-cert", "category": "endpoint",
                    "algorithm": f"{sig} certificate", "status": "pq-safe" if PQ_NAMES.search(sig) else QV,
                    "snippet": f"server authenticates with {sig}", "service": s})
    return out


# -------------------------------------------------------------- evaluation
NAIVE = re.compile(r"rsa|ecdsa|ecdh|\bec\b|dsa|ed25519|x25519|RS256|ES256|secp|prime256|P-256|ECDHE", re.I)


def naive_grep(root: Path):
    hits = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "labels.json":
            for i, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if NAIVE.search(line):
                    hits.append({"file": path.relative_to(root).as_posix(), "line": i})
    return hits


def prf(pred, truth):
    p = {(f["file"], f["line"]) for f in pred}
    t = {(f["file"], f["line"]) for f in truth}
    tp = len(p & t)
    prec = tp / len(p) if p else 0.0
    rec = tp / len(t) if t else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"tp": tp, "fp": len(p - t), "fn": len(t - p), "precision": round(prec, 3), "recall": round(rec, 3),
            "f1": round(f1, 3), "false_positives": sorted(p - t), "missed": sorted(t - p)}


def _hybrid_findings(path, root, rel, kind, model):
    """The hybrid engine (rules + ML classifier + crypto verification) on one code / config file."""
    from . import detect
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    out = []
    for r in detect.analyse_text(text, rel, model=model):
        if not r["finding"]:
            continue
        pq = bool(detect.PQ.search(r["snippet"]))
        out.append({"file": rel, "line": r["line"], "rule": r["rules"][0] if r["rules"] else "ml+verification",
                    "category": "config" if kind == "conf" else "code", "algorithm": r["primitive"] or "?",
                    "status": "pq-safe" if pq else QV, "snippet": r["snippet"][:160], "service": service_for(path),
                    "severity": r["severity"], "ml_p": r["ml_p"], "verification": r["verification"],
                    "banking_context": r["banking_context"], "detected_by": "rule" if r["rules"] else "ML + verification"})
    return out


def scan_dir(root: Path, skip=frozenset()):
    """ONE engine for any directory of banking code: the hybrid detector reads code and config lines;
    certificates (X.509 / PEM) and dependency manifests are parsed exactly. Same finding format."""
    import joblib
    from . import detect
    model = joblib.load(detect.MODEL)
    root = root.resolve()
    out = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel in skip or any(p in SKIP_DIRS for p in rel.split("/")):
            continue
        kind = _file_kind(path)
        if kind == "dep":
            out += scan_deps(path, root)
        elif kind == "cert":
            out += scan_pem(path, root)
        elif kind in ("code", "conf"):
            out += _hybrid_findings(path, root, rel, kind, model)
    return out


def evaluate():
    """Accuracy of the engine that scans the mini-bank, on the hand-labelled bank corpus (corpus/)."""
    root = config.CORPUS
    truth = json.loads((root / "labels.json").read_text())["positives"]
    found = [f for f in scan_dir(root) if f["status"] == QV]
    rules_only = [f for f in scan_tree(root) if f["status"] == QV]
    by_cat = {}
    for cat in sorted({t["category"] for t in truth}):
        by_cat[cat] = prf([f for f in found if _cat(f) == cat], [t for t in truth if t["category"] == cat])
    res = {"pq_bridge": prf(found, truth), "rules_only": prf(rules_only, truth), "naive_grep": prf(naive_grep(root), truth),
           "by_category": by_cat, "labelled_positives": len(truth), "files": len({t['file'] for t in truth}),
           "engine": "hybrid (rules + ML + verification) for code and config; exact parsers for certificates and dependencies"}
    config.EVIDENCE.mkdir(parents=True, exist_ok=True)
    (config.EVIDENCE / "detection_eval.json").write_text(json.dumps(res, indent=1))
    return res


def _cat(f):
    return {"certificate": "certificate", "dependency": "dependency", "config": "config"}.get(f["category"], "code")


SIMULATORS = {"apps/probe.py", "apps/loadgen.py", "apps/legacy.py", "apps/legacy-openssl.cnf", "apps/clearing.py",
              "runtime/conf/clearing.conf"}   # test harness, customer apps and the external partner


def scan_estate(include_endpoints=True):
    """The mini-bank estate = its source, rendered nginx configs, PKI material, plus live endpoints, all read by the
    same engine (see scan_dir). Traffic simulators and the gate's probe are test harness, not bank estate."""
    findings = scan_dir(config.TESTBED, skip=SIMULATORS)
    if include_endpoints:
        try:
            findings += scan_endpoints()
        except Exception as e:
            findings.append({"file": "tls://*", "line": 0, "rule": "endpoint-error", "category": "endpoint",
                             "algorithm": "-", "status": "error", "snippet": str(e)[:160], "service": None})
    config.EVIDENCE.mkdir(parents=True, exist_ok=True)
    (config.EVIDENCE / "inventory.json").write_text(json.dumps(findings, indent=1))
    return findings
