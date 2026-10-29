"""Real-world TLS posture of public banking / fintech endpoints.

One ordinary HTTPS handshake per host, exactly as a browser would make, from the toolbox
container (OpenSSL 3.5 + oqs-provider). The client offers, in order: HQC hybrid, ML-KEM hybrid,
X25519, P-256 (ML-KEM is offered only to measure industry adoption; PQ-Bridge itself
uses HQC). The server picks, so the result shows what each institution supports today.
"""
import json
import re
import time

from . import config, testbed

HOSTS = [
    # US / global banks
    "www.jpmorganchase.com", "www.chase.com", "www.jpmorgan.com", "www.bankofamerica.com", "www.wellsfargo.com",
    "www.citi.com", "www.goldmansachs.com", "www.capitalone.com", "www.hsbc.com", "www.barclays.co.uk",
    # Cloud / payment networks / fintech
    "aws.amazon.com", "www.visa.com", "www.mastercard.com", "www.paypal.com", "stripe.com", "www.swift.com",
    # India
    "www.onlinesbi.sbi", "www.hdfcbank.com", "www.icicibank.com", "www.axisbank.com", "www.npci.org.in",
    "www.rbi.org.in", "razorpay.com", "juspay.in",
]


def offered_groups():
    hy = testbed.PQ["hybrid_group"]
    return f"{hy}:X25519MLKEM768:X25519:P-256"


def probe(host):
    out = testbed.tool(
        f"echo | timeout 15 openssl s_client -connect {host}:443 -servername {host} -groups {offered_groups()} "
        f"-showcerts 2>&1", check=False, timeout=40).stdout

    def find(rx):
        m = re.search(rx, out)
        return m.group(1).strip() if m else None
    rd = re.search(r"handshake has read (\d+) bytes and written (\d+) bytes", out)
    group = find(r"Negotiated TLS1\.3 group: (\S+)") or find(r"(?:Peer|Server) Temp Key: ([^,\n]+)")
    leaf_key = find(r"Server public key is (\d+) bit")
    chain = len(re.findall(r"BEGIN CERTIFICATE", out))
    sig = find(r"Peer signature type: (\S+)")
    a_line = find(r"\n\s*a:(PKEY: [^\n]+)")
    return {
        "host": host, "ok": "BEGIN CERTIFICATE" in out,
        "protocol": find(r"Protocol\s*:\s*(\S+)") or find(r"New, (TLSv[\d.]+)"),
        "cipher": find(r"Cipher is (\S+)"), "group": group,
        "pq_kex": bool(group and ("MLKEM" in group.upper() or "HQC" in group.upper())),
        "peer_sig": sig, "leaf_key_bits": int(leaf_key) if leaf_key else None, "leaf_key": a_line,
        "leaf_sig_alg": find(r"\n\s*a:PKEY:[^\n]*sigalg: (\S+)"),
        "issuer": find(r"\n\s*i:([^\n]+)"), "chain_certs": chain,
        "bytes_read": int(rd.group(1)) if rd else None, "bytes_written": int(rd.group(2)) if rd else None,
        "error": None if "BEGIN CERTIFICATE" in out else out.strip().splitlines()[-1][:160] if out.strip() else "no output",
    }


def run(hosts=HOSTS, log=print):
    rows = []
    for h in hosts:
        r = probe(h)
        log(f"survey {h}: {r['group']} / {r['peer_sig']} / {r['leaf_key']}")
        rows.append(r)
    ok = [r for r in rows if r["ok"]]
    summary = {
        "probed": len(rows), "reachable": len(ok),
        "pq_hybrid_kex": sum(r["pq_kex"] for r in ok),
        "hqc_kex": sum(bool(r["group"] and "hqc" in r["group"].lower()) for r in ok),
        "classical_kex": sum(not r["pq_kex"] for r in ok),
        "rsa_leaf": sum(bool(r["peer_sig"] and r["peer_sig"].startswith("rsa")) for r in ok),
        "ecdsa_leaf": sum(bool(r["peer_sig"] and "ecdsa" in r["peer_sig"]) for r in ok),
        "pq_signature_leaf": sum(bool(r["peer_sig"] and re.search("mldsa|falcon|slh|fndsa", r["peer_sig"], re.I)) for r in ok),
        "offered_groups": offered_groups(), "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    out = {"summary": summary, "rows": rows}
    config.EVIDENCE.mkdir(parents=True, exist_ok=True)
    (config.EVIDENCE / "tls_survey.json").write_text(json.dumps(out, indent=1))
    return out
