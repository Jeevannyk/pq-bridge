"""Benchmark worker. Runs INSIDE the toolbox container (OpenSSL 3.5 + oqs-provider), stdlib only.
Prints one JSON document. Driven by pqbridge/bench.py."""
import base64
import json
import os
import re
import socket
import ssl
import statistics
import subprocess
import sys
import time

W = "/tmp/bench"
os.makedirs(W, exist_ok=True)
SECS = int(os.environ.get("BENCH_SECS", "2"))
N_HS = int(os.environ.get("BENCH_HANDSHAKES", "80"))


def sh(cmd, check=True, env=None):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, env={**os.environ, **(env or {})})
    if check and p.returncode:
        raise RuntimeError(f"{cmd}\n{p.stderr[-400:]}")
    return p.stdout + p.stderr


def size(path):
    return os.path.getsize(path)


# ------------------------------------------------------------ primitives
SIGS = [  # label, family, genpkey args, speed mode, speed name
    ("RSA-2048", "classical", "-algorithm RSA -pkeyopt rsa_keygen_bits:2048", "prov", "rsa2048"),
    ("RSA-3072", "classical", "-algorithm RSA -pkeyopt rsa_keygen_bits:3072", "prov", "rsa3072"),
    ("ECDSA P-256", "classical", "-algorithm EC -pkeyopt ec_paramgen_curve:P-256", "legacy", "ecdsap256"),
    ("Ed25519", "classical", "-algorithm ED25519", "legacy", "ed25519"),
    ("FN-DSA-512 (Falcon)", "post-quantum", "-algorithm falcon512", "prov", "falcon512"),
    ("FN-DSA-1024 (Falcon)", "post-quantum", "-algorithm falcon1024", "prov", "falcon1024"),
    ("SLH-DSA-SHA2-128s", "post-quantum", "-algorithm SLH-DSA-SHA2-128s", "prov", "SLH-DSA-SHA2-128s"),
    ("SLH-DSA-SHA2-128f", "post-quantum", "-algorithm SLH-DSA-SHA2-128f", "prov", "SLH-DSA-SHA2-128f"),
]
# label, family, speed name, public key bytes, ciphertext bytes (raw, as sent in the TLS key_share).
# HQC sizes are liboqs 0.16.0 constants (OQS_KEM_hqc_*_length_*); oqs-provider has no OID for HQC keys yet,
# so they cannot be serialised to files. TLS wire sizes below are measured, not assumed.
KEMS = [
    ("X25519 (ECDH)", "classical", "X25519", 32, 32),
    ("P-256 (ECDH)", "classical", "ECP-256", 65, 65),
    ("HQC-1", "post-quantum", "hqc1", 2241, 4433),
    ("HQC-3", "post-quantum", "hqc3", 4514, 8978),
    ("X25519 + HQC-1 (hybrid)", "hybrid", "x25519_hqc1", 32 + 2241, 32 + 4433),
]


def speed_sig(mode, name):
    if mode == "prov":
        out = sh(f"openssl speed -seconds {SECS} -mr -signature-algorithms {name}", check=False)
        m = re.findall(r"^\+F10:\d+:([\d.]+):([\d.]+):([\d.]+)", out, re.M)
        if m:
            k, s, v = map(float, m[-1])
            return {"keygen_per_s": k, "sign_per_s": s, "verify_per_s": v}
    else:
        out = sh(f"openssl speed -seconds {SECS} -mr {name}", check=False)
        m = re.findall(r"^\+F[46]:\d+:\d+:(?:[A-Za-z0-9]+:)?([\d.]+):([\d.]+)", out, re.M)
        if m:
            s, v = map(float, m[-1])
            return {"keygen_per_s": None, "sign_per_s": s, "verify_per_s": v}
    return {"error": out[-200:]}


def sizes_sig(label, gen):
    k = f"{W}/{abs(hash(label))}.key"
    sh(f"openssl genpkey {gen} -out {k}")
    sh(f"openssl pkey -in {k} -pubout -outform DER -out {k}.pub.der")
    sh(f"openssl pkey -in {k} -outform DER -out {k}.der")
    with open(f"{W}/msg", "wb") as f:
        f.write(b"x" * 32)
    if "RSA" in gen or "EC " in gen:
        sh(f"openssl dgst -sha256 -sign {k} -out {k}.sig {W}/msg")
    else:
        sh(f"openssl pkeyutl -sign -inkey {k} -rawin -in {W}/msg -out {k}.sig")
    sh(f"openssl req -x509 -new -key {k} -subj /CN=bench -days 1 -outform DER -out {k}.crt.der")
    return {"public_key_bytes": size(f"{k}.pub.der"), "private_key_bytes": size(f"{k}.der"),
            "signature_bytes": size(f"{k}.sig"), "self_signed_cert_bytes": size(f"{k}.crt.der")}



def speed_kem(name):
    out = sh(f"openssl speed -seconds {SECS} -mr -kem-algorithms {name}", check=False)
    m = re.findall(r"^\+F9:\d+:([\d.]+):([\d.]+):([\d.]+)", out, re.M)
    if not m:
        return {"error": out[-200:]}
    k, e, d = map(float, m[-1])
    return {"keygen_per_s": k, "encaps_per_s": e, "decaps_per_s": d}


# ------------------------------------------------------------ TLS modes
CA = "-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign"
LEAF = "-addext subjectAltName=DNS:localhost -addext basicConstraints=CA:FALSE -addext keyUsage=critical,digitalSignature"


def chain(name, root_gen, leaf_gen):
    d = f"{W}/{name}"
    os.makedirs(d, exist_ok=True)
    sh(f"openssl genpkey {root_gen} -out {d}/root.key && openssl req -x509 -new -key {d}/root.key "
       f"-subj /CN=root-{name} -days 2 {CA} -out {d}/root.crt")
    sh(f"openssl genpkey {leaf_gen} -out {d}/leaf.key && openssl req -new -key {d}/leaf.key -subj /CN=localhost {LEAF} "
       f"-out {d}/leaf.csr && openssl x509 -req -in {d}/leaf.csr -CA {d}/root.crt -CAkey {d}/root.key "
       f"-copy_extensions copy -days 2 -out {d}/leaf.crt")
    sh(f"openssl x509 -in {d}/leaf.crt -outform DER -out {d}/leaf.der")
    return d


MODES = [  # label, family, group, chain name, root gen, leaf gen
    ("Classical: X25519 + RSA-2048", "classical", "X25519", "rsa", "-algorithm RSA -pkeyopt rsa_keygen_bits:2048",
     "-algorithm RSA -pkeyopt rsa_keygen_bits:2048"),
    ("Classical: X25519 + ECDSA P-256", "classical", "X25519", "ecdsa", "-algorithm EC -pkeyopt ec_paramgen_curve:P-256",
     "-algorithm EC -pkeyopt ec_paramgen_curve:P-256"),
    ("Hybrid: X25519+HQC-1 + FN-DSA-512 leaf / SLH-DSA root (deployed)", "hybrid", "x25519_hqc1", "pq",
     "-algorithm SLH-DSA-SHA2-128s", "-algorithm falcon512"),
    ("PQ-only: HQC-1 + FN-DSA-512 leaf / SLH-DSA root", "pq-only", "hqc1", "pq", None, None),
    ("PQ-only: HQC-1 + FN-DSA-512 leaf / FN-DSA root", "pq-only", "hqc1", "fnfn", "-algorithm falcon512",
     "-algorithm falcon512"),
    ("PQ-only: HQC-3 + FN-DSA-1024 leaf / SLH-DSA root (cat. 3/5)", "pq-only", "hqc3", "fn1024",
     "-algorithm SLH-DSA-SHA2-128s", "-algorithm falcon1024"),
]
# Probed and recorded, not benchmarked: an SLH-DSA *leaf* cannot be served over TLS 1.3 by OpenSSL 3.5
# (no TLS signature codepoint -> nginx "unknown certificate type"). SLH-DSA is used for the root CA only.
FINDINGS = ["SLH-DSA has no TLS 1.3 signature codepoint in OpenSSL 3.5: nginx rejects an SLH-DSA leaf certificate "
            "(SSL_CTX_use_certificate: unknown certificate type). SLH-DSA is therefore limited to the offline root CA."]


def groups_conf(group):
    path = f"{W}/groups_{group}.cnf"
    with open(path, "w") as f:
        f.write(f"""openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
ssl_conf = ssl_sect
[provider_sect]
default = default_sect
oqsprovider = oqs_sect
[default_sect]
activate = 1
[oqs_sect]
activate = 1
[ssl_sect]
system_default = sd
[sd]
Groups = {group}
""")
    return path


LATENCY_CLIENT = r"""
import socket, ssl, sys, time, statistics, json
port, ca, n = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
ctx = ssl.create_default_context(cafile=ca)
ts = []
for _ in range(n):
    t0 = time.perf_counter()
    with socket.create_connection(("localhost", port), timeout=10) as s:
        with ctx.wrap_socket(s, server_hostname="localhost"):
            pass
    ts.append((time.perf_counter() - t0) * 1000)
ts.sort()
print(json.dumps({"median_ms": round(statistics.median(ts), 3), "p95_ms": round(ts[int(0.95 * (n - 1))], 3),
                  "mean_ms": round(statistics.mean(ts), 3)}))
"""


def tls_modes():
    with open(f"{W}/lat.py", "w") as f:
        f.write(LATENCY_CLIENT)
    sh("pkill -f /tmp/bench/nginx_ || true", check=False)
    time.sleep(0.5)
    chains, servers, rows = {}, [], []
    for i, (label, fam, group, cname, rg, lg) in enumerate(MODES):
        if cname not in chains:
            chains[cname] = chain(cname, rg, lg)
        d = chains[cname]
        port = 9500 + i
        conf = f"{W}/nginx_{i}.conf"
        with open(conf, "w") as f:
            f.write(f"pid {W}/nginx_{i}.pid; error_log {W}/nginx_{i}.err; events {{}}\n"
                    f"http {{ access_log off; server {{ listen {port} ssl; ssl_protocols TLSv1.3; "
                    f"ssl_certificate {d}/leaf.crt; ssl_certificate_key {d}/leaf.key; ssl_ecdh_curve {group}; "
                    f"location / {{ return 200 ok; }} }} }}\n")
        sh(f"nginx -c {conf}")
        servers.append(conf)
    time.sleep(1)
    for i, (label, fam, group, cname, rg, lg) in enumerate(MODES):
        d, port = chains[cname], 9500 + i
        env = {"OPENSSL_CONF": groups_conf(group)}
        out = sh(f"echo | openssl s_client -connect localhost:{port} -CAfile {d}/root.crt -groups {group} 2>&1",
                 check=False, env=env)
        rd = re.search(r"handshake has read (\d+) bytes and written (\d+) bytes", out)
        neg = re.search(r"Negotiated TLS1\.3 group: (\S+)", out) or re.search(r"Peer Temp Key: (\w+)", out)
        sig = re.search(r"Peer signature type: (\S+)", out)
        lat = json.loads(sh(f"python3 {W}/lat.py {port} {d}/root.crt {N_HS}", env=env).strip().splitlines()[-1])
        st = sh(f"openssl s_time -connect localhost:{port} -new -time {SECS + 1} -CAfile {d}/root.crt 2>&1",
                check=False, env=env)
        cps = re.search(r"([\d.]+) connections/user sec", st)
        conns = re.search(r"(\d+) connections in ([\d.]+)s", st)
        rows.append({"mode": label, "family": fam, "group": neg.group(1) if neg else None,
                     "peer_sig": sig.group(1) if sig else None,
                     "verified": "Verify return code: 0" in out,
                     "bytes_server_to_client": int(rd.group(1)) if rd else None,
                     "bytes_client_to_server": int(rd.group(2)) if rd else None,
                     "leaf_cert_bytes": size(f"{d}/leaf.der"), **lat,
                     "handshakes_per_user_sec": float(cps.group(1)) if cps else None,
                     "handshakes_per_wall_sec": round(int(conns.group(1)) / float(conns.group(2)), 1) if conns else None})
    for i in range(len(MODES)):
        sh(f"nginx -c {W}/nginx_{i}.conf -s stop", check=False)
    return rows


def jwt_sizes(sig_rows):
    header = len(base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').rstrip(b"="))
    payload = len(base64.urlsafe_b64encode(b'{"sub":"ACC-1001","iat":1793187880,"exp":1793188180}').rstrip(b"="))
    out = []
    for name, alg in [("RS256", "RSA-2048"), ("ES256", "ECDSA P-256"), ("EdDSA", "Ed25519"),
                      ("FN-DSA-512", "FN-DSA-512 (Falcon)"), ("SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s")]:
        r = next(x for x in sig_rows if x["algorithm"] == alg)
        sig = r["signature_bytes"] if alg != "ECDSA P-256" else 64      # JWS ES256 uses raw r||s (64 B), not DER
        tok = header + payload + (4 * sig + 2) // 3 + 2
        out.append({"jwt_alg": name, "signature_bytes": sig, "token_bytes": tok,
                    "sign_ms": round(1000 / r["sign_per_s"], 3) if r.get("sign_per_s") else None,
                    "verify_ms": round(1000 / r["verify_per_s"], 3) if r.get("verify_per_s") else None,
                    "storage_GB_per_100M_tokens": round(tok * 1e8 / 1e9, 2)})
    return out


def main():
    sig_rows = []
    for label, fam, gen, mode, name in SIGS:
        sig_rows.append({"algorithm": label, "family": fam, **sizes_sig(label, gen), **speed_sig(mode, name)})
    kem_rows = []
    for label, fam, name, pk, ct in KEMS:
        kem_rows.append({"algorithm": label, "family": fam, "public_key_bytes": pk, "ciphertext_bytes": ct,
                         "shared_secret_bytes": 32 if fam != "hybrid" else 64, **speed_kem(name)})
    print(json.dumps({"signatures": sig_rows, "kems": kem_rows, "tls": tls_modes(), "jwt": jwt_sizes(sig_rows),
                      "findings": FINDINGS,
                      "env": {"openssl": sh("openssl version").strip(),
                              "oqsprovider": re.search(r"OQS Provider\s+version: (\S+)",
                                                       sh("openssl list -providers -verbose", check=False)).group(1)
                              if "OQS" in sh("openssl list -providers", check=False) else None,
                              "cpu": sh("grep -m1 'model name' /proc/cpuinfo", check=False).split(":")[-1].strip(),
                              "nproc": os.cpu_count(), "speed_seconds": SECS, "handshakes": N_HS}}))


if __name__ == "__main__":
    main()
