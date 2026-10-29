"""Benchmark worker. Runs INSIDE the toolbox container (OpenSSL 3.5 + oqs-provider), stdlib only.
Driven by pqbridge/bench.py, which prepends CFG: the bank's own TLS settings, cert profile and algorithms,
and has already issued a scratch copy of the bank's PKI under /tmp/bench/pki (live PKI and traffic untouched)."""
import json
import os
import re
import secrets
import socket
import ssl
import statistics
import subprocess
import sys
import time

sys.path.insert(0, "/apps")
import bank                      # the bank's own sign / verify code, the same module the KMS and resource servers run

W = "/tmp/bench"
PKI = f"{W}/pki"
N_HS = int(os.environ.get("BENCH_HANDSHAKES", "80"))
N_SIGN = int(os.environ.get("BENCH_SIGN_OPS", "10"))


def sh(cmd, check=True, env=None):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, env={**os.environ, **(env or {})})
    if check and p.returncode:
        raise RuntimeError(f"{cmd}\n{p.stderr[-400:]}")
    return p.stdout + p.stderr


def groups_conf(groups):
    path = f"{W}/groups_{abs(hash(groups))}.cnf"
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
Groups = {groups}
""")
    return path


# ------------------------------------------------------------ mTLS between two bank nodes, per crypto mode
CLIENT = r"""
import json, socket, ssl, statistics, sys, time
port, ca, crt, key, n = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
ctx = ssl.create_default_context(cafile=ca)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(crt, key)
ts, bad, err = [], 0, None
for _ in range(n):
    t0 = time.perf_counter()
    try:
        with socket.create_connection(("localhost", port), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname="payments") as t:
                t.sendall(b"GET / HTTP/1.1\r\nHost: payments\r\nConnection: close\r\n\r\n")
                if not t.recv(64).startswith(b"HTTP/1.1 200"):
                    bad += 1
    except Exception as e:
        bad, err = bad + 1, str(e)[:120]
        continue
    ts.append((time.perf_counter() - t0) * 1000)
if not ts:
    print(json.dumps({"error": err or "no handshake completed"}))
else:
    ts.sort()
    print(json.dumps({"median_ms": round(statistics.median(ts), 3), "p95_ms": round(ts[int(0.95 * (len(ts) - 1))], 3),
                      "handshakes_per_s": round(1000 / statistics.mean(ts), 1), "failed": bad, "error": err}))
"""


def tls_modes():
    with open(f"{W}/client.py", "w") as f:
        f.write(CLIENT)
    sh("pkill -f /tmp/bench/nginx_ || true", check=False)
    time.sleep(0.5)
    for i, m in enumerate(CFG["modes"]):
        with open(f"{W}/nginx_{i}.conf", "w") as f:
            f.write(f"pid {W}/nginx_{i}.pid; error_log {W}/nginx_{i}.err; events {{}}\n"
                    f"http {{ access_log off; server {{ listen {9500 + i} ssl; ssl_protocols TLSv1.3; {m['stanza']}\n"
                    f"    location / {{ return 200 ok; }} }} }}\n")
        sh(f"nginx -c {W}/nginx_{i}.conf")
    time.sleep(1)
    rows = []
    try:
        for i, m in enumerate(CFG["modes"]):
            port = 9500 + i
            ca = f"{PKI}/trust/{m['trust']}.pem"
            crt, key = f"{PKI}/certs/probe.{m['cert']}.crt", f"{PKI}/certs/probe.{m['cert']}.key"
            env = {"OPENSSL_CONF": groups_conf(m["client_groups"])}
            out = sh(f"echo | openssl s_client -connect localhost:{port} -servername payments -CAfile {ca} "
                     f"-cert {crt} -key {key} -groups {m['client_groups']} 2>&1", check=False, env=env)
            rd = re.search(r"handshake has read (\d+) bytes and written (\d+) bytes", out)
            neg = re.search(r"Negotiated TLS1\.3 group: (\S+)", out) or re.search(r"Peer Temp Key: (\w+)", out)
            sig = re.search(r"Peer signature type: (\S+)", out)
            lat = json.loads(sh(f"python3 {W}/client.py {port} {ca} {crt} {key} {N_HS}", env=env).strip().splitlines()[-1])
            rows.append({"mode": m["label"], "family": m["key"], "group": neg.group(1) if neg else None,
                         "peer_sig": sig.group(1) if sig else None, "verified": "Verify return code: 0" in out,
                         "bytes_server_to_client": int(rd.group(1)) if rd else None,
                         "bytes_client_to_server": int(rd.group(2)) if rd else None, **lat})
    finally:
        for i in range(len(CFG["modes"])):
            sh(f"nginx -c {W}/nginx_{i}.conf -s stop", check=False)
    return rows


# ------------------------------------------------------------ what the bank signs, with the bank's own sign / verify code
def med_ms(fn, n):
    ts = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        ts.append((time.perf_counter() - t0) * 1000)
    return round(statistics.median(ts), 1)


def signed_rows():
    gens = {"RS256": "-algorithm RSA -pkeyopt rsa_keygen_bits:2048", "FN-DSA-512": f"-algorithm {CFG['leaf_sig']}",
            "SLH-DSA-SHA2-128s": f"-algorithm {CFG['root_sig']}"}
    keys = {}
    for alg, gen in gens.items():
        k = f"{W}/sign_{bank.ALG_TAG[alg]}.key"
        sh(f"openssl genpkey {gen} -out {k} && openssl pkey -in {k} -pubout -out {k}.pub")
        keys[alg] = (k, open(f"{k}.pub").read())

    now = int(time.time())
    claims = {"iss": "https://pqbank/identity", "sub": "CUST-1001", "aud": "pqbank-api", "scope": "accounts:read payments:write",
              "iat": now, "exp": now + 300, "jti": secrets.token_hex(8)}
    batch = ("transfer_id,debit,credit,amount\n" + "".join(f"{i},ACC-{1001 + i % 50},ACC-{2001 + i % 50},{i * 37 % 900 + 10}\n"
                                                           for i in range(500))).encode()
    rows = []
    for item, alg in [("Access token (JWT)", "RS256"), ("Access token (JWT)", "FN-DSA-512"),
                      ("Settlement batch (500 transfers)", "RS256"), ("Settlement batch (500 transfers)", "SLH-DSA-SHA2-128s")]:
        k, pub = keys[alg]
        if item.startswith("Access"):
            header = {"alg": alg, "typ": "JWT", "kid": f"jwt-{bank.ALG_TAG[alg]}-0a1b2c3d"}
            data = f"{bank.b64u(bank.canon(header))}.{bank.b64u(bank.canon(claims))}".encode()
        else:
            data = batch
        n = max(3, N_SIGN // 2) if alg.startswith("SLH") else N_SIGN
        sig = bank.openssl_sign(alg, k, data)
        assert bank.openssl_verify(alg, pub, data, sig), f"{alg} signature did not verify"
        rows.append({"item": item, "algorithm": alg, "signature_bytes": len(sig),
                     "payload_bytes": len(data) + (len(bank.b64u(sig)) + 1 if item.startswith("Access") else 0),
                     "sign_ms": med_ms(lambda: bank.openssl_sign(alg, k, data), n),
                     "verify_ms": med_ms(lambda: bank.openssl_verify(alg, pub, data, sig), n)})
    return rows


def main():
    print(json.dumps({"tls": tls_modes(), "signed": signed_rows(),
                      "env": {"openssl": sh("openssl version").strip(),
                              "oqsprovider": re.search(r"OQS Provider\s+version: (\S+)",
                                                       sh("openssl list -providers -verbose", check=False)).group(1)
                              if "OQS" in sh("openssl list -providers", check=False) else None,
                              "cpu": sh("grep -m1 'model name' /proc/cpuinfo", check=False).split(":")[-1].strip(),
                              "nproc": os.cpu_count(), "handshakes": N_HS, "sign_ops": N_SIGN}}))


if __name__ == "__main__":
    main()
