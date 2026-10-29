"""Benchmarks of PQBank's own crypto: classical vs hybrid vs PQ-only.

Runs inside the toolbox container (the OpenSSL 3.5 + oqs-provider build the bank uses) and reuses the bank's
own pieces: the cert recipe (testbed._leaf), the sidecar's mTLS server settings (testbed._server_tls), its client
group lists (testbed._out_groups) and its sign / verify code (apps/bank.py). A scratch copy of the PKI is issued so
live traffic and live keys are untouched. Measured on Docker Desktop on the team laptop (an emulator, not bank hardware).
    python -m pqbridge.bench
"""
import json
import secrets
import subprocess
import time
from pathlib import Path

from . import config, testbed

W = "/tmp/bench"
NODES = ["payments", "probe"]      # server identity (a bank service) and the client identity (the gate's probe)
MODES = [  # key, label, the service state the bank holds in that mode
    ("classical", "Classical", {"kex": "classical", "cert": "rsa", "trust": "rsa"}),
    ("hybrid", "Hybrid", {"kex": "hybrid", "cert": "pq", "trust": "both"}),
    ("pq-only", "Pure PQC", {"kex": "pq-only", "cert": "pq", "trust": "both"}),
]



def _scratch_pki():
    seed = lambda: secrets.token_hex(32)
    steps = [
        f"rm -rf {W} && mkdir -p {W}/pki/certs {W}/pki/trust && cd {W}/pki",
        f"openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa-root.key -out rsa-root.crt -subj '/CN=PQBank RSA Root CA' "
        f"-days 90 {testbed.CA_EXT} 2>/dev/null",
        *[testbed._leaf(n, "rsa") for n in NODES],
        f"{testbed._seed_file('root', seed())} && openssl genpkey -algorithm {config.PQ['root_sig']} -rand /tmp/q_root.bin -out pq-root.key",
        f"openssl req -x509 -new -key pq-root.key -subj '/CN=PQBank SLH-DSA Root CA' -days 90 {testbed.CA_EXT} -out pq-root.crt",
        *[testbed._leaf(n, "pq", seed()) for n in NODES],
        "cat rsa-root.crt pq-root.crt > trust/both.pem && cp rsa-root.crt trust/rsa.pem",
    ]
    testbed.tool(" && ".join(steps), timeout=300)


def _cfg():
    modes = []
    for key, label, st in MODES:
        stanza = testbed._server_tls("payments", st).replace("/pki/", f"{W}/pki/")
        modes.append({"key": key, "label": label, "cert": st["cert"], "trust": st["trust"], "stanza": stanza,
                      "client_groups": testbed._out_groups(st)})
    return {"modes": modes, "leaf_sig": config.PQ["leaf_sig"], "root_sig": config.PQ["root_sig"]}


def run(log=print, handshakes=80, sign_ops=10):
    log("Benchmarking the bank's mTLS and signing paths in three modes (about 2 min)")
    script = (Path(__file__).parent / "bench_tool.py").read_text(encoding="utf-8")
    script = f"import json\nCFG = json.loads({json.dumps(json.dumps(_cfg()))})\n" + script
    _scratch_pki()
    try:
        p = subprocess.run(testbed.COMPOSE + ["exec", "-T", "-e", f"BENCH_HANDSHAKES={handshakes}", "-e", f"BENCH_SIGN_OPS={sign_ops}",
                                              "toolbox", "python3", "-"],
                           input=script, capture_output=True, text=True, encoding="utf-8", timeout=1800)
    finally:
        testbed.tool(f"rm -rf {W}", check=False)
    if p.returncode:
        raise RuntimeError(p.stderr[-800:])
    res = json.loads(p.stdout.strip().splitlines()[-1])
    base = res["tls"][0]
    btot = base["bytes_server_to_client"] + base["bytes_client_to_server"]
    for r in res["tls"]:
        if r.get("error") and "median_ms" not in r:
            raise RuntimeError(f"{r['mode']}: {r['error']}")
        r["bytes_total"] = r["bytes_server_to_client"] + r["bytes_client_to_server"]
        r["bytes_vs_classical_x"] = round(r["bytes_total"] / btot, 2)
        r["latency_vs_classical_x"] = round(r["median_ms"] / base["median_ms"], 2)
    res["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
    config.EVIDENCE.mkdir(parents=True, exist_ok=True)
    (config.EVIDENCE / "benchmarks.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    for r in res["tls"]:
        log(f"  {r['mode']}: {r['group']}/{r['peer_sig']} {r['bytes_total']} B, median {r['median_ms']} ms, {r['handshakes_per_s']} hs/s")
    for r in res["signed"]:
        log(f"  {r['item']} {r['algorithm']}: sig {r['signature_bytes']} B, sign {r['sign_ms']} ms, verify {r['verify_ms']} ms")
    return res


if __name__ == "__main__":
    print(json.dumps(run(), indent=1)[:3000])
