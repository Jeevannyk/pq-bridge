"""Classical vs hybrid vs PQ-only benchmarks: performance, storage, runtime, bandwidth.

Runs pqbridge/bench_tool.py inside the toolbox container (same OpenSSL 3.5 + oqs-provider build the
bank uses) and derives comparison metrics. Measured on Docker Desktop on the team laptop (an emulator,
not bank hardware); the environment block in benchmarks.json records the CPU.
    python -m pqbridge.bench
"""
import json
import subprocess
import time
from pathlib import Path

from . import config, testbed

DAILY_HANDSHAKES = 10_000_000      # projection basis: a mid-size bank's daily TLS handshakes (assumption)
SHORT = ["Classical · RSA-2048", "Classical · ECDSA P-256", "Hybrid · HQC-1 + FN-DSA ★", "PQ-only · HQC-1, SLH root",
         "PQ-only · HQC-1, FN-DSA root", "PQ-only · HQC-3 + FN-DSA-1024"]   # order of bench_tool.MODES


def run(log=print, seconds=2, handshakes=80):
    script = (Path(__file__).parent / "bench_tool.py").read_text()
    log("Benchmarking primitives and TLS modes inside the toolbox (takes ~2-3 min)")
    p = subprocess.run(testbed.COMPOSE + ["exec", "-T", "-e", f"BENCH_SECS={seconds}", "-e", f"BENCH_HANDSHAKES={handshakes}",
                                          "toolbox", "python3", "-"],
                       input=script, capture_output=True, text=True, encoding="utf-8", timeout=1800)
    if p.returncode:
        raise RuntimeError(p.stderr[-800:])
    res = json.loads(p.stdout.strip().splitlines()[-1])
    base = next(r for r in res["tls"] if r["mode"].startswith("Classical: X25519 + RSA"))
    for r, short in zip(res["tls"], SHORT):
        r["short"] = short
        tot = (r["bytes_server_to_client"] or 0) + (r["bytes_client_to_server"] or 0)
        btot = base["bytes_server_to_client"] + base["bytes_client_to_server"]
        r["bytes_total"] = tot
        r["bytes_vs_classical_x"] = round(tot / btot, 2)
        r["latency_vs_classical_x"] = round(r["median_ms"] / base["median_ms"], 2)
        r["bandwidth_GB_per_day"] = round(tot * DAILY_HANDSHAKES / 1e9, 1)
    res["projection"] = {"daily_handshakes": DAILY_HANDSHAKES, "note": "assumption for bandwidth projection"}
    res["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
    config.EVIDENCE.mkdir(parents=True, exist_ok=True)
    (config.EVIDENCE / "benchmarks.json").write_text(json.dumps(res, indent=1))
    for r in res["tls"]:
        log(f"  {r['mode']}: {r['group']}/{r['peer_sig']} {r['bytes_total']} B, median {r['median_ms']} ms, "
            f"{r['handshakes_per_wall_sec']} hs/s")
    return res


if __name__ == "__main__":
    print(json.dumps(run(), indent=1)[:3000])
