"""Quantum randomness from QpiAI QCloud for PQC key generation.

Circuit: Hadamard on every qubit, then measure -> each shot is n uniform bits.
Bits pass statistical health tests, then each 32-byte key seed is derived with
HKDF-SHA256 over (quantum bits || OS CSPRNG bytes). Mixing means the seed is
never weaker than the OS source, even if the quantum source is degraded or is
a simulator (whose output is classical pseudo-randomness).
"""
import hashlib
import hmac
import json
import math
import os
import time

from scipy.stats import chi2

from . import config

N_QUBITS = 6                  # QpiAI QCloud free tier cap
BITS_PER_SEED = 256
MIN_SAMPLE_BITS = 4096


def _login():
    if config.QCLOUD_API_KEY and "Local" not in config.QCLOUD_DEVICE:
        from qpiai_quantum import QpiAIQuantumAuth
        QpiAIQuantumAuth.login(api_key=config.QCLOUD_API_KEY)


def quantum_bits(n_bits):
    """Sample n_bits from H-then-measure circuits on QpiAI QCloud. Returns (bitstring, run metadata)."""
    from qpiai_quantum import Circuit
    _login()
    shots = math.ceil(n_bits / N_QUBITS)
    c = Circuit(N_QUBITS, N_QUBITS)
    for q in range(N_QUBITS):
        c.h(q)
    c.measure(list(range(N_QUBITS)), list(range(N_QUBITS)))
    t0 = time.time()
    res = c.run(shots=shots, experiment_name="pqbridge-qrng", device_name=config.QCLOUD_DEVICE)
    counts = res.get_counts()
    bits = "".join(outcome * n for outcome, n in counts.items())[:n_bits]
    meta = {
        "device": config.QCLOUD_DEVICE,
        "qubits": N_QUBITS,
        "shots": shots,
        "job_id": getattr(res, "job_id", None),
        "execution_time_s": round(time.time() - t0, 3),
        "distinct_outcomes": len(counts),
        "source_note": ("QpiAI simulator: classical pseudo-randomness, mixed with OS CSPRNG"
                        if ("Local" in config.QCLOUD_DEVICE or "Simulator" in config.QCLOUD_DEVICE)
                        else "QpiAI quantum hardware"),
    }
    return bits, meta, counts


def health_tests(bits, counts):
    """Simple SP 800-22 / 800-90B style checks on the raw quantum output."""
    n = len(bits)
    ones = bits.count("1")
    s_obs = abs(2 * ones - n) / math.sqrt(n)
    monobit_p = math.erfc(s_obs / math.sqrt(2))
    # per-qubit bias: each column of the shot matrix should be ~50% ones
    outcomes = [o for o, k in counts.items() for _ in range(k)]
    col_bias = max(abs(sum(o[i] == "1" for o in outcomes) / len(outcomes) - 0.5) for i in range(N_QUBITS))
    # chi-square over 4-bit nibbles
    nib = [int(bits[i:i + 4], 2) for i in range(0, n - n % 4, 4)]
    exp = len(nib) / 16
    stat = sum((nib.count(v) - exp) ** 2 / exp for v in range(16))
    chi_p = float(chi2.sf(stat, 15))
    passed = monobit_p > 0.001 and chi_p > 0.001 and col_bias < 0.15
    return {"n_bits": n, "ones_ratio": round(ones / n, 4), "monobit_p": round(monobit_p, 4),
            "nibble_chi2_p": round(chi_p, 4), "max_qubit_bias": round(col_bias, 4), "passed": passed}


def hkdf(ikm: bytes, info: bytes, salt: bytes, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def key_seeds(labels, purpose="pqc-keygen"):
    """One 32-byte hex seed per label, each from its own 256 quantum bits + 32 OS bytes."""
    # Health tests need a reasonable sample, so draw at least MIN_SAMPLE_BITS even for one seed.
    # On a failed health test the sample is discarded and redrawn (SP 800-90B style).
    for attempt in range(1, 4):
        bits, meta, counts = quantum_bits(max(BITS_PER_SEED * len(labels), MIN_SAMPLE_BITS))
        health = health_tests(bits, counts)
        health["attempt"] = attempt
        if health["passed"]:
            break
    else:
        raise RuntimeError(f"QRNG health tests failed 3 times: {health}")
    salt = os.urandom(32)
    seeds = {}
    for i, label in enumerate(labels):
        chunk = int(bits[i * BITS_PER_SEED:(i + 1) * BITS_PER_SEED], 2).to_bytes(32, "big")
        seeds[label] = hkdf(chunk + os.urandom(32), f"{purpose}:{label}".encode(), salt).hex()
    report = {"purpose": purpose, "labels": labels, "run": meta, "health": health, "ts": time.time()}
    config.EVIDENCE.mkdir(parents=True, exist_ok=True)
    with open(config.EVIDENCE / "qrng_runs.jsonl", "a") as f:
        f.write(json.dumps(report) + "\n")
    return seeds, report
