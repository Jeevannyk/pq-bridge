"""Gate probes, run inside the toolbox container (on the bank network, OpenSSL 3.5).

  probe.py timing <service> <n>   -> handshake latency stats (ms) with probe client cert
  probe.py negative               -> attack / misuse cases that MUST be rejected
"""
import base64
import json
import os
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

TRUST = "/pki/trust/both.pem" if os.path.exists("/pki/trust/both.pem") else "/pki/trust/rsa.pem"
PROBE_CERT = ("/pki/certs/probe.rsa.crt", "/pki/certs/probe.rsa.key")


def client_ctx(cert=PROBE_CERT):
    c = ssl.create_default_context(cafile=TRUST)
    if cert:
        c.load_cert_chain(*cert)
    return c


def timing(svc, n):
    ctx = client_ctx()
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        with socket.create_connection((svc, 443), timeout=5) as s:
            with ctx.wrap_socket(s, server_hostname=svc):
                pass
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    return {"service": svc, "n": n, "median_ms": round(statistics.median(samples), 2),
            "p95_ms": round(samples[int(0.95 * (n - 1))], 2)}


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def post_pay(token):
    req = urllib.request.Request("https://gateway/pay", method="POST",
                                 data=json.dumps({"tx_id": "neg-" + os.urandom(4).hex(), "from": "X", "to": "Y",
                                                  "amount": 1}).encode(),
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, context=client_ctx(None), timeout=10) as r:
            return r.status, r.read().decode()[:120]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:120]


def signed_expired_token():
    head = b64u(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    body = b64u(json.dumps({"sub": "attacker", "iat": 1, "exp": 2}).encode())
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(f"{head}.{body}".encode())
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", "/pki/jwt/rs256.key", f.name],
                         capture_output=True).stdout
    return f"{head}.{body}.{b64u(sig)}"


def get_health(svc, cert):
    try:
        with urllib.request.urlopen(f"https://{svc}/health", context=client_ctx(cert), timeout=5) as r:
            return r.status, "accepted"
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:80].strip()
    except Exception as e:
        return 0, f"{type(e).__name__}: {str(e)[:80]}"


def negative():
    cases = []
    body = b64u(json.dumps({"sub": "attacker", "exp": 9999999999}).encode())
    forged = f"{b64u(json.dumps({'alg': 'RS256', 'typ': 'JWT'}).encode())}.{body}.{b64u(os.urandom(256))}"
    alg_none = f"{b64u(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode())}.{body}."
    for name, tok in [("forged JWT signature", forged),
                      ("alg=none JWT", alg_none),
                      ("expired JWT (validly signed)", signed_expired_token())]:
        code, msg = post_pay(tok)
        cases.append({"case": name, "target": "payment-switch", "result": code, "detail": msg,
                      "rejected": code in (401, 403)})
    rogue_dir = tempfile.mkdtemp()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=rogue",
                    "-keyout", f"{rogue_dir}/k", "-out", f"{rogue_dir}/c", "-days", "1"], capture_output=True)
    for svc in ["card-auth", "payment-switch", "ledger"]:
        code, msg = get_health(svc, None)
        cases.append({"case": "no client certificate", "target": svc, "result": code, "detail": msg,
                      "rejected": code != 200})
        code, msg = get_health(svc, (f"{rogue_dir}/c", f"{rogue_dir}/k"))
        cases.append({"case": "rogue self-signed client cert", "target": svc, "result": code, "detail": msg,
                      "rejected": code != 200})
    return cases


if __name__ == "__main__":
    if sys.argv[1] == "timing":
        print(json.dumps(timing(sys.argv[2], int(sys.argv[3]))))
    elif sys.argv[1] == "negative":
        print(json.dumps(negative()))
