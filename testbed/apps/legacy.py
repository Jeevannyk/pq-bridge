"""A customer client that predates PQC: classical groups only (see
legacy-openssl.cnf) and trusts only the RSA root. Probes the gateway once a
second. If a migration breaks it, the verification gate sees it here."""
import json
import os
import ssl
import time
import urllib.request

OUT = "/state/legacy.json"
stats = {"ok": 0, "fail": 0, "last_error": None, "recent_failures": []}

while not os.path.exists("/pki/rsa-root.crt"):
    time.sleep(1)

while True:
    try:
        c = ssl.create_default_context(cafile="/pki/rsa-root.crt")
        with urllib.request.urlopen("https://gateway/health", context=c, timeout=5) as r:
            r.read()
        stats["ok"] += 1
    except Exception as e:
        stats["fail"] += 1
        stats["last_error"] = f"{type(e).__name__}: {str(e)[:160]}"
        stats["recent_failures"] = (stats["recent_failures"] + [{"t": time.time(), "reason": stats["last_error"]}])[-20:]
    stats["updated"] = time.time()
    with open(OUT + ".tmp", "w") as f:
        json.dump(stats, f)
    os.replace(OUT + ".tmp", OUT)
    time.sleep(1)
