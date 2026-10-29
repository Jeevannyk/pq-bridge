"""A customer app built before PQC: classical key exchange only (legacy-openssl.cnf) and it trusts only the RSA
root. Checks the gateway once a second. If a migration breaks old customers, the verification gate sees it here."""
import json
import os
import ssl
import time
import urllib.request

OUT = "/state/legacy.json"
stats = {"ok": 0, "fail": 0, "last_error": None, "recent_failures": []}


def probe():
    c = ssl.create_default_context(cafile="/pki/rsa-root.crt")
    with urllib.request.urlopen("https://gateway/health", context=c, timeout=5) as r:
        r.read()


while not os.path.exists("/pki/rsa-root.crt"):
    time.sleep(1)
while True:                                  # don't count boot-time failures
    try:
        probe()
        break
    except Exception:
        time.sleep(1)

while True:
    try:
        probe()
        stats["ok"] += 1
    except Exception as e:
        stats["fail"] += 1
        stats["last_error"] = f"{type(e).__name__}: {str(e)[:160]}"
        stats["recent_failures"] = (stats["recent_failures"] + [{"t": time.time(), "reason": stats["last_error"]}])[-20:]
    stats["updated"] = time.time()
    with open(OUT + ".tmp", "w") as f:
        json.dump(stats, f)
    try:
        os.replace(OUT + ".tmp", OUT)
    except PermissionError:                       # the host file is briefly locked (OneDrive / Windows): retry next second
        pass
    time.sleep(1)
