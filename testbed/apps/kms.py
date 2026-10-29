"""Key Management Service. The only process that can read signing keys (/kms is mounted into this container alone).

  GET  /keys   public keys: kid, purpose, alg, SPKI (base64url DER)
  POST /sign   {purpose, alg, data_b64} -> {sig_b64, kid, alg}; the caller (mTLS client certificate CN)
               must be authorised for the purpose
Key files: /kms/<purpose>.<rsa|fndsa|slhdsa>.key / .pub, created by the migration controller (QRNG-seeded).
"""
import glob
import os
import subprocess

import bank

KEYDIR = "/kms"
TAG_ALG = {v: k for k, v in bank.ALG_TAG.items()}
POLICY = {"jwt": {"identity"}, "audit": {"ledger"}, "settlement": {"settlement"}}   # purpose -> allowed callers


def _keys():
    out = []
    for pub in sorted(glob.glob(f"{KEYDIR}/*.pub")):
        purpose, tag = os.path.basename(pub).split(".")[:2]
        der = subprocess.run(["openssl", "pkey", "-pubin", "-in", pub, "-outform", "DER"], capture_output=True).stdout
        kid = f"{purpose}-{tag}-{bank.sha256_hex(der)[:8]}"
        out.append({"kid": kid, "purpose": purpose, "alg": TAG_ALG[tag], "spki": bank.b64u(der), "use": "sig"})
    return out


_cache = {"mtime": None, "keys": []}


def keys():
    m = max((os.path.getmtime(p) for p in glob.glob(f"{KEYDIR}/*.pub")), default=0)
    if m != _cache["mtime"]:
        _cache.update(mtime=m, keys=_keys())
    return _cache["keys"]


class KMS(bank.Handler):
    routes = {("GET", "/keys"): "list_keys", ("POST", "/sign"): "sign"}

    def list_keys(self):
        self.reply(200, {"keys": keys()})

    def sign(self):
        b = self.body()
        purpose, alg, caller = b.get("purpose"), b.get("alg"), self.client_cn()
        if caller not in POLICY.get(purpose, set()):
            return self.reply(403, {"error": f"{caller or 'unknown caller'} is not allowed to sign for {purpose}"})
        tag = bank.ALG_TAG.get(alg)
        keyfile = f"{KEYDIR}/{purpose}.{tag}.key"
        if not tag or not os.path.exists(keyfile):
            return self.reply(404, {"error": f"no {alg} key for {purpose}"})
        sig = bank.openssl_sign(alg, keyfile, bank.b64u_dec(b["data_b64"]))
        kid = next(k["kid"] for k in keys() if k["purpose"] == purpose and k["alg"] == alg)
        self.reply(200, {"sig_b64": bank.b64u(sig), "kid": kid, "alg": alg})


if __name__ == "__main__":
    bank.serve(KMS)
