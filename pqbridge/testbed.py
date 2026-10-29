"""Control plane for the Docker mini-bank: PKI, nginx config rendering, reloads, stats.

All crypto operations run inside the `toolbox` container with OpenSSL 3.5, so the
host needs only Docker.
"""
import json
import shutil
import subprocess
import time

from . import config
from .config import CONF, GROUPS, INITIAL_STATE, PKI, PQ, RUNTIME, STATE, TESTBED

COMPOSE = ["docker", "compose", "-f", str(TESTBED / "docker-compose.yml")]
BANK = list(config.SERVICES)                      # the bank's own services
ROLES = BANK + list(config.PARTNERS)              # every node with an nginx sidecar (incl. the clearing house)
IDENTITIES = ROLES + ["probe"]                    # every TLS identity (probe = the gate's test client)
KMS = RUNTIME / "kms"
CLEARING_TRUST = RUNTIME / "clearing-trust"
KMS_PURPOSES = ["jwt", "audit", "settlement"]


def run(cmd, check=True, timeout=600):
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}\n{p.stdout}\n{p.stderr}")
    return p


def compose(*args, check=True, timeout=900):
    return run(COMPOSE + list(args), check=check, timeout=timeout)


def exec_in(service, script, check=True, timeout=120):
    return compose("exec", "-T", service, "sh", "-c", script, check=check, timeout=timeout)


def tool(script, check=True, timeout=120):
    return exec_in("toolbox", script, check=check, timeout=timeout)


# ------------------------------------------------------------------ state ----
def read_state():
    return json.loads((STATE / "services.json").read_text())


def write_state(st):
    tmp = STATE / "services.json.tmp"
    tmp.write_text(json.dumps(st, indent=2))
    # On Windows the rename fails while a container (or OneDrive sync) has the target open; retry briefly.
    for attempt in range(40):
        try:
            tmp.replace(STATE / "services.json")
            return
        except PermissionError:
            time.sleep(0.05)
    tmp.replace(STATE / "services.json")


def read_json(name, default=None):
    try:
        return json.loads((STATE / name).read_text())
    except Exception:
        return default if default is not None else {}


# -------------------------------------------------------------------- PKI ----
CA_EXT = "-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign"
LEAF_EXT = ("-addext basicConstraints=CA:FALSE -addext keyUsage=critical,digitalSignature "
            "-addext extendedKeyUsage=serverAuth,clientAuth")


def _seed_file(label, seed_hex):
    """Write QRNG-derived bytes to a file that `openssl genpkey -rand` mixes into OpenSSL's DRBG."""
    return f"printf '{seed_hex}' | python3 -c 'import sys;sys.stdout.buffer.write(bytes.fromhex(sys.stdin.read()))' > /tmp/q_{label}.bin"


def _leaf(name, alg, seed=None):
    """Shell snippet: key + CSR + cert for one identity, signed by the matching root."""
    san = f"DNS:{name}" + (",DNS:localhost" if name == "gateway" else "")
    if alg == "rsa":
        keygen = f"openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out certs/{name}.rsa.key"
        root = "rsa-root"
    else:
        keygen = (f"{_seed_file(name, seed)} && openssl genpkey -algorithm {PQ['leaf_sig']} "
                  f"-rand /tmp/q_{name}.bin -out certs/{name}.pq.key")
        root = "pq-root"
    return (f"{keygen} && openssl req -new -key certs/{name}.{alg}.key -subj /CN={name}/O=PQBank "
            f"-addext subjectAltName={san} {LEAF_EXT} -out /tmp/{name}.csr && "
            f"openssl x509 -req -in /tmp/{name}.csr -CA {root}.crt -CAkey {root}.key -copy_extensions copy "
            f"-days 90 -out certs/{name}.{alg}.crt 2>/dev/null")


def pki_init():
    """Classical baseline: RSA-2048 root + leaf certs; KMS RSA keys for jwt / audit / settlement;
    the clearing house trusts the bank's RSA settlement key."""
    steps = [
        "cd /pki && mkdir -p certs trust",
        "openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa-root.key -out rsa-root.crt "
        f"-subj '/CN=PQBank RSA Root CA' -days 365 {CA_EXT} 2>/dev/null",
        *[_leaf(n, "rsa") for n in IDENTITIES],
        *[f"openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /kms/{p}.rsa.key && "
          f"openssl pkey -in /kms/{p}.rsa.key -pubout -out /kms/{p}.rsa.pub" for p in KMS_PURPOSES],
        "cp /kms/settlement.rsa.pub /clearing-trust/settlement-rsa.pem",
        "cp rsa-root.crt trust/rsa.pem && cp rsa-root.crt trust/client-trust.pem",
        "chmod -R a+r /pki /clearing-trust",
    ]
    tool(" && ".join(steps), timeout=300)


def pki_issue_pq(seeds):
    """SLH-DSA root CA + FN-DSA-512 leaf certs. `seeds` maps identity name (and 'root') -> QRNG-derived hex."""
    steps = [
        "cd /pki",
        f"{_seed_file('root', seeds['root'])} && openssl genpkey -algorithm {PQ['root_sig']} "
        "-rand /tmp/q_root.bin -out pq-root.key",
        f"openssl req -x509 -new -key pq-root.key -subj '/CN=PQBank SLH-DSA Root CA' -days 3650 {CA_EXT} -out pq-root.crt",
        *[_leaf(n, "pq", seeds[n]) for n in IDENTITIES],
        "cat rsa-root.crt pq-root.crt > trust/both.tmp && mv trust/both.tmp trust/both.pem",
        "cp trust/both.pem trust/ct.tmp && mv trust/ct.tmp trust/client-trust.pem",
        "chmod -R a+r /pki",
    ]
    tool(" && ".join(steps), timeout=300)


KMS_ALG = {"fndsa": PQ["leaf_sig"], "slhdsa": PQ["root_sig"]}


def kms_keygen(purpose, tag, seed):
    """Create a new KMS signing key (QRNG-seeded) for a purpose: tag fndsa (FN-DSA-512) or slhdsa (SLH-DSA)."""
    tool(f"{_seed_file(purpose + tag, seed)} && openssl genpkey -algorithm {KMS_ALG[tag]} -rand /tmp/q_{purpose}{tag}.bin "
         f"-out /kms/{purpose}.{tag}.key && openssl pkey -in /kms/{purpose}.{tag}.key -pubout -out /kms/{purpose}.{tag}.pub")


def kms_has(purpose, tag):
    return (KMS / f"{purpose}.{tag}.pub").exists()


def clearing_trust_key(purpose, tag):
    """Hand the clearing house (partner) the bank's new public key, as a bank would in a key ceremony."""
    tool(f"cp /kms/{purpose}.{tag}.pub /clearing-trust/{purpose}-{tag}.pem && chmod a+r /clearing-trust/*")


# ------------------------------------------------------------------ nginx ----
def _out_groups(svc_state):
    # A PQ-enabled client must also offer the pure PQ group, or it cannot reach a PQ-only peer.
    return f"{GROUPS['hybrid']}:{PQ['pq_group']}" if svc_state["kex"] != "classical" else GROUPS["classical"]


def _client_tls(name, s, target, prefix="proxy_"):
    """mTLS settings for a client (this node) talking to `target`."""
    return f"""
      {prefix}ssl_server_name on;
      {prefix}ssl_name {target};
      {prefix}ssl_protocols TLSv1.3;
      {prefix}ssl_verify on;
      {prefix}ssl_verify_depth 2;
      {prefix}ssl_trusted_certificate /pki/trust/{s['trust']}.pem;
      {prefix}ssl_certificate /pki/certs/{name}.{s['cert']}.crt;
      {prefix}ssl_certificate_key /pki/certs/{name}.{s['cert']}.key;
      {prefix}ssl_conf_command Groups {_out_groups(s)};"""


def _proxy(name, s, target, strip=True):
    up = target.replace("-", "_")
    # A request landing on a peer mid-reload is retried; payments/ledger are idempotent on transfer ids.
    return f"""
      proxy_pass https://{up}{'/' if strip else ''};
      proxy_set_header Host {target};
      proxy_next_upstream error timeout http_502 non_idempotent;
      proxy_next_upstream_tries 3;{_client_tls(name, s, target)}"""


def _server_tls(name, s, cert=None, verify_client=True):
    c = cert or s["cert"]
    v = f"""
    ssl_client_certificate /pki/trust/{s['trust']}.pem;
    ssl_verify_client on;
    ssl_verify_depth 2;""" if verify_client else ""
    return f"""
    ssl_certificate /pki/certs/{name}.{c}.crt;
    ssl_certificate_key /pki/certs/{name}.{c}.key;
    ssl_ecdh_curve {GROUPS[s['kex']]};{v}"""


def render_conf(name, st):
    s = st[name]
    http_targets = [t for c, t in config.CALLS if c == name and t != "postgres"]
    uses_db = (name, "postgres") in config.CALLS
    upstreams = "".join(f"  upstream {t.replace('-', '_')} {{ server {t}:443 max_fails=0; server {t}:443 max_fails=0; }}\n"
                        for t in http_targets)
    out = [("load_module /usr/lib/nginx/modules/ngx_stream_module.so;\n" if uses_db or name == "postgres" else "")
           + f"worker_processes 1;\npid /run/nginx/{name}.pid;\nerror_log /dev/stderr warn;\nevents {{ worker_connections 512; }}\n"]

    if name == "gateway":
        r = lambda t, strip=False: _proxy(name, s, t, strip)
        out.append(f"""http {{
  access_log off;
  limit_req_zone $binary_remote_addr zone=api:10m rate=300r/s;
{upstreams}
  server {{
    listen 443 ssl;
    server_name gateway localhost;
    ssl_protocols TLSv1.2 TLSv1.3;{_server_tls(name, s, cert=s['public_cert'], verify_client=False)}
    location = /health {{ default_type application/json; return 200 '{{"ok":true}}'; }}
    location /oauth/ {{ limit_req zone=api burst=600 nodelay;{r('identity')}
    }}
    location = /.well-known/jwks.json {{{r('identity')}
    }}
    location /api/accounts {{ limit_req zone=api burst=600 nodelay;{r('accounts')}
    }}
    location /api/payments/ {{ limit_req zone=api burst=600 nodelay;{r('payments')}
    }}
  }}
}}
""")
    elif name != "postgres":
        egress = "".join(f"""
    location /{t}/ {{{_proxy(name, s, t)}
    }}""" for t in http_targets)
        out.append(f"""http {{
  access_log off;
{upstreams}
  server {{
    listen 443 ssl;
    server_name {name};
    ssl_protocols TLSv1.3;{_server_tls(name, s)}
    location / {{
      proxy_pass http://127.0.0.1:8000;
      proxy_set_header X-Client-CN $ssl_client_s_dn;
    }}
  }}
""" + (f"""
  server {{
    listen 127.0.0.1:9001;{egress}
  }}
""" if http_targets else "") + "}\n")

    if name == "postgres":
        out.append(f"""stream {{
  server {{
    listen 5432 ssl;
    ssl_protocols TLSv1.3;{_server_tls(name, s)}
    proxy_pass 127.0.0.1:5433;
  }}
}}
""")
    elif uses_db:
        out.append(f"""stream {{
  upstream pg {{ server postgres:5432; }}
  server {{
    listen 127.0.0.1:6543;
    proxy_pass pg;
    proxy_ssl on;{_client_tls(name, s, "postgres")}
  }}
}}
""")
    return "".join(out)


def write_confs(st, only=None):
    CONF.mkdir(parents=True, exist_ok=True)
    for name in only or ROLES:
        (CONF / f"{name}.conf").write_text(render_conf(name, st), newline="\n")


def reload(name):
    """Validate then gracefully reload nginx: in-flight connections finish, no downtime."""
    exec_in(name, f"nginx -t -c /conf/{name}.conf 2>&1 && nginx -s reload -c /conf/{name}.conf")


def apply_state(st, changed):
    write_state(st)
    write_confs(st, only=[c for c in changed if c in ROLES])
    for c in changed:
        if c in ROLES:
            reload(c)


# ------------------------------------------------------------- lifecycle ----
def up():
    for d in (PKI, STATE, CONF, RUNTIME / "evidence", KMS, CLEARING_TRUST):
        d.mkdir(parents=True, exist_ok=True)
    compose("build", timeout=3600)        # first build compiles liboqs; slow laptops need well over 15 min
    compose("up", "-d", "toolbox")
    if not (PKI / "rsa-root.crt").exists():
        pki_init()
    if not (STATE / "services.json").exists():
        write_state(INITIAL_STATE)
    write_confs(read_state())
    compose("up", "-d")
    wait_healthy()


def wait_healthy(timeout=240):
    t0 = time.time()
    while time.time() - t0 < timeout:
        lg = read_json("loadgen.json")
        if lg.get("ok", 0) > 5:
            return True
        time.sleep(2)
    raise RuntimeError("the bank did not start serving customers; check `docker compose -f testbed/docker-compose.yml logs`")


def down(wipe=False):
    compose("down", "-v" if wipe else "--remove-orphans", check=False)
    if wipe and RUNTIME.exists():
        shutil.rmtree(RUNTIME)


def ledger_stats():
    p = exec_in("ledger", "wget -qO- http://127.0.0.1:8000/stats", check=False)
    try:
        return json.loads(p.stdout)
    except Exception:
        return {}


def traffic():
    return {"payments": read_json("loadgen.json"), "legacy": read_json("legacy.json"), "ledger": ledger_stats()}
