#!/bin/sh
# Usage: start.sh <role>
#   service roles (card-auth, payment-switch, ledger): app on 127.0.0.1:8000 + nginx TLS sidecar
#   gateway: nginx only
#   loadgen / legacy: python client loop
ROLE="$1"
case "$ROLE" in
  gateway)
    exec nginx -c /conf/gateway.conf -g 'daemon off;'
    ;;
  card-auth|payment-switch|ledger)
    python3 -u /apps/service.py "$ROLE" &
    exec nginx -c "/conf/$ROLE.conf" -g 'daemon off;'
    ;;
  loadgen)
    exec python3 -u /apps/loadgen.py
    ;;
  legacy)
    # Legacy client: classical groups only, trusts only the RSA root.
    export OPENSSL_CONF=/apps/legacy-openssl.cnf
    exec python3 -u /apps/legacy.py
    ;;
  *)
    echo "unknown role $ROLE"; exit 1
    ;;
esac
