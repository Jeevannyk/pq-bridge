#!/bin/sh
# Usage: start.sh <role>
#   gateway                      nginx only (public TLS, rate limiting, routing over mTLS)
#   identity accounts payments   app on 127.0.0.1:8000 + nginx sidecar (mTLS in, mTLS egress, DB egress)
#   ledger kms settlement
#   clearing                     external partner, same shape
#   postgres                     PostgreSQL 17 on 127.0.0.1:5433 + nginx stream sidecar (mTLS) on :5432
#   legacy                       old customer app (classical TLS only)
ROLE="$1"
case "$ROLE" in
  gateway)
    exec nginx -c /conf/gateway.conf -g 'daemon off;'
    ;;
  identity|accounts|payments|ledger|kms|settlement|clearing)
    cd /apps && python3 -u "/apps/$ROLE.py" &
    exec nginx -c "/conf/$ROLE.conf" -g 'daemon off;'
    ;;
  postgres)
    mkdir -p /data/pg && chown -R postgres:postgres /data/pg
    if [ ! -s /data/pg/PG_VERSION ]; then
      su postgres -s /bin/sh -c "initdb -D /data/pg -U postgres --auth-local=trust --auth-host=scram-sha-256" >/dev/null
    fi
    su postgres -s /bin/sh -c "pg_ctl -D /data/pg -o '-c listen_addresses=127.0.0.1 -p 5433' -l /data/pg/server.log -w start"
    cd /apps && python3 -u /apps/dbinit.py
    exec nginx -c /conf/postgres.conf -g 'daemon off;'
    ;;
  legacy)
    export OPENSSL_CONF=/apps/legacy-openssl.cnf
    exec python3 -u /apps/legacy.py
    ;;
  *)
    echo "unknown role $ROLE"; exit 1
    ;;
esac
