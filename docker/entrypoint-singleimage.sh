#!/usr/bin/env bash
# Single-image entrypoint: bring up an embedded PostgreSQL, then hand off to the
# normal docker-entrypoint.sh (migrate + collectstatic + admin) with honcho as
# the command so gunicorn (web) + dbos_worker (worker) run supervised in ONE
# container.
#
# This is the "one artifact, no external DB" deploy. The classic 3-tier
# compose/k8s (external Postgres + separate web/worker) still ships for anyone
# who wants privilege separation / horizontal scale.
#
# pgdata MUST live on a mounted volume (default /data/pgdata) or scan history is
# lost when the container is replaced.
set -euo pipefail

log() { echo "[singleimage] $*"; }

PGDATA="${PGDATA:-/data/pgdata}"
DB_NAME="${DB_NAME:-openeasd}"
DB_USER="${DB_USER:-openeasd}"
DB_PASSWORD="${DB_PASSWORD:-}"
export DB_HOST="127.0.0.1"
export DB_PORT="${DB_PORT:-5432}"

PG_BIN="$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1 || true)"
if [ -z "${PG_BIN}" ] || [ ! -x "${PG_BIN}/pg_ctl" ]; then
  log "FATAL: PostgreSQL binaries not found under /usr/lib/postgresql/*/bin"
  exit 1
fi
if [ -z "${DB_PASSWORD}" ]; then
  log "FATAL: DB_PASSWORD must be set (the production settings guard also refuses the default)."
  exit 1
fi

# The postgres server must not run as root; use the packaged 'postgres' user.
mkdir -p "${PGDATA}" /var/run/postgresql
chown -R postgres:postgres "${PGDATA}" /var/run/postgresql

FIRST_BOOT=0
if [ ! -s "${PGDATA}/PG_VERSION" ]; then
  FIRST_BOOT=1
  log "initialising a fresh PostgreSQL cluster at ${PGDATA}"
  su postgres -c "${PG_BIN}/initdb -D '${PGDATA}' --auth-local=trust --auth-host=scram-sha-256 --encoding=UTF8"
fi

log "starting PostgreSQL (${PG_BIN})"
su postgres -c "${PG_BIN}/pg_ctl -D '${PGDATA}' -o '-c listen_addresses=127.0.0.1 -p ${DB_PORT} -c unix_socket_directories=/var/run/postgresql' -w -t 60 start"

for _ in $(seq 1 30); do
  if su postgres -c "${PG_BIN}/pg_isready -h 127.0.0.1 -p ${DB_PORT}" >/dev/null 2>&1; then break; fi
  sleep 1
done

run_sql() { su postgres -c "${PG_BIN}/psql -h /var/run/postgresql -p ${DB_PORT} -v ON_ERROR_STOP=1 -c \"$1\""; }
scalar()  { su postgres -c "${PG_BIN}/psql -h /var/run/postgresql -p ${DB_PORT} -tAc \"$1\""; }

if [ -z "$(scalar "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'")" ]; then
  log "creating role ${DB_USER}"
  run_sql "CREATE ROLE \\\"${DB_USER}\\\" LOGIN PASSWORD '${DB_PASSWORD}' CREATEDB;"
else
  run_sql "ALTER ROLE \\\"${DB_USER}\\\" PASSWORD '${DB_PASSWORD}';"
fi
if [ -z "$(scalar "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'")" ]; then
  log "creating database ${DB_NAME}"
  run_sql "CREATE DATABASE \\\"${DB_NAME}\\\" OWNER \\\"${DB_USER}\\\";"
fi

# Hand off to the standard bootstrap (migrate + collectstatic + admin) with
# honcho as the command — it supervises web + worker in this one container.
log "handing off to docker-entrypoint.sh (web bootstrap) + honcho"
exec env OPENEASD_ROLE=web ./docker-entrypoint.sh honcho start -f docker/Procfile
