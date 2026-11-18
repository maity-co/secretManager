#!/usr/bin/env bash
set -euo pipefail
export PGDATA=/var/lib/postgresql/data PGHOST=/run/postgresql
mkdir -p "$PGDATA" /keys /backups "$PGHOST"
chown postgres:postgres "$PGDATA"
chmod 0700 "$PGDATA"
chown postgres:secretmanager "$PGHOST"
chmod 0770 "$PGHOST"
chown secretmanager:secretmanager /keys
chmod 0700 /keys
chown secretmanager:secretmanager /backups
chmod 0700 /backups
gosu secretmanager node /app/src/cli.js init --directory /keys
if [[ ! -s "$PGDATA/PG_VERSION" ]]; then
  gosu postgres initdb --auth-local=peer --auth-host=reject --encoding=UTF8 --no-locale >/dev/null
fi
if [[ "$(cat "$PGDATA/PG_VERSION")" != 17 ]]; then
  echo 'PostgreSQL data requires a supported major-version migration.' >&2
  exit 1
fi
db_pid=''
app_pid=''
cleanup() {
  trap - TERM INT EXIT
  if [[ -n "$app_pid" ]]; then kill -TERM "$app_pid" 2>/dev/null || true; fi
  if [[ -n "$db_pid" ]]; then kill -TERM "$db_pid" 2>/dev/null || true; fi
  if [[ -n "$app_pid" ]]; then wait "$app_pid" 2>/dev/null || true; fi
  if [[ -n "$db_pid" ]]; then wait "$db_pid" 2>/dev/null || true; fi
}
trap cleanup EXIT
trap 'exit 0' TERM INT
gosu postgres postgres -D "$PGDATA" -c listen_addresses='' -c unix_socket_directories="$PGHOST" -c unix_socket_group=secretmanager -c unix_socket_permissions=0770 -c log_statement=none -c log_min_error_statement=panic -c log_error_verbosity=terse -c log_min_messages=panic &
db_pid=$!
for attempt in {1..60}; do
  if gosu postgres pg_isready -q -h "$PGHOST" -U postgres -d postgres; then break; fi
  if ! kill -0 "$db_pid" 2>/dev/null; then echo 'Database startup failed.' >&2; exit 1; fi
  sleep 1
done
gosu postgres pg_isready -q -h "$PGHOST" -U postgres -d postgres
if [[ "$(gosu postgres psql --no-psqlrc -h "$PGHOST" --username=postgres --dbname=postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname='secretmanager'")" != 1 ]]; then
  gosu postgres env PGUSER=postgres PGDATABASE=postgres createuser -h "$PGHOST" secretmanager
fi
if [[ "$(gosu postgres psql --no-psqlrc -h "$PGHOST" --username=postgres --dbname=postgres -tAc "SELECT 1 FROM pg_database WHERE datname='secretmanager'")" != 1 ]]; then
  gosu postgres env PGUSER=postgres PGDATABASE=postgres createdb -h "$PGHOST" --owner=secretmanager secretmanager
fi
if [[ $# -gt 0 ]]; then
  gosu secretmanager "$@"
  exit $?
fi
gosu secretmanager node /app/src/server.js &
app_pid=$!
set +e
wait -n "$db_pid" "$app_pid"
status=$?
set -e
# Either process exiting unexpectedly stops the whole service.
if [[ "$status" -eq 0 ]]; then exit 1; else exit "$status"; fi
