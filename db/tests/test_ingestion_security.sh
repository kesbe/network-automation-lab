#!/usr/bin/env bash

set -euo pipefail

CONTAINER="compliance-postgres-security-ci"
DB="network_compliance_security_test"

cleanup() {
    docker rm -f "${CONTAINER}" >/dev/null 2>&1 || true
}

trap cleanup EXIT

echo "===== START POSTGRESQL ====="

cleanup

docker run \
  -d \
  --name "${CONTAINER}" \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  docker.io/library/postgres@sha256:42b8b8b29c8a4e933d88943e5b03001a78794905cf786e6e7634e9f2abd5a0d3 \
  >/dev/null

READY=false

for i in $(seq 1 60)
do
    if docker exec "${CONTAINER}" \
        sh -c '
          pg_isready -U postgres >/dev/null 2>&1 &&
          test -f /var/lib/postgresql/data/postmaster.pid &&
          test "$(head -1 /var/lib/postgresql/data/postmaster.pid)" = "1"
        '
    then
        READY=true
        break
    fi

    sleep 1
done

if [ "${READY}" != "true" ]; then
    echo "postgres_ready=FAIL"
    echo
    echo "===== POSTGRESQL LOGS ====="
    docker logs "${CONTAINER}" 2>&1 || true
    exit 1
fi

echo "postgres_ready=PASS"

echo
echo "===== CREATE ADMIN ====="

docker exec "${CONTAINER}" \
  psql \
    -U postgres \
    -v ON_ERROR_STOP=1 \
    -c "
      CREATE ROLE netauto_admin
      LOGIN
      SUPERUSER;
    " \
  >/dev/null

docker exec "${CONTAINER}" \
  createdb \
    -U postgres \
    -O netauto_admin \
    "${DB}"

echo "database_created=PASS"

echo
echo "===== APPLY MIGRATIONS ====="

for migration in \
    db/migrations/001_compliance_schema.sql \
    db/migrations/002_finding_ingestion.sql \
    db/migrations/003_compliance_run_ingestion.sql \
    db/migrations/004_ingestion_security.sql
do
    docker exec \
      -i \
      "${CONTAINER}" \
      psql \
        -U netauto_admin \
        -d "${DB}" \
        -v ON_ERROR_STOP=1 \
      < "${migration}" \
      >/dev/null

    echo "$(basename "${migration}")=PASS"
done

echo
echo "===== VERIFY FUNCTION SECURITY ====="

RESULT="$(
docker exec "${CONTAINER}" \
  psql \
    -U netauto_admin \
    -d "${DB}" \
    -Atc "
      SELECT
        count(*)
      FROM pg_proc p
      JOIN pg_namespace n
        ON n.oid=p.pronamespace
      WHERE n.nspname='compliance'
        AND p.proname IN (
          'ingest_finding',
          'ingest_compliance_run'
        )
        AND pg_get_userbyid(p.proowner)='compliance_api_owner'
        AND p.prosecdef=true
        AND p.proconfig @> ARRAY['search_path=pg_catalog, compliance'];
    "
)"

test "${RESULT}" = "2"

echo "security_definer_functions=PASS"

echo
echo "===== VERIFY INGEST ROLE ====="

RESULT="$(
docker exec "${CONTAINER}" \
  psql \
    -U netauto_admin \
    -d "${DB}" \
    -Atc "
      SELECT
        has_schema_privilege(
          'compliance_ingest',
          'compliance',
          'USAGE'
        ),

        has_function_privilege(
          'compliance_ingest',
          'compliance.ingest_compliance_run(jsonb,bigint,bigint,bigint,text,text)',
          'EXECUTE'
        ),

        has_function_privilege(
          'compliance_ingest',
          'compliance.ingest_finding(text,text,text,text,text,text,text,text,text,boolean,text,boolean,text,text,jsonb,jsonb,jsonb,jsonb,timestamp with time zone,text,jsonb)',
          'EXECUTE'
        ),

        has_table_privilege(
          'compliance_ingest',
          'compliance.compliance_runs',
          'SELECT'
        ),

        has_table_privilege(
          'compliance_ingest',
          'compliance.compliance_runs',
          'INSERT'
        );
    "
)"

test "${RESULT}" = "t|t|f|f|f"

echo "least_privilege_boundary=PASS"

echo
echo "===== VERIFY PUBLIC EXECUTE REMOVED ====="

RESULT="$(
docker exec "${CONTAINER}" \
  psql \
    -U netauto_admin \
    -d "${DB}" \
    -Atc "
      SELECT
        has_function_privilege(
          'public',
          'compliance.ingest_compliance_run(jsonb,bigint,bigint,bigint,text,text)',
          'EXECUTE'
        );
    "
)"

test "${RESULT}" = "f"

echo "public_execute_removed=PASS"

echo
echo "===== SECURITY REGRESSION TEST ====="
echo "result=PASS"
