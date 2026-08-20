#!/usr/bin/env bash

set -euo pipefail

CONTAINER="${POSTGRES_TEST_CONTAINER:-compliance-postgres-test}"
DB="${POSTGRES_TEST_DB:-compliance_ci_migration_test}"
PGUSER="${POSTGRES_TEST_USER:-postgres}"

ROOT_DIR="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/../.." &&
    pwd
)"

MIGRATIONS="${ROOT_DIR}/db/migrations"

cleanup() {
    docker exec \
      "${CONTAINER}" \
      psql \
        -U "${PGUSER}" \
        -d postgres \
        -c "DROP DATABASE IF EXISTS ${DB};" \
      >/dev/null 2>&1 || true
}

trap cleanup EXIT

echo "===== RESET TEST DATABASE ====="

docker exec \
  "${CONTAINER}" \
  psql \
    -U "${PGUSER}" \
    -d postgres \
    -c "DROP DATABASE IF EXISTS ${DB};"

docker exec \
  "${CONTAINER}" \
  psql \
    -U "${PGUSER}" \
    -d postgres \
    -c "CREATE DATABASE ${DB};"


echo
echo "===== APPLY MIGRATIONS ====="

for migration in \
  "${MIGRATIONS}/001_compliance_schema.sql" \
  "${MIGRATIONS}/002_finding_ingestion.sql" \
  "${MIGRATIONS}/003_compliance_run_ingestion.sql"
do
    echo "Applying $(basename "${migration}")"

    docker exec \
      -i \
      "${CONTAINER}" \
      psql \
        -v ON_ERROR_STOP=1 \
        -U "${PGUSER}" \
        -d "${DB}" \
      < "${migration}"
done


echo
echo "===== VERIFY TABLE COUNT ====="

TABLE_COUNT="$(
    docker exec \
      "${CONTAINER}" \
      psql \
        -U "${PGUSER}" \
        -d "${DB}" \
        -Atc "
SELECT count(*)
FROM pg_tables
WHERE schemaname = 'compliance';
"
)"

echo "tables=${TABLE_COUNT}"

test "${TABLE_COUNT}" = "5"


echo
echo "===== VERIFY REQUIRED TABLES ====="

TABLES="$(
    docker exec \
      "${CONTAINER}" \
      psql \
        -U "${PGUSER}" \
        -d "${DB}" \
        -Atc "
SELECT tablename
FROM pg_tables
WHERE schemaname = 'compliance'
ORDER BY tablename;
"
)"

printf '%s\n' "${TABLES}"

for table in \
  compliance_findings \
  compliance_run_devices \
  compliance_runs \
  finding_events \
  finding_occurrences
do
    printf '%s\n' "${TABLES}" |
        grep -qx "${table}"
done


echo
echo "===== VERIFY DATABASE API ====="

FUNCTIONS="$(
    docker exec \
      "${CONTAINER}" \
      psql \
        -U "${PGUSER}" \
        -d "${DB}" \
        -Atc "
SELECT p.proname
FROM pg_proc p
JOIN pg_namespace n
  ON n.oid = p.pronamespace
WHERE n.nspname = 'compliance'
  AND p.proname IN (
      'ingest_finding',
      'ingest_compliance_run'
  )
ORDER BY p.proname;
"
)"

printf '%s\n' "${FUNCTIONS}"

printf '%s\n' "${FUNCTIONS}" |
    grep -qx 'ingest_compliance_run'

printf '%s\n' "${FUNCTIONS}" |
    grep -qx 'ingest_finding'


echo
echo "===== VERIFY EMPTY INITIAL STATE ====="

COUNTS="$(
    docker exec \
      "${CONTAINER}" \
      psql \
        -U "${PGUSER}" \
        -d "${DB}" \
        -At \
        -F '|' \
        -c "
SELECT
    (SELECT count(*)
       FROM compliance.compliance_runs),

    (SELECT count(*)
       FROM compliance.compliance_run_devices),

    (SELECT count(*)
       FROM compliance.compliance_findings),

    (SELECT count(*)
       FROM compliance.finding_occurrences),

    (SELECT count(*)
       FROM compliance.finding_events);
"
)"

echo "${COUNTS}"

test "${COUNTS}" = "0|0|0|0|0"


echo
echo "========================================"
echo "MIGRATION CHAIN TEST: PASS"
echo "========================================"
