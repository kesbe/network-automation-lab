#!/usr/bin/env bash

set -uo pipefail

CONTAINER="${POSTGRES_TEST_CONTAINER:-compliance-postgres-test}"
DB="${POSTGRES_TEST_DB:-compliance_v3_migration_test}"
PGUSER="${POSTGRES_TEST_USER:-postgres}"

ROOT_DIR="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/../.." &&
    pwd
)"

MIGRATIONS="${ROOT_DIR}/db/migrations"

TEST_DB_CREATED=0
TEST_PREREQ_ROLE_CREATED=0
TEST_WRITER_ROLE_CREATED=0


fail() {
    echo
    echo "V3_MIGRATION_CHAIN_TEST=HOLD"
    echo "reason=$1"
    exit 1
}


safe_database_name() {
    [[ "${DB}" =~ ^compliance_v3_[a-z0-9_]+$ ]] || return 1
    [[ "${DB}" != "network_compliance" ]] || return 1
}


cleanup() {
    if [[ "${TEST_DB_CREATED}" -eq 1 ]]; then

        if ! safe_database_name; then
            echo "cleanup_database_name_gate=HOLD"

        else
            echo
            echo "===== CLEANUP DISPOSABLE DATABASE ====="
            echo "cleanup_database=${DB}"

            docker exec \
                "${CONTAINER}" \
                psql \
                    -v ON_ERROR_STOP=1 \
                    -U "${PGUSER}" \
                    -d postgres \
                    -c \
                    "DROP DATABASE IF EXISTS ${DB} WITH (FORCE);" \
                >/dev/null

            CLEANUP_RC=$?

            echo "cleanup_rc=${CLEANUP_RC}"

            if [[ "${CLEANUP_RC}" -eq 0 ]]; then
                echo "cleanup_gate=PASS"
            else
                echo "cleanup_gate=HOLD"
            fi
        fi
    fi


    if [[ "${TEST_WRITER_ROLE_CREATED}" -eq 1 ]]; then

        echo
        echo "===== CLEANUP TEST WRITER ROLE ====="
        echo "cleanup_role=compliance_writer"

        docker exec \
            "${CONTAINER}" \
            psql \
                -v ON_ERROR_STOP=1 \
                -U "${PGUSER}" \
                -d postgres \
                -c "DROP ROLE IF EXISTS compliance_writer;" \
            >/dev/null

        WRITER_CLEANUP_RC=$?

        echo "writer_cleanup_rc=${WRITER_CLEANUP_RC}"

        if [[ "${WRITER_CLEANUP_RC}" -eq 0 ]]; then
            echo "writer_cleanup_gate=PASS"
        else
            echo "writer_cleanup_gate=HOLD"
        fi
    fi


    if [[ "${TEST_PREREQ_ROLE_CREATED}" -eq 1 ]]; then

        echo
        echo "===== CLEANUP TEST PREREQUISITE ROLE ====="
        echo "cleanup_role=netauto_admin"

        docker exec \
            "${CONTAINER}" \
            psql \
                -v ON_ERROR_STOP=1 \
                -U "${PGUSER}" \
                -d postgres \
                -c "DROP ROLE IF EXISTS netauto_admin;" \
            >/dev/null

        ROLE_CLEANUP_RC=$?

        echo "role_cleanup_rc=${ROLE_CLEANUP_RC}"

        if [[ "${ROLE_CLEANUP_RC}" -eq 0 ]]; then
            echo "role_cleanup_gate=PASS"
        else
            echo "role_cleanup_gate=HOLD"
        fi
    fi
}

trap cleanup EXIT


echo
echo "===== V3 MIGRATION CHAIN TEST ====="

echo "container=${CONTAINER}"
echo "database=${DB}"
echo "user=${PGUSER}"


# ------------------------------------------------------------------
# Safety boundary
# ------------------------------------------------------------------

if ! safe_database_name; then
    fail "unsafe test database name: ${DB}"
fi

echo "test_database_name_gate=PASS"


EXACT_COUNT="$(
    docker ps -a \
        --filter "name=^/${CONTAINER}$" \
        --format '{{.ID}}' |
    sed '/^$/d' |
    wc -l
)"

echo "exact_container_count=${EXACT_COUNT}"

if [[ "${EXACT_COUNT}" -ne 1 ]]; then
    fail "expected exactly one Docker test container"
fi

echo "container_identity_gate=PASS"


RUNNING="$(
    docker inspect \
        "${CONTAINER}" \
        --format '{{.State.Running}}'
)"

echo "container_running=${RUNNING}"

if [[ "${RUNNING}" != "true" ]]; then
    fail "Docker PostgreSQL test container is not running"
fi


docker exec \
    "${CONTAINER}" \
    pg_isready \
        -U "${PGUSER}" \
    >/dev/null

READY_RC=$?

echo "postgres_readiness_rc=${READY_RC}"

if [[ "${READY_RC}" -ne 0 ]]; then
    fail "Docker PostgreSQL is not ready"
fi

echo "postgres_readiness_gate=PASS"


PRODUCTION_DB_COUNT="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -U "${PGUSER}" \
            -d postgres \
            -Atc "
SELECT count(*)
FROM pg_database
WHERE datname = 'network_compliance';
"
)"

echo "production_db_count=${PRODUCTION_DB_COUNT}"

if [[ "${PRODUCTION_DB_COUNT}" != "0" ]]; then
    fail "network_compliance unexpectedly exists in Docker test cluster"
fi

echo "production_db_absence_gate=PASS"


PREEXISTING_TEST_DB_COUNT="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -U "${PGUSER}" \
            -d postgres \
            -Atc "
SELECT count(*)
FROM pg_database
WHERE datname = '${DB}';
"
)"

echo "preexisting_test_db_count=${PREEXISTING_TEST_DB_COUNT}"

if [[ "${PREEXISTING_TEST_DB_COUNT}" != "0" ]]; then
    fail "test database already exists; refusing to drop unknown state"
fi

echo "test_db_collision_gate=PASS"


# ------------------------------------------------------------------
# Cluster prerequisite role
#
# Migration 004 intentionally assumes netauto_admin already exists.
# The Docker test cluster must emulate that production prerequisite.
# ------------------------------------------------------------------

echo
echo "===== VERIFY MIGRATION CLUSTER PREREQUISITE ====="

NETAUTO_ADMIN_COUNT="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -U "${PGUSER}" \
            -d postgres \
            -Atc "
SELECT count(*)
FROM pg_roles
WHERE rolname = 'netauto_admin';
"
)"

echo "netauto_admin_preexisting_count=${NETAUTO_ADMIN_COUNT}"

if [[ "${NETAUTO_ADMIN_COUNT}" == "0" ]]; then

    echo "creating_test_prerequisite_role=netauto_admin"

    docker exec \
        "${CONTAINER}" \
        psql \
            -v ON_ERROR_STOP=1 \
            -U "${PGUSER}" \
            -d postgres \
            -c "
CREATE ROLE netauto_admin
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;
"

    ROLE_CREATE_RC=$?

    echo "netauto_admin_create_rc=${ROLE_CREATE_RC}"

    if [[ "${ROLE_CREATE_RC}" -ne 0 ]]; then
        fail "unable to create netauto_admin test prerequisite"
    fi

    TEST_PREREQ_ROLE_CREATED=1

elif [[ "${NETAUTO_ADMIN_COUNT}" == "1" ]]; then

    echo "netauto_admin_preexisting=YES"

else

    fail "unexpected netauto_admin role count"
fi


NETAUTO_ATTRIBUTES="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -U "${PGUSER}" \
            -d postgres \
            -At \
            -F '|' \
            -c "
SELECT
    rolcanlogin,
    rolsuper,
    rolcreatedb,
    rolcreaterole
FROM pg_roles
WHERE rolname = 'netauto_admin';
"
)"

echo "netauto_admin_attributes=${NETAUTO_ATTRIBUTES}"

if [[ "${NETAUTO_ATTRIBUTES}" != "f|f|f|f" ]]; then
    fail "unsafe netauto_admin test prerequisite attributes"
fi

echo "netauto_admin_prerequisite_gate=PASS"


# ------------------------------------------------------------------
# Runtime writer prerequisite
#
# compliance_writer is an externally provisioned LOGIN identity.
# Controlled API permissions come from membership in compliance_ingest,
# which migration 004 creates.
# ------------------------------------------------------------------

echo
echo "===== VERIFY COMPLIANCE WRITER PREREQUISITE ====="

WRITER_COUNT="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -U "${PGUSER}" \
            -d postgres \
            -Atc "
SELECT count(*)
FROM pg_roles
WHERE rolname = 'compliance_writer';
"
)"

echo "compliance_writer_preexisting_count=${WRITER_COUNT}"

if [[ "${WRITER_COUNT}" == "0" ]]; then

    docker exec \
        "${CONTAINER}" \
        psql \
            -v ON_ERROR_STOP=1 \
            -U "${PGUSER}" \
            -d postgres \
            -c "
CREATE ROLE compliance_writer
    LOGIN
    PASSWORD NULL
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;
"

    WRITER_CREATE_RC=$?

    echo "compliance_writer_create_rc=${WRITER_CREATE_RC}"

    if [[ "${WRITER_CREATE_RC}" -ne 0 ]]; then
        fail "unable to create compliance_writer test prerequisite"
    fi

    TEST_WRITER_ROLE_CREATED=1

elif [[ "${WRITER_COUNT}" != "1" ]]; then

    fail "unexpected compliance_writer role count"
fi


WRITER_ATTRIBUTES="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -U "${PGUSER}" \
            -d postgres \
            -At \
            -F '|' \
            -c "
SELECT
    rolcanlogin,
    rolsuper,
    rolcreatedb,
    rolcreaterole,
    rolreplication,
    rolbypassrls
FROM pg_roles
WHERE rolname = 'compliance_writer';
"
)"

echo "compliance_writer_attributes=${WRITER_ATTRIBUTES}"

if [[ "${WRITER_ATTRIBUTES}" != "t|f|f|f|f|f" ]]; then
    fail "unsafe compliance_writer test attributes"
fi

echo "compliance_writer_prerequisite_gate=PASS"


# ------------------------------------------------------------------
# Create disposable database
# ------------------------------------------------------------------

echo
echo "===== CREATE DISPOSABLE DATABASE ====="

docker exec \
    "${CONTAINER}" \
    psql \
        -v ON_ERROR_STOP=1 \
        -U "${PGUSER}" \
        -d postgres \
        -c "CREATE DATABASE ${DB};"

CREATE_RC=$?

echo "create_database_rc=${CREATE_RC}"

if [[ "${CREATE_RC}" -ne 0 ]]; then
    fail "unable to create disposable database"
fi

TEST_DB_CREATED=1

echo "create_database_gate=PASS"


# ------------------------------------------------------------------
# Apply the complete V3 migration chain
# ------------------------------------------------------------------

echo
echo "===== APPLY V3 MIGRATIONS 001 -> 008 ====="

MIGRATION_FILES=(
    "001_compliance_schema.sql"
    "002_finding_ingestion.sql"
    "003_compliance_run_ingestion.sql"
    "004_ingestion_security.sql"
    "005_absence_based_resolution.sql"
    "006_transport_event_idempotency.sql"
    "007_stale_reconciliation_security.sql"
    "008_remediation_ticket_lifecycle.sql"
)

APPLIED=0

for NAME in "${MIGRATION_FILES[@]}"; do
    FILE="${MIGRATIONS}/${NAME}"

    if [[ ! -f "${FILE}" ]]; then
        fail "missing migration: ${NAME}"
    fi

    echo
    echo "applying=${NAME}"

    docker exec \
        -i \
        "${CONTAINER}" \
        psql \
            -v ON_ERROR_STOP=1 \
            -U "${PGUSER}" \
            -d "${DB}" \
        < "${FILE}"

    APPLY_RC=$?

    echo "migration_rc=${APPLY_RC}"

    if [[ "${APPLY_RC}" -ne 0 ]]; then
        fail "migration failed: ${NAME}"
    fi

    APPLIED=$((APPLIED + 1))

    echo "migration_gate=PASS|${NAME}"

    if [[ "${NAME}" == "004_ingestion_security.sql" ]]; then

        echo
        echo "===== BIND RUNTIME WRITER TO INGEST CAPABILITY ====="

        docker exec \
            "${CONTAINER}" \
            psql \
                -v ON_ERROR_STOP=1 \
                -U "${PGUSER}" \
                -d "${DB}" \
                -c "
GRANT compliance_ingest
TO compliance_writer;
"

        WRITER_GRANT_RC=$?

        echo "writer_capability_grant_rc=${WRITER_GRANT_RC}"

        if [[ "${WRITER_GRANT_RC}" -ne 0 ]]; then
            fail "unable to grant compliance_ingest to compliance_writer"
        fi


        WRITER_MEMBER="$(
            docker exec \
                "${CONTAINER}" \
                psql \
                    -U "${PGUSER}" \
                    -d "${DB}" \
                    -Atc "
SELECT pg_has_role(
    'compliance_writer',
    'compliance_ingest',
    'MEMBER'
);
"
        )"

        echo "writer_is_compliance_ingest_member=${WRITER_MEMBER}"

        if [[ "${WRITER_MEMBER}" != "t" ]]; then
            fail "compliance_writer capability membership missing"
        fi

        echo "writer_capability_membership_gate=PASS"
    fi
done

echo
echo "migrations_applied=${APPLIED}"

if [[ "${APPLIED}" -ne 8 ]]; then
    fail "expected 8 migrations"
fi

echo "migration_count_gate=PASS"


# ------------------------------------------------------------------
# Verify required tables
# ------------------------------------------------------------------

echo
echo "===== VERIFY REQUIRED TABLES ====="

REQUIRED_TABLES=(
    compliance_runs
    compliance_run_devices
    compliance_findings
    finding_occurrences
    finding_events
    transport_events
    remediation_attempts
    ticket_records
)

for TABLE in "${REQUIRED_TABLES[@]}"; do
    COUNT="$(
        docker exec \
            "${CONTAINER}" \
            psql \
                -U "${PGUSER}" \
                -d "${DB}" \
                -Atc "
SELECT count(*)
FROM pg_tables
WHERE schemaname = 'compliance'
  AND tablename = '${TABLE}';
"
    )"

    echo "table=${TABLE}|count=${COUNT}"

    if [[ "${COUNT}" != "1" ]]; then
        fail "required table missing: ${TABLE}"
    fi
done

echo "required_tables_gate=PASS"


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

echo "compliance_table_count=${TABLE_COUNT}"


# ------------------------------------------------------------------
# Verify required API functions
# ------------------------------------------------------------------

echo
echo "===== VERIFY REQUIRED FUNCTIONS ====="

REQUIRED_FUNCTIONS=(
    ingest_finding
    ingest_compliance_run
    claim_transport_event
    complete_transport_event
    fail_transport_event
    reclaim_stale_transport_event
    inspect_stale_transport_event
    create_remediation_attempt
    record_remediation_approval
    transition_remediation_attempt
    upsert_ticket_record
    update_ticket_record
)

for FUNCTION_NAME in "${REQUIRED_FUNCTIONS[@]}"; do
    COUNT="$(
        docker exec \
            "${CONTAINER}" \
            psql \
                -U "${PGUSER}" \
                -d "${DB}" \
                -Atc "
SELECT count(*)
FROM pg_proc p
JOIN pg_namespace n
  ON n.oid = p.pronamespace
WHERE n.nspname = 'compliance'
  AND p.proname = '${FUNCTION_NAME}';
"
    )"

    echo "function=${FUNCTION_NAME}|count=${COUNT}"

    if [[ "${COUNT}" -lt 1 ]]; then
        fail "required function missing: ${FUNCTION_NAME}"
    fi
done

echo "required_functions_gate=PASS"


# ------------------------------------------------------------------
# Verify V3 SECURITY DEFINER boundary
# ------------------------------------------------------------------

echo
echo "===== VERIFY V3 FUNCTION SECURITY ====="

SECURE_COUNT="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -U "${PGUSER}" \
            -d "${DB}" \
            -Atc "
SELECT count(*)
FROM pg_proc p
JOIN pg_namespace n
  ON n.oid = p.pronamespace
WHERE n.nspname = 'compliance'
  AND p.proname IN (
      'create_remediation_attempt',
      'record_remediation_approval',
      'transition_remediation_attempt',
      'upsert_ticket_record',
      'update_ticket_record'
  )
  AND p.prosecdef = true
  AND EXISTS (
      SELECT 1
      FROM unnest(
          COALESCE(
              p.proconfig,
              ARRAY[]::text[]
          )
      ) AS c(setting)
      WHERE setting =
            'search_path=pg_catalog, compliance'
  );
"
)"

echo "secure_v3_function_count=${SECURE_COUNT}"

if [[ "${SECURE_COUNT}" != "5" ]]; then
    fail "V3 functions do not all have SECURITY DEFINER and fixed search_path"
fi

echo "v3_function_security_gate=PASS"


# ------------------------------------------------------------------
# Verify capability roles
# ------------------------------------------------------------------

echo
echo "===== VERIFY CAPABILITY ROLES ====="

for ROLE in \
    compliance_api_owner \
    compliance_remediation \
    compliance_ticketing
do
    ROLE_RESULT="$(
        docker exec \
            "${CONTAINER}" \
            psql \
                -U "${PGUSER}" \
                -d "${DB}" \
                -Atc "
SELECT
    rolname || '|' ||
    rolcanlogin || '|' ||
    rolsuper
FROM pg_roles
WHERE rolname = '${ROLE}';
"
    )"

    echo "role=${ROLE}|attributes=${ROLE_RESULT}"

    if [[ "${ROLE_RESULT}" != "${ROLE}|false|false" ]]; then
        fail "unsafe or missing capability role: ${ROLE}"
    fi
done

echo "capability_role_gate=PASS"


# ------------------------------------------------------------------
# Verify no direct DML to V3 application roles
# ------------------------------------------------------------------

echo
echo "===== VERIFY NO DIRECT TABLE DML ====="

DIRECT_DML="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -U "${PGUSER}" \
            -d "${DB}" \
            -At \
            -F '|' \
            -c "
SELECT
    has_table_privilege(
        'compliance_remediation',
        'compliance.remediation_attempts',
        'INSERT'
    ),
    has_table_privilege(
        'compliance_remediation',
        'compliance.remediation_attempts',
        'UPDATE'
    ),
    has_table_privilege(
        'compliance_ticketing',
        'compliance.ticket_records',
        'INSERT'
    ),
    has_table_privilege(
        'compliance_ticketing',
        'compliance.ticket_records',
        'UPDATE'
    );
"
)"

echo "direct_dml=${DIRECT_DML}"

if [[ "${DIRECT_DML}" != "f|f|f|f" ]]; then
    fail "application capability role has direct table DML"
fi

echo "no_direct_dml_gate=PASS"


# ------------------------------------------------------------------
# Verify cross-capability separation
# ------------------------------------------------------------------

echo
echo "===== VERIFY CAPABILITY SEPARATION ====="

CAPABILITIES="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -U "${PGUSER}" \
            -d "${DB}" \
            -At \
            -F '|' \
            -c "
SELECT
    has_function_privilege(
        'compliance_remediation',
        p1.oid,
        'EXECUTE'
    ),
    has_function_privilege(
        'compliance_remediation',
        p2.oid,
        'EXECUTE'
    ),
    has_function_privilege(
        'compliance_ticketing',
        p3.oid,
        'EXECUTE'
    ),
    has_function_privilege(
        'compliance_ticketing',
        p4.oid,
        'EXECUTE'
    )
FROM
    (
        SELECT p.oid
        FROM pg_proc p
        JOIN pg_namespace n
          ON n.oid = p.pronamespace
        WHERE n.nspname = 'compliance'
          AND p.proname =
              'create_remediation_attempt'
        LIMIT 1
    ) p1,
    (
        SELECT p.oid
        FROM pg_proc p
        JOIN pg_namespace n
          ON n.oid = p.pronamespace
        WHERE n.nspname = 'compliance'
          AND p.proname =
              'record_remediation_approval'
        LIMIT 1
    ) p2,
    (
        SELECT p.oid
        FROM pg_proc p
        JOIN pg_namespace n
          ON n.oid = p.pronamespace
        WHERE n.nspname = 'compliance'
          AND p.proname =
              'record_remediation_approval'
        LIMIT 1
    ) p3,
    (
        SELECT p.oid
        FROM pg_proc p
        JOIN pg_namespace n
          ON n.oid = p.pronamespace
        WHERE n.nspname = 'compliance'
          AND p.proname =
              'transition_remediation_attempt'
        LIMIT 1
    ) p4;
"
)"

echo "capability_matrix=${CAPABILITIES}"

# Expected:
#
# remediation can create attempt             true
# remediation can approve                    false
# ticketing can approve                      true
# ticketing can transition remediation       false

if [[ "${CAPABILITIES}" != "t|f|t|f" ]]; then
    fail "cross-capability privilege boundary incorrect"
fi

echo "capability_separation_gate=PASS"


# ------------------------------------------------------------------
# Empty V3 state
# ------------------------------------------------------------------

echo
echo "===== VERIFY EMPTY V3 STATE ====="

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
    (
        SELECT count(*)
        FROM compliance.compliance_findings
    ),
    (
        SELECT count(*)
        FROM compliance.remediation_attempts
    ),
    (
        SELECT count(*)
        FROM compliance.ticket_records
    );
"
)"

echo "empty_state=${COUNTS}"

if [[ "${COUNTS}" != "0|0|0" ]]; then
    fail "new database does not have empty lifecycle state"
fi

echo "empty_v3_state_gate=PASS"


echo
echo "========================================"
echo "V3 MIGRATION CHAIN TEST: PASS"
echo "========================================"

exit 0
