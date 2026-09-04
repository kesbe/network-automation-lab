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


TEST_EXPORTER_RUNTIME_ROLE_CREATED=0


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

    if [[ "${TEST_EXPORTER_RUNTIME_ROLE_CREATED}" -eq 1 ]]; then

        echo
        echo "===== CLEANUP TEST EXPORTER RUNTIME ROLE ====="
        echo "cleanup_role=compliance_exporter_runtime"

        docker exec \
            "${CONTAINER}" \
            psql \
                -v ON_ERROR_STOP=1 \
                -U "${PGUSER}" \
                -d postgres \
                -c \
                "DROP ROLE IF EXISTS compliance_exporter_runtime;" \
            >/dev/null

        EXPORTER_RUNTIME_CLEANUP_RC=$?

        echo \
            "exporter_runtime_cleanup_rc="\
"${EXPORTER_RUNTIME_CLEANUP_RC}"

        if [[ \
            "${EXPORTER_RUNTIME_CLEANUP_RC}" -eq 0 \
        ]]; then
            echo \
                "exporter_runtime_cleanup_gate=PASS"
        else
            echo \
                "exporter_runtime_cleanup_gate=HOLD"
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
echo "===== APPLY V3 MIGRATIONS 001 -> 014 ====="

MIGRATION_FILES=(
    "001_compliance_schema.sql"
    "002_finding_ingestion.sql"
    "003_compliance_run_ingestion.sql"
    "004_ingestion_security.sql"
    "005_absence_based_resolution.sql"
    "006_transport_event_idempotency.sql"
    "007_stale_reconciliation_security.sql"
    "008_remediation_ticket_lifecycle.sql"
    "009_compliance_exporter_read_model.sql"
    "010_v3_transport_event_identity.sql"
    "011_v3_activation_source_durability.sql"
    "012_v3_transactional_run_ingestion.sql"
    "013_v3_activation_source_reader.sql"
    "014_v3_activation_sources_for_run_reader.sql"
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

if [[ "${APPLIED}" -ne 14 ]]; then
    fail "expected 14 migrations"
fi

echo "migration_count_gate=PASS"


# ------------------------------------------------------------------
# Create disposable exporter runtime identity
#
# Production runtime credentials are NOT created by migration 009.
# This LOGIN role exists only to prove inherited read-only capability.
# ------------------------------------------------------------------

echo
echo "===== CREATE TEST EXPORTER RUNTIME IDENTITY ====="

EXPORTER_RUNTIME_PREEXISTING="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -U "${PGUSER}" \
            -d postgres \
            -Atc "
SELECT count(*)
FROM pg_roles
WHERE rolname = 'compliance_exporter_runtime';
"
)"

echo \
    "exporter_runtime_preexisting_count="\
"${EXPORTER_RUNTIME_PREEXISTING}"

if [[ "${EXPORTER_RUNTIME_PREEXISTING}" != "0" ]]; then
    fail \
        "compliance_exporter_runtime unexpectedly already exists"
fi


docker exec \
    "${CONTAINER}" \
    psql \
        -v ON_ERROR_STOP=1 \
        -U "${PGUSER}" \
        -d postgres \
        -c "
CREATE ROLE compliance_exporter_runtime
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;

GRANT compliance_exporter
    TO compliance_exporter_runtime;
" \
    >/dev/null

EXPORTER_RUNTIME_CREATE_RC=$?

echo \
    "exporter_runtime_create_rc="\
"${EXPORTER_RUNTIME_CREATE_RC}"

if [[ "${EXPORTER_RUNTIME_CREATE_RC}" -ne 0 ]]; then
    fail \
        "unable to create disposable exporter runtime identity"
fi

TEST_EXPORTER_RUNTIME_ROLE_CREATED=1


EXPORTER_RUNTIME_ATTRIBUTES="$(
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
WHERE rolname = 'compliance_exporter_runtime';
"
)"

echo \
    "exporter_runtime_attributes="\
"${EXPORTER_RUNTIME_ATTRIBUTES}"

if [[ \
    "${EXPORTER_RUNTIME_ATTRIBUTES}" \
    != "t|f|f|f|f|f" \
]]; then
    fail \
        "unsafe exporter runtime role attributes"
fi


EXPORTER_RUNTIME_MEMBER="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -U "${PGUSER}" \
            -d postgres \
            -Atc "
SELECT pg_has_role(
    'compliance_exporter_runtime',
    'compliance_exporter',
    'member'
);
"
)"

echo \
    "exporter_runtime_is_exporter_member="\
"${EXPORTER_RUNTIME_MEMBER}"

if [[ "${EXPORTER_RUNTIME_MEMBER}" != "t" ]]; then
    fail \
        "exporter runtime capability membership missing"
fi

echo "exporter_runtime_identity_gate=PASS"


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
# Verify exporter read-model views
# ------------------------------------------------------------------

echo
echo "===== VERIFY EXPORTER READ MODEL VIEWS ====="

REQUIRED_EXPORTER_VIEWS=(
    exporter_findings_summary
    exporter_remediation_summary
    exporter_active_ticket_summary
    exporter_overview
)

for VIEW in "${REQUIRED_EXPORTER_VIEWS[@]}"; do

    COUNT="$(
        docker exec \
            "${CONTAINER}" \
            psql \
                -U "${PGUSER}" \
                -d "${DB}" \
                -Atc "
SELECT count(*)
FROM pg_views
WHERE schemaname = 'compliance'
  AND viewname = '${VIEW}';
"
    )"

    echo "view=${VIEW}|count=${COUNT}"

    if [[ "${COUNT}" != "1" ]]; then
        fail "required exporter view missing: ${VIEW}"
    fi
done

echo "required_exporter_views_gate=PASS"


EXPORTER_VIEW_COUNT="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -U "${PGUSER}" \
            -d "${DB}" \
            -Atc "
SELECT count(*)
FROM pg_views
WHERE schemaname = 'compliance'
  AND viewname LIKE 'exporter_%';
"
)"

echo "exporter_view_count=${EXPORTER_VIEW_COUNT}"

if [[ "${EXPORTER_VIEW_COUNT}" != "4" ]]; then
    fail "unexpected exporter read-model view count"
fi

echo "exporter_view_count_gate=PASS"


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
    compliance_ticketing \
    compliance_exporter_owner \
    compliance_exporter
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
# Verify exporter read-model security
# ------------------------------------------------------------------

echo
echo "===== VERIFY EXPORTER READ MODEL SECURITY ====="


# The capability role and inherited runtime role must both be able
# to SELECT all four approved aggregate views.

EXPORTER_VIEW_PRIVILEGES="$(
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
        'compliance_exporter',
        'compliance.exporter_findings_summary',
        'SELECT'
    ),
    has_table_privilege(
        'compliance_exporter',
        'compliance.exporter_remediation_summary',
        'SELECT'
    ),
    has_table_privilege(
        'compliance_exporter',
        'compliance.exporter_active_ticket_summary',
        'SELECT'
    ),
    has_table_privilege(
        'compliance_exporter',
        'compliance.exporter_overview',
        'SELECT'
    ),
    has_table_privilege(
        'compliance_exporter_runtime',
        'compliance.exporter_findings_summary',
        'SELECT'
    ),
    has_table_privilege(
        'compliance_exporter_runtime',
        'compliance.exporter_remediation_summary',
        'SELECT'
    ),
    has_table_privilege(
        'compliance_exporter_runtime',
        'compliance.exporter_active_ticket_summary',
        'SELECT'
    ),
    has_table_privilege(
        'compliance_exporter_runtime',
        'compliance.exporter_overview',
        'SELECT'
    );
"
)"

echo \
    "exporter_view_privileges="\
"${EXPORTER_VIEW_PRIVILEGES}"

if [[ \
    "${EXPORTER_VIEW_PRIVILEGES}" \
    != "t|t|t|t|t|t|t|t" \
]]; then
    fail \
        "exporter approved-view SELECT privileges are incomplete"
fi

echo "exporter_view_select_gate=PASS"


# Prove an actual query works while running under the disposable
# runtime identity.

EXPORTER_RUNTIME_VIEW_QUERY="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -q \
            -v ON_ERROR_STOP=1 \
            -U "${PGUSER}" \
            -d "${DB}" \
            -At \
            -F '|' \
            -c "
SET ROLE compliance_exporter_runtime;

SELECT
    (SELECT count(*)
     FROM compliance.exporter_findings_summary),
    (SELECT count(*)
     FROM compliance.exporter_remediation_summary),
    (SELECT count(*)
     FROM compliance.exporter_active_ticket_summary),
    (SELECT count(*)
     FROM compliance.exporter_overview);
"
)"

EXPORTER_RUNTIME_VIEW_RC=$?

echo \
    "exporter_runtime_view_query_rc="\
"${EXPORTER_RUNTIME_VIEW_RC}"

echo \
    "exporter_runtime_view_query="\
"${EXPORTER_RUNTIME_VIEW_QUERY}"

if [[ "${EXPORTER_RUNTIME_VIEW_RC}" -ne 0 ]]; then
    fail \
        "exporter runtime cannot query approved views"
fi

# Empty summaries are expected before fixture data exists.
# exporter_overview itself always returns one aggregate row.

if [[ \
    "${EXPORTER_RUNTIME_VIEW_QUERY}" \
    != "0|0|0|1" \
]]; then
    fail \
        "unexpected empty exporter read-model state"
fi

echo "exporter_runtime_view_query_gate=PASS"


# Direct base-table SELECT must remain unavailable.

EXPORTER_BASE_SELECT="$(
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
        'compliance_exporter_runtime',
        'compliance.compliance_findings',
        'SELECT'
    ),
    has_table_privilege(
        'compliance_exporter_runtime',
        'compliance.remediation_attempts',
        'SELECT'
    ),
    has_table_privilege(
        'compliance_exporter_runtime',
        'compliance.ticket_records',
        'SELECT'
    );
"
)"

echo \
    "exporter_base_select_privileges="\
"${EXPORTER_BASE_SELECT}"

if [[ "${EXPORTER_BASE_SELECT}" != "f|f|f" ]]; then
    fail \
        "exporter runtime has forbidden base-table SELECT"
fi

echo "exporter_base_select_privilege_gate=PASS"


# Prove the denial with an actual query, not only catalog metadata.

BASE_SELECT_OUTPUT="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -q \
            -v ON_ERROR_STOP=1 \
            -U "${PGUSER}" \
            -d "${DB}" \
            -c "
SET ROLE compliance_exporter_runtime;

SELECT count(*)
FROM compliance.compliance_findings;
" \
        2>&1
)"

BASE_SELECT_RC=$?

echo "exporter_direct_base_select_rc=${BASE_SELECT_RC}"

if [[ "${BASE_SELECT_RC}" -eq 0 ]]; then
    echo "${BASE_SELECT_OUTPUT}"
    fail \
        "exporter runtime unexpectedly read base table"
fi

if ! printf '%s\n' "${BASE_SELECT_OUTPUT}" |
     grep -Fq \
       "permission denied for table compliance_findings"
then
    echo "${BASE_SELECT_OUTPUT}"
    fail \
        "base-table SELECT failed for unexpected reason"
fi

echo "exporter_direct_base_select_denial_gate=PASS"


# Direct base-table mutation must be unavailable as well.

EXPORTER_BASE_DML="$(
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
        'compliance_exporter_runtime',
        'compliance.compliance_findings',
        'INSERT'
    ),
    has_table_privilege(
        'compliance_exporter_runtime',
        'compliance.compliance_findings',
        'UPDATE'
    ),
    has_table_privilege(
        'compliance_exporter_runtime',
        'compliance.compliance_findings',
        'DELETE'
    ),

    has_table_privilege(
        'compliance_exporter_runtime',
        'compliance.remediation_attempts',
        'INSERT'
    ),
    has_table_privilege(
        'compliance_exporter_runtime',
        'compliance.remediation_attempts',
        'UPDATE'
    ),
    has_table_privilege(
        'compliance_exporter_runtime',
        'compliance.remediation_attempts',
        'DELETE'
    ),

    has_table_privilege(
        'compliance_exporter_runtime',
        'compliance.ticket_records',
        'INSERT'
    ),
    has_table_privilege(
        'compliance_exporter_runtime',
        'compliance.ticket_records',
        'UPDATE'
    ),
    has_table_privilege(
        'compliance_exporter_runtime',
        'compliance.ticket_records',
        'DELETE'
    );
"
)"

echo \
    "exporter_base_dml_privileges="\
"${EXPORTER_BASE_DML}"

if [[ \
    "${EXPORTER_BASE_DML}" \
    != "f|f|f|f|f|f|f|f|f" \
]]; then
    fail \
        "exporter runtime has forbidden base-table DML"
fi

echo "exporter_base_dml_gate=PASS"


# Exporter must not inherit remediation or ticket lifecycle functions.

EXPORTER_FUNCTIONS="$(
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
        'compliance_exporter_runtime',
        'compliance.create_remediation_attempt(text,text,text,text,text,text,text,text,text,integer,bigint,jsonb)',
        'EXECUTE'
    ),
    has_function_privilege(
        'compliance_exporter_runtime',
        'compliance.record_remediation_approval(text,text,text,jsonb)',
        'EXECUTE'
    ),
    has_function_privilege(
        'compliance_exporter_runtime',
        'compliance.transition_remediation_attempt(text,text,text,bigint,bigint,bigint,text,text,text,jsonb)',
        'EXECUTE'
    ),
    has_function_privilege(
        'compliance_exporter_runtime',
        'compliance.upsert_ticket_record(text,text,text,text,text,text,text,text,boolean,jsonb)',
        'EXECUTE'
    ),
    has_function_privilege(
        'compliance_exporter_runtime',
        'compliance.update_ticket_record(text,text,text,text,boolean,text,text,text,jsonb)',
        'EXECUTE'
    );
"
)"

echo \
    "exporter_lifecycle_function_privileges="\
"${EXPORTER_FUNCTIONS}"

if [[ "${EXPORTER_FUNCTIONS}" != "f|f|f|f|f" ]]; then
    fail \
        "exporter runtime can execute lifecycle mutation APIs"
fi

echo "exporter_function_separation_gate=PASS"


# Runtime has schema usage but no schema-create capability.

EXPORTER_SCHEMA_PRIVILEGES="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -U "${PGUSER}" \
            -d "${DB}" \
            -At \
            -F '|' \
            -c "
SELECT
    has_schema_privilege(
        'compliance_exporter_runtime',
        'compliance',
        'USAGE'
    ),
    has_schema_privilege(
        'compliance_exporter_runtime',
        'compliance',
        'CREATE'
    );
"
)"

echo \
    "exporter_schema_privileges="\
"${EXPORTER_SCHEMA_PRIVILEGES}"

if [[ "${EXPORTER_SCHEMA_PRIVILEGES}" != "t|f" ]]; then
    fail \
        "unsafe exporter schema privileges"
fi

echo "exporter_schema_privilege_gate=PASS"

echo "phase7e_exporter_security_gate=PASS"


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
