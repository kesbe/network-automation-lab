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
    echo "V3_LIFECYCLE_BEHAVIOR_TEST=HOLD"
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
echo "===== V3 LIFECYCLE BEHAVIOR TEST ====="

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


# ==================================================================
# V3 lifecycle behavioral acceptance
# ==================================================================

echo
echo "===== V3 LIFECYCLE BEHAVIOR MATRIX ====="

BEHAVIOR_PASS_COUNT=0


behavior_scalar() {
    docker exec \
        "${CONTAINER}" \
        psql \
            -X \
            -q \
            -A \
            -t \
            -v ON_ERROR_STOP=1 \
            -U "${PGUSER}" \
            -d "${DB}" \
            -c "$1"
}


behavior_exec() {
    local LABEL="$1"
    local SQL="$2"

    docker exec \
        "${CONTAINER}" \
        psql \
            -X \
            -q \
            -v ON_ERROR_STOP=1 \
            -U "${PGUSER}" \
            -d "${DB}" \
            -c "${SQL}" \
        >/dev/null

    local RC=$?

    echo "${LABEL}_setup_rc=${RC}"

    if [[ "${RC}" -ne 0 ]]; then
        fail "${LABEL} setup failed"
    fi
}


behavior_expect() {
    local LABEL="$1"
    local EXPECTED="$2"
    local SQL="$3"

    local OUTPUT
    local RC

    OUTPUT="$(
        behavior_scalar "${SQL}" 2>&1
    )"

    RC=$?

    echo
    echo "${LABEL}_rc=${RC}"
    echo "${LABEL}_actual=${OUTPUT}"
    echo "${LABEL}_expected=${EXPECTED}"

    if [[ \
        "${RC}" -eq 0 \
        && "${OUTPUT}" == "${EXPECTED}" \
    ]]; then
        echo "${LABEL}=PASS"

        BEHAVIOR_PASS_COUNT=$((BEHAVIOR_PASS_COUNT + 1))
    else
        fail "${LABEL} assertion failed"
    fi
}


behavior_expect_failure() {
    local LABEL="$1"
    local NEEDLE="$2"
    local SQL="$3"

    local OUTPUT
    local RC

    OUTPUT="$(
        docker exec \
            "${CONTAINER}" \
            psql \
                -X \
                -q \
                -v ON_ERROR_STOP=1 \
                -U "${PGUSER}" \
                -d "${DB}" \
                -c "${SQL}" \
            2>&1
    )"

    RC=$?

    echo
    echo "${LABEL}_rc=${RC}"

    if [[ "${RC}" -eq 0 ]]; then
        echo "${OUTPUT}"
        fail "${LABEL} unexpectedly succeeded"
    fi

    if printf '%s\n' "${OUTPUT}" |
       grep -Fq -- "${NEEDLE}"
    then
        echo "${LABEL}_expected_failure=${NEEDLE}"
        echo "${LABEL}=PASS"

        BEHAVIOR_PASS_COUNT=$((BEHAVIOR_PASS_COUNT + 1))
    else
        echo "${OUTPUT}"
        fail "${LABEL} failed for unexpected reason"
    fi
}


# ------------------------------------------------------------------
# Durable finding fixtures
#
# Direct inserts are fixture setup only and run as the disposable
# PostgreSQL superuser. Application capability roles remain unable
# to perform direct table DML.
# ------------------------------------------------------------------

echo
echo "===== SEED DURABLE FINDING FIXTURES ====="

docker exec \
    -i \
    "${CONTAINER}" \
    psql \
        -X \
        -q \
        -v ON_ERROR_STOP=1 \
        -U "${PGUSER}" \
        -d "${DB}" \
<<'SQL'
INSERT INTO compliance.compliance_findings (
    finding_id,
    finding_fingerprint,

    device,
    policy_id,
    control,
    finding_scope,

    category,
    severity,
    ticket_required,
    owner,

    status,
    first_seen,
    last_seen,

    remediation_supported,
    remediation_mode,
    remediation_risk,

    expected,
    current_actual
)
VALUES
(
    'finding-auto-main',
    'fingerprint-auto-main',
    'leaf01',
    'POL-AUTO-MAIN',
    'bgp_maximum_paths',
    'device',
    'routing',
    'high',
    false,
    'network',
    'OPEN',
    now(),
    now(),
    true,
    'auto',
    'low',
    '{"maximum_paths": 4}'::jsonb,
    '{"maximum_paths": 1}'::jsonb
),
(
    'finding-auto-failure',
    'fingerprint-auto-failure',
    'leaf03',
    'POL-AUTO-FAIL',
    'bgp_maximum_paths',
    'device',
    'routing',
    'high',
    false,
    'network',
    'OPEN',
    now(),
    now(),
    true,
    'auto',
    'low',
    '{"maximum_paths": 4}'::jsonb,
    '{"maximum_paths": 1}'::jsonb
),
(
    'finding-recheck-failure',
    'fingerprint-recheck-failure',
    'leaf04',
    'POL-RECHECK-FAIL',
    'bgp_maximum_paths',
    'device',
    'routing',
    'high',
    false,
    'network',
    'OPEN',
    now(),
    now(),
    true,
    'auto',
    'low',
    '{"maximum_paths": 4}'::jsonb,
    '{"maximum_paths": 1}'::jsonb
),
(
    'finding-illegal-transition',
    'fingerprint-illegal-transition',
    'leaf05',
    'POL-ILLEGAL',
    'bgp_maximum_paths',
    'device',
    'routing',
    'medium',
    false,
    'network',
    'OPEN',
    now(),
    now(),
    true,
    'auto',
    'low',
    '{"maximum_paths": 4}'::jsonb,
    '{"maximum_paths": 1}'::jsonb
),
(
    'finding-approval-main',
    'fingerprint-approval-main',
    'edge01',
    'POL-APPROVAL-MAIN',
    'ntp_servers',
    'device',
    'system',
    'high',
    true,
    'network',
    'OPEN',
    now(),
    now(),
    true,
    'approval_required',
    'medium',
    '{"servers": ["10.0.0.10"]}'::jsonb,
    '{"servers": []}'::jsonb
),
(
    'finding-approval-reject',
    'fingerprint-approval-reject',
    'edge02',
    'POL-APPROVAL-REJECT',
    'ntp_servers',
    'device',
    'system',
    'high',
    true,
    'network',
    'OPEN',
    now(),
    now(),
    true,
    'approval_required',
    'medium',
    '{"servers": ["10.0.0.10"]}'::jsonb,
    '{"servers": []}'::jsonb
),
(
    'finding-approval-no-ticket',
    'fingerprint-approval-no-ticket',
    'edge03',
    'POL-APPROVAL-NO-TICKET',
    'ntp_servers',
    'device',
    'system',
    'high',
    false,
    'network',
    'OPEN',
    now(),
    now(),
    true,
    'approval_required',
    'medium',
    '{"servers": ["10.0.0.10"]}'::jsonb,
    '{"servers": []}'::jsonb
),
(
    'finding-blocked',
    'fingerprint-blocked',
    'leaf06',
    'POL-BLOCKED',
    'bgp_maximum_paths',
    'device',
    'routing',
    'medium',
    false,
    'network',
    'OPEN',
    now(),
    now(),
    true,
    'auto',
    'low',
    '{"maximum_paths": 4}'::jsonb,
    '{"maximum_paths": 1}'::jsonb
),
(
    'finding-report-only',
    'fingerprint-report-only',
    'leaf07',
    'POL-REPORT',
    'logging_server',
    'device',
    'system',
    'low',
    false,
    'network',
    'OPEN',
    now(),
    now(),
    false,
    'report_only',
    'low',
    '{"server": "10.0.0.20"}'::jsonb,
    '{"server": null}'::jsonb
),
(
    'finding-ticket',
    'fingerprint-ticket',
    'edge04',
    'POL-TICKET',
    'ntp_servers',
    'device',
    'system',
    'high',
    true,
    'network',
    'OPEN',
    now(),
    now(),
    true,
    'approval_required',
    'medium',
    '{"servers": ["10.0.0.10"]}'::jsonb,
    '{"servers": []}'::jsonb
);
SQL

FIXTURE_RC=$?

echo "fixture_insert_rc=${FIXTURE_RC}"

if [[ "${FIXTURE_RC}" -ne 0 ]]; then
    fail "unable to seed lifecycle fixtures"
fi

echo "fixture_insert_gate=PASS"


# ==================================================================
# B01 — AUTO creates READY
# ==================================================================

behavior_expect \
"B01_auto_create" \
"READY|true|false" \
"
SET ROLE compliance_remediation;

WITH r AS (
    SELECT compliance.create_remediation_attempt(
        p_remediation_attempt_id =>
            'attempt-auto-main',

        p_finding_id =>
            'finding-auto-main',

        p_event_id =>
            'event-auto-main',

        p_compliance_run_id =>
            NULL,

        p_target_id =>
            'target-auto-main-001',

        p_device =>
            'leaf01',

        p_platform =>
            'frr',

        p_control =>
            'bgp_maximum_paths',

        p_remediation_policy =>
            'auto',

        p_attempt_number =>
            1,

        p_workflow_job_id =>
            1001,

        p_details =>
            '{\"case\":\"B01\"}'::jsonb
    ) AS j
)
SELECT
    (j->>'remediation_state')
    || '|'
    || (j->>'inserted')
    || '|'
    || (j->>'duplicate')
FROM r;
"


# ==================================================================
# B02 — exact replay is idempotent
# ==================================================================

behavior_expect \
"B02_attempt_replay" \
"READY|false|true" \
"
SET ROLE compliance_remediation;

WITH r AS (
    SELECT compliance.create_remediation_attempt(
        p_remediation_attempt_id =>
            'attempt-auto-main',
        p_finding_id =>
            'finding-auto-main',
        p_event_id =>
            'event-auto-main',
        p_compliance_run_id =>
            NULL,
        p_target_id =>
            'target-auto-main-001',
        p_device =>
            'leaf01',
        p_platform =>
            'frr',
        p_control =>
            'bgp_maximum_paths',
        p_remediation_policy =>
            'auto',
        p_attempt_number =>
            1,
        p_workflow_job_id =>
            1001,
        p_details =>
            '{\"case\":\"B01\"}'::jsonb
    ) AS j
)
SELECT
    (j->>'remediation_state')
    || '|'
    || (j->>'inserted')
    || '|'
    || (j->>'duplicate')
FROM r;
"


# ==================================================================
# B03 — same attempt ID cannot move to another target
# ==================================================================

behavior_expect_failure \
"B03_attempt_target_collision" \
"remediation attempt identity reuse with different content" \
"
SET ROLE compliance_remediation;

SELECT compliance.create_remediation_attempt(
    p_remediation_attempt_id =>
        'attempt-auto-main',
    p_finding_id =>
        'finding-auto-main',
    p_event_id =>
        'event-auto-main',
    p_compliance_run_id =>
        NULL,
    p_target_id =>
        'target-different-001',
    p_device =>
        'leaf01',
    p_platform =>
        'frr',
    p_control =>
        'bgp_maximum_paths',
    p_remediation_policy =>
        'auto',
    p_attempt_number =>
        1,
    p_workflow_job_id =>
        1001,
    p_details =>
        '{}'::jsonb
);
"


# ==================================================================
# B04 — approval finding cannot be upgraded to AUTO
# ==================================================================

behavior_expect_failure \
"B04_approval_to_auto_rejected" \
"remediation policy mismatch:" \
"
SET ROLE compliance_remediation;

SELECT compliance.create_remediation_attempt(
    'attempt-policy-bypass',
    'finding-approval-main',
    'event-policy-bypass',
    NULL,
    'target-approval-main-001',
    'edge01',
    'cisco_ios',
    'ntp_servers',
    'auto',
    1,
    1101,
    '{}'::jsonb
);
"


# ==================================================================
# B05 — approval-required finding must require ticket
# ==================================================================

behavior_expect_failure \
"B05_approval_without_ticket_rejected" \
"approval_required remediation requires" \
"
SET ROLE compliance_remediation;

SELECT compliance.create_remediation_attempt(
    'attempt-no-ticket',
    'finding-approval-no-ticket',
    'event-no-ticket',
    NULL,
    'target-approval-no-ticket-001',
    'edge03',
    'cisco_ios',
    'ntp_servers',
    'approval_required',
    1,
    1102,
    '{}'::jsonb
);
"


# ==================================================================
# B06 — approval attempt starts WAITING_FOR_APPROVAL
# ==================================================================

behavior_expect \
"B06_approval_create" \
"WAITING_FOR_APPROVAL|PENDING" \
"
SET ROLE compliance_remediation;

WITH r AS (
    SELECT compliance.create_remediation_attempt(
        'attempt-approval-main',
        'finding-approval-main',
        'event-approval-main',
        NULL,
        'target-approval-main-001',
        'edge01',
        'cisco_ios',
        'ntp_servers',
        'approval_required',
        1,
        1201,
        '{}'::jsonb
    ) AS j
)
SELECT
    (j->>'remediation_state')
    || '|'
    || (j->>'approval_state')
FROM r;
"


# ==================================================================
# B07 — approved request becomes READY
# ==================================================================

behavior_expect \
"B07_approval_granted" \
"READY|APPROVED|false" \
"
SET ROLE compliance_ticketing;

WITH r AS (
    SELECT compliance.record_remediation_approval(
        'attempt-approval-main',
        'APPROVED',
        'behavior-test-approver',
        '{}'::jsonb
    ) AS j
)
SELECT
    (j->>'remediation_state')
    || '|'
    || (j->>'approval_state')
    || '|'
    || (j->>'duplicate')
FROM r;
"


# ==================================================================
# B08 — rejection becomes BLOCKED
# ==================================================================

behavior_exec \
"B08_create_reject_fixture" \
"
SET ROLE compliance_remediation;

SELECT compliance.create_remediation_attempt(
    'attempt-approval-reject',
    'finding-approval-reject',
    'event-approval-reject',
    NULL,
    'target-approval-reject-001',
    'edge02',
    'cisco_ios',
    'ntp_servers',
    'approval_required',
    1,
    1202,
    '{}'::jsonb
);
"

behavior_expect \
"B08_approval_rejected" \
"BLOCKED|REJECTED|false" \
"
SET ROLE compliance_ticketing;

WITH r AS (
    SELECT compliance.record_remediation_approval(
        'attempt-approval-reject',
        'REJECTED',
        'behavior-test-approver',
        '{}'::jsonb
    ) AS j
)
SELECT
    (j->>'remediation_state')
    || '|'
    || (j->>'approval_state')
    || '|'
    || (j->>'duplicate')
FROM r;
"


# ==================================================================
# B09 — READY -> RUNNING
# ==================================================================

behavior_expect \
"B09_auto_running" \
"RUNNING" \
"
SET ROLE compliance_remediation;

WITH r AS (
    SELECT compliance.transition_remediation_attempt(
        p_remediation_attempt_id =>
            'attempt-auto-main',
        p_expected_state =>
            'READY',
        p_new_state =>
            'RUNNING',
        p_remediation_job_id =>
            2001
    ) AS j
)
SELECT (j->>'remediation_state')
FROM r;
"


# ==================================================================
# B10 — RUNNING -> SUCCEEDED does not resolve finding
# ==================================================================

behavior_exec \
"B10_transition_succeeded" \
"
SET ROLE compliance_remediation;

SELECT compliance.transition_remediation_attempt(
    p_remediation_attempt_id =>
        'attempt-auto-main',
    p_expected_state =>
        'RUNNING',
    p_new_state =>
        'SUCCEEDED',
    p_remediation_job_id =>
        2001
);
"

behavior_expect \
"B10_success_not_resolution" \
"SUCCEEDED|REMEDIATING" \
"
SELECT
    r.remediation_state
    || '|'
    || f.status
FROM compliance.remediation_attempts r
JOIN compliance.compliance_findings f
  ON f.finding_id = r.finding_id
WHERE r.remediation_attempt_id =
      'attempt-auto-main';
"


# ==================================================================
# B11 — COMPLETED requires targeted recheck ID
# ==================================================================

behavior_expect_failure \
"B11_completion_without_recheck_rejected" \
"recheck_job_id is required" \
"
SET ROLE compliance_remediation;

SELECT compliance.transition_remediation_attempt(
    p_remediation_attempt_id =>
        'attempt-auto-main',
    p_expected_state =>
        'SUCCEEDED',
    p_new_state =>
        'COMPLETED'
);
"


# ==================================================================
# B12 — recheck-correlated completion succeeds
# ==================================================================

behavior_exec \
"B12_complete_with_recheck" \
"
SET ROLE compliance_remediation;

SELECT compliance.transition_remediation_attempt(
    p_remediation_attempt_id =>
        'attempt-auto-main',
    p_expected_state =>
        'SUCCEEDED',
    p_new_state =>
        'COMPLETED',
    p_recheck_job_id =>
        3001
);
"

behavior_expect \
"B12_completed_with_recheck" \
"COMPLETED|3001|REMEDIATING" \
"
SELECT
    r.remediation_state
    || '|'
    || r.recheck_job_id::text
    || '|'
    || f.status
FROM compliance.remediation_attempts r
JOIN compliance.compliance_findings f
  ON f.finding_id = r.finding_id
WHERE r.remediation_attempt_id =
      'attempt-auto-main';
"


# ==================================================================
# B13 — remediation failure returns finding OPEN
# ==================================================================

behavior_exec \
"B13_create" \
"
SET ROLE compliance_remediation;

SELECT compliance.create_remediation_attempt(
    'attempt-auto-failure',
    'finding-auto-failure',
    'event-auto-failure',
    NULL,
    'target-auto-failure-001',
    'leaf03',
    'frr',
    'bgp_maximum_paths',
    'auto',
    1,
    1301,
    '{}'::jsonb
);

SELECT compliance.transition_remediation_attempt(
    'attempt-auto-failure',
    'READY',
    'RUNNING',
    NULL,
    2101
);

SELECT compliance.transition_remediation_attempt(
    p_remediation_attempt_id =>
        'attempt-auto-failure',
    p_expected_state =>
        'RUNNING',
    p_new_state =>
        'FAILED',
    p_remediation_job_id =>
        2101,
    p_failure_class =>
        'TRANSIENT',
    p_failure_message =>
        'synthetic transient failure'
);
"

behavior_expect \
"B13_failed_remediation" \
"FAILED|TRANSIENT|OPEN" \
"
SELECT
    r.remediation_state
    || '|'
    || r.failure_class
    || '|'
    || f.status
FROM compliance.remediation_attempts r
JOIN compliance.compliance_findings f
  ON f.finding_id = r.finding_id
WHERE r.remediation_attempt_id =
      'attempt-auto-failure';
"


# ==================================================================
# B14 — targeted recheck failure returns finding OPEN
# ==================================================================

behavior_exec \
"B14_create" \
"
SET ROLE compliance_remediation;

SELECT compliance.create_remediation_attempt(
    'attempt-recheck-failure',
    'finding-recheck-failure',
    'event-recheck-failure',
    NULL,
    'target-recheck-failure-001',
    'leaf04',
    'frr',
    'bgp_maximum_paths',
    'auto',
    1,
    1401,
    '{}'::jsonb
);

SELECT compliance.transition_remediation_attempt(
    'attempt-recheck-failure',
    'READY',
    'RUNNING',
    NULL,
    2201
);

SELECT compliance.transition_remediation_attempt(
    'attempt-recheck-failure',
    'RUNNING',
    'SUCCEEDED',
    NULL,
    2201
);

SELECT compliance.transition_remediation_attempt(
    p_remediation_attempt_id =>
        'attempt-recheck-failure',
    p_expected_state =>
        'SUCCEEDED',
    p_new_state =>
        'RECHECK_FAILED',
    p_recheck_job_id =>
        3201,
    p_failure_class =>
        'UNKNOWN',
    p_failure_message =>
        'synthetic recheck failure'
);
"

behavior_expect \
"B14_recheck_failed" \
"RECHECK_FAILED|3201|OPEN" \
"
SELECT
    r.remediation_state
    || '|'
    || r.recheck_job_id::text
    || '|'
    || f.status
FROM compliance.remediation_attempts r
JOIN compliance.compliance_findings f
  ON f.finding_id = r.finding_id
WHERE r.remediation_attempt_id =
      'attempt-recheck-failure';
"


# ==================================================================
# B15 — illegal READY -> SUCCEEDED transition rejected
# ==================================================================

behavior_exec \
"B15_create" \
"
SET ROLE compliance_remediation;

SELECT compliance.create_remediation_attempt(
    'attempt-illegal',
    'finding-illegal-transition',
    'event-illegal',
    NULL,
    'target-illegal-001',
    'leaf05',
    'frr',
    'bgp_maximum_paths',
    'auto',
    1,
    1501,
    '{}'::jsonb
);
"

behavior_expect_failure \
"B15_illegal_transition_rejected" \
"invalid remediation transition:" \
"
SET ROLE compliance_remediation;

SELECT compliance.transition_remediation_attempt(
    'attempt-illegal',
    'READY',
    'SUCCEEDED'
);
"


# ==================================================================
# B16 — blocked is accepted as safe privilege downgrade
# ==================================================================

behavior_expect \
"B16_blocked_safe_override" \
"BLOCKED|NOT_REQUIRED" \
"
SET ROLE compliance_remediation;

WITH r AS (
    SELECT compliance.create_remediation_attempt(
        'attempt-blocked',
        'finding-blocked',
        'event-blocked',
        NULL,
        'target-blocked-001',
        'leaf06',
        'frr',
        'bgp_maximum_paths',
        'blocked',
        1,
        1601,
        '{}'::jsonb
    ) AS j
)
SELECT
    (j->>'remediation_state')
    || '|'
    || (j->>'approval_state')
FROM r;
"


# ==================================================================
# B17 — report_only may map to observe_only, never executable
# ==================================================================

behavior_expect \
"B17_report_only_observe" \
"BLOCKED|observe_only" \
"
SET ROLE compliance_remediation;

WITH r AS (
    SELECT compliance.create_remediation_attempt(
        'attempt-report-only',
        'finding-report-only',
        'event-report-only',
        NULL,
        'target-report-only-001',
        'leaf07',
        'frr',
        'logging_server',
        'observe_only',
        1,
        1701,
        '{}'::jsonb
    ) AS j
)
SELECT
    (j->>'remediation_state')
    || '|'
    || (j->>'remediation_policy')
FROM r;
"


# ==================================================================
# B18 — first operational ticket created
# ==================================================================

behavior_expect \
"B18_ticket_create" \
"ticket-record-001|true|false|APPROVAL_PENDING" \
"
SET ROLE compliance_ticketing;

WITH r AS (
    SELECT compliance.upsert_ticket_record(
        p_ticket_record_id =>
            'ticket-record-001',
        p_finding_id =>
            'finding-ticket',
        p_provider =>
            'servicenow',
        p_ticket_type =>
            'CHANGE',
        p_external_ticket_id =>
            'external-ticket-001',
        p_external_ticket_number =>
            'CHG000001',
        p_ticket_state =>
            'APPROVAL_PENDING',
        p_approval_state =>
            'PENDING',
        p_remediation_allowed =>
            false,
        p_details =>
            '{}'::jsonb
    ) AS j
)
SELECT
    (j->>'ticket_record_id')
    || '|'
    || (j->>'inserted')
    || '|'
    || (j->>'duplicate')
    || '|'
    || (j->>'ticket_state')
FROM r;
"


# ==================================================================
# B19 — exact ticket replay does not duplicate
# ==================================================================

behavior_expect \
"B19_ticket_replay" \
"ticket-record-001|false|true" \
"
SET ROLE compliance_ticketing;

WITH r AS (
    SELECT compliance.upsert_ticket_record(
        'ticket-record-001',
        'finding-ticket',
        'servicenow',
        'CHANGE',
        'external-ticket-001',
        'CHG000001',
        'APPROVAL_PENDING',
        'PENDING',
        false,
        '{}'::jsonb
    ) AS j
)
SELECT
    (j->>'ticket_record_id')
    || '|'
    || (j->>'inserted')
    || '|'
    || (j->>'duplicate')
FROM r;
"


# ==================================================================
# B20 — different proposed record ID still dedups active ticket
# ==================================================================

behavior_expect \
"B20_active_ticket_dedup" \
"ticket-record-001|false|true" \
"
SET ROLE compliance_ticketing;

WITH r AS (
    SELECT compliance.upsert_ticket_record(
        'ticket-record-002',
        'finding-ticket',
        'servicenow',
        'CHANGE',
        'external-ticket-001',
        'CHG000001',
        'APPROVAL_PENDING',
        'PENDING',
        false,
        '{}'::jsonb
    ) AS j
)
SELECT
    (j->>'ticket_record_id')
    || '|'
    || (j->>'inserted')
    || '|'
    || (j->>'duplicate')
FROM r;
"


# ------------------------------------------------------------------
# Administrative verification for B18-B20.
#
# This intentionally runs outside SET ROLE compliance_ticketing.
# Application capability roles remain unable to SELECT the table.
# ------------------------------------------------------------------

echo
echo "===== VERIFY ACTIVE TICKET DEDUP ====="

TICKET_DEDUP_STATE="$(
    behavior_scalar "
SELECT
    count(*)::text
    || '|'
    || count(*) FILTER (
        WHERE ticket_state NOT IN (
            'RESOLVED',
            'CLOSED'
        )
    )::text
FROM compliance.ticket_records
WHERE finding_id = 'finding-ticket'
  AND provider = 'servicenow'
  AND ticket_type = 'CHANGE';
"
)"

TICKET_DEDUP_RC=$?

echo "ticket_dedup_verify_rc=${TICKET_DEDUP_RC}"
echo "ticket_dedup_state=${TICKET_DEDUP_STATE}"
echo "ticket_dedup_expected=1|1"

if [[ \
    "${TICKET_DEDUP_RC}" -eq 0 \
    && "${TICKET_DEDUP_STATE}" == "1|1" \
]]; then
    echo "active_ticket_dedup_gate=PASS"
else
    fail "active ticket dedup verification failed"
fi


# ==================================================================
# B21 — ticket approval state persists
# ==================================================================

behavior_expect \
"B21_ticket_approved" \
"APPROVED|APPROVED|true" \
"
SET ROLE compliance_ticketing;

WITH r AS (
    SELECT compliance.update_ticket_record(
        p_ticket_record_id =>
            'ticket-record-001',
        p_expected_state =>
            'APPROVAL_PENDING',
        p_new_state =>
            'APPROVED',
        p_approval_state =>
            'APPROVED',
        p_remediation_allowed =>
            true,
        p_details =>
            '{}'::jsonb
    ) AS j
)
SELECT
    (j->>'ticket_state')
    || '|'
    || (j->>'approval_state')
    || '|'
    || (j->>'remediation_allowed')
FROM r;
"


# ==================================================================
# B22 — remediation capability cannot self-approve
# ==================================================================

behavior_expect_failure \
"B22_remediation_cannot_approve" \
"permission denied for function record_remediation_approval" \
"
SET ROLE compliance_remediation;

SELECT compliance.record_remediation_approval(
    'attempt-approval-main',
    'APPROVED',
    'forbidden-remediation-role',
    '{}'::jsonb
);
"


# ==================================================================
# B23 — ticket capability cannot transition remediation
# ==================================================================

behavior_expect_failure \
"B23_ticketing_cannot_remediate" \
"permission denied for function transition_remediation_attempt" \
"
SET ROLE compliance_ticketing;

SELECT compliance.transition_remediation_attempt(
    'attempt-auto-main',
    'COMPLETED',
    'RUNNING'
);
"


# ==================================================================
# B24 — application capability role has no direct table DML
# ==================================================================

behavior_expect_failure \
"B24_direct_dml_denied" \
"permission denied for table remediation_attempts" \
"
SET ROLE compliance_remediation;

UPDATE compliance.remediation_attempts
SET details = details
WHERE remediation_attempt_id =
      'attempt-auto-main';
"


# ==================================================================
# B25 — COMPLETED attempt still does not resolve durable finding
# ==================================================================

behavior_expect \
"B25_finding_not_resolved_by_awx_success" \
"COMPLETED|REMEDIATING|" \
"
SELECT
    r.remediation_state
    || '|'
    || f.status
    || '|'
    || COALESCE(
        f.resolved_at::text,
        ''
    )
FROM compliance.remediation_attempts r
JOIN compliance.compliance_findings f
  ON f.finding_id = r.finding_id
WHERE r.remediation_attempt_id =
      'attempt-auto-main';
"


echo
echo "behavior_pass_count=${BEHAVIOR_PASS_COUNT}"

if [[ "${BEHAVIOR_PASS_COUNT}" -ne 25 ]]; then
    fail "expected 25 behavioral acceptance cases"
fi

echo "phase7d_behavior_case_count_gate=PASS"
echo "phase7d_behavior_matrix_gate=PASS"



echo
echo "========================================"
echo "V3 LIFECYCLE BEHAVIOR TEST: PASS"
echo "========================================"

exit 0
