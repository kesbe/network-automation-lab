#!/usr/bin/env bash

set -uo pipefail

CONTAINER="${POSTGRES_V3_READER_CONTAINER:-compliance-postgres-v3-reader-ci}"
DB="${POSTGRES_V3_READER_DB:-compliance_v3_activation_reader_test}"
PGUSER="postgres"

ROOT_DIR="$(
    cd "$(dirname "${BASH_SOURCE[0]}")/../.." &&
    pwd
)"

MIGRATIONS="${ROOT_DIR}/db/migrations"

IMAGE="docker.io/library/postgres@sha256:42b8b8b29c8a4e933d88943e5b03001a78794905cf786e6e7634e9f2abd5a0d3"


fail() {
    echo
    echo "V3_ACTIVATION_SOURCE_READER_TEST=HOLD"
    echo "reason=$1"
    exit 1
}


cleanup() {
    docker rm \
        -f \
        "${CONTAINER}" \
        >/dev/null 2>&1 ||
        true
}

trap cleanup EXIT


echo
echo "===== V3 ACTIVATION SOURCE READER BEHAVIOR TEST ====="

cleanup


docker run \
    -d \
    --name "${CONTAINER}" \
    -e POSTGRES_HOST_AUTH_METHOD=trust \
    "${IMAGE}" \
    >/dev/null

RC=$?

if [[ "${RC}" -ne 0 ]]; then
    fail "unable to start disposable PostgreSQL"
fi


READY=false

for _ in $(seq 1 60)
do
    if docker exec \
        "${CONTAINER}" \
        pg_isready \
            -U "${PGUSER}" \
        >/dev/null 2>&1
    then
        READY=true
        break
    fi

    sleep 1
done

if [[ "${READY}" != true ]]; then
    fail "disposable PostgreSQL did not become ready"
fi

echo "postgres_ready=PASS"


docker exec \
    "${CONTAINER}" \
    psql \
        -U postgres \
        -v ON_ERROR_STOP=1 \
        -c "
CREATE ROLE netauto_admin
    LOGIN
    SUPERUSER;

CREATE ROLE compliance_writer
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;
" \
    >/dev/null

RC=$?

if [[ "${RC}" -ne 0 ]]; then
    fail "unable to create test prerequisite roles"
fi

echo "test_roles=PASS"


docker exec \
    "${CONTAINER}" \
    createdb \
        -U postgres \
        -O netauto_admin \
        "${DB}"

RC=$?

if [[ "${RC}" -ne 0 ]]; then
    fail "unable to create disposable database"
fi

echo "database_created=PASS"


MIGRATION_FILES=(
    001_compliance_schema.sql
    002_finding_ingestion.sql
    003_compliance_run_ingestion.sql
    004_ingestion_security.sql
    005_absence_based_resolution.sql
    006_transport_event_idempotency.sql
    007_stale_reconciliation_security.sql
    008_remediation_ticket_lifecycle.sql
    009_compliance_exporter_read_model.sql
    010_v3_transport_event_identity.sql
    011_v3_activation_source_durability.sql
    012_v3_transactional_run_ingestion.sql
    013_v3_activation_source_reader.sql
)

APPLIED=0

for NAME in "${MIGRATION_FILES[@]}"
do
    FILE="${MIGRATIONS}/${NAME}"

    if [[ ! -f "${FILE}" ]]; then
        fail "missing migration ${NAME}"
    fi

    docker exec \
        -i \
        "${CONTAINER}" \
        psql \
            -U netauto_admin \
            -d "${DB}" \
            -v ON_ERROR_STOP=1 \
        < "${FILE}" \
        >/tmp/v3-reader-migration.out \
        2>&1

    RC=$?

    if [[ "${RC}" -ne 0 ]]; then
        cat /tmp/v3-reader-migration.out
        fail "migration failed: ${NAME}"
    fi

    APPLIED=$((APPLIED + 1))

    echo "migration_gate=PASS|${NAME}"

    if [[ "${NAME}" == "004_ingestion_security.sql" ]]; then
        docker exec \
            "${CONTAINER}" \
            psql \
                -U netauto_admin \
                -d "${DB}" \
                -v ON_ERROR_STOP=1 \
                -c "
GRANT compliance_ingest
TO compliance_writer;
" \
            >/dev/null

        RC=$?

        if [[ "${RC}" -ne 0 ]]; then
            fail "unable to bind compliance_writer to compliance_ingest"
        fi
    fi
done

if [[ "${APPLIED}" -ne 13 ]]; then
    fail "unexpected migration count"
fi

echo "migration_chain_001_013=PASS"


echo
echo "===== VERIFY CONSTRAINT AND SECURITY ====="

CATALOG="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -U netauto_admin \
            -d "${DB}" \
            -At \
            -F '|' \
            -c "
SELECT
    (
        SELECT count(*)
        FROM pg_constraint AS c
        JOIN pg_namespace AS n
          ON n.oid = c.connamespace
        WHERE n.nspname = 'compliance'
          AND c.conname =
              'v3_activation_sources_run_finding_unique'
          AND c.contype = 'u'
    ),
    has_function_privilege(
        'public',
        'compliance.read_v3_activation_source(text,text)',
        'EXECUTE'
    ),
    has_function_privilege(
        'compliance_ingest',
        'compliance.read_v3_activation_source(text,text)',
        'EXECUTE'
    ),
    has_function_privilege(
        'compliance_writer',
        'compliance.read_v3_activation_source(text,text)',
        'EXECUTE'
    ),
    has_table_privilege(
        'compliance_ingest',
        'compliance.v3_activation_sources',
        'SELECT'
    ),
    has_table_privilege(
        'compliance_writer',
        'compliance.v3_activation_sources',
        'SELECT'
    );
"
)"

echo "catalog=${CATALOG}"

if [[ "${CATALOG}" != "1|f|t|t|f|f" ]]; then
    fail "reader security or unique constraint is incorrect"
fi

echo "reader_catalog_security=PASS"


SECURITY_DEF="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -U netauto_admin \
            -d "${DB}" \
            -At \
            -F '|' \
            -c "
SELECT
    pg_get_userbyid(p.proowner),
    p.prosecdef,
    COALESCE(
        array_to_string(p.proconfig, ','),
        ''
    )
FROM pg_proc AS p
JOIN pg_namespace AS n
  ON n.oid = p.pronamespace
WHERE n.nspname = 'compliance'
  AND p.proname = 'read_v3_activation_source'
  AND pg_get_function_identity_arguments(p.oid)
      = 'p_run_id text, p_finding_id text';
"
)"

echo "reader_security=${SECURITY_DEF}"

if [[ "${SECURITY_DEF}" != \
      "compliance_api_owner|t|search_path=pg_catalog, compliance" ]]
then
    fail "reader SECURITY DEFINER boundary is incorrect"
fi

echo "reader_security_definer=PASS"


echo
echo "===== SEED VALID ACTIVATION SOURCE ====="

docker exec \
    -i \
    "${CONTAINER}" \
    psql \
        -U netauto_admin \
        -d "${DB}" \
        -v ON_ERROR_STOP=1 \
        >/dev/null <<'SQL'
INSERT INTO compliance.compliance_runs (
    run_id,
    schema_version,
    generated_at,
    source,
    workflow_job_id,
    compliance_job_id,
    aggregator_job_id,
    devices_checked,
    devices_compliant,
    devices_noncompliant,
    total_findings,
    critical_findings,
    high_findings,
    medium_findings,
    low_findings,
    info_findings,
    raw_result
)
VALUES (
    'reader-run-001',
    '1.0',
    '2026-01-01 10:00:00+00',
    'test',
    1001,
    1002,
    1003,
    1,
    0,
    1,
    1,
    0,
    1,
    0,
    0,
    0,
    '{}'::jsonb
);


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
    resolved_at,
    remediation_supported,
    remediation_mode,
    remediation_risk,
    expected,
    current_actual,
    created_at,
    updated_at
)
VALUES (
    'finding-reader-001',
    'leaf01|reader|maxpaths',
    'leaf01',
    'READER-001',
    'maximum_paths',
    'device',
    'routing',
    'high',
    false,
    'network',
    'OPEN',
    '2026-01-01 10:00:00+00',
    '2026-01-01 10:00:00+00',
    NULL,
    true,
    'auto',
    'low',
    '{"value":2}'::jsonb,
    '{"value":1}'::jsonb,
    '2026-01-01 10:00:00+00',
    '2026-01-01 10:00:00+00'
);


WITH lifecycle AS (
    INSERT INTO compliance.finding_events (
        finding_id,
        run_id,
        event_type,
        event_time,
        old_status,
        new_status,
        actor,
        details
    )
    VALUES (
        'finding-reader-001',
        'reader-run-001',
        'DETECTED',
        '2026-01-01 10:00:00+00',
        NULL,
        'OPEN',
        'test',
        '{}'::jsonb
    )
    RETURNING
        event_id,
        run_id,
        finding_id,
        event_type,
        event_time
)
INSERT INTO compliance.v3_activation_sources (
    finding_event_id,
    run_id,
    finding_id,
    lifecycle_event_type,
    activated_at,
    finding_snapshot,
    resolved_target
)
SELECT
    event_id,
    run_id,
    finding_id,
    event_type,
    event_time,
    '{
      "finding_id": "finding-reader-001",
      "device": "leaf01",
      "vendor": "frr",
      "platform": "frr",
      "control": "maximum_paths",
      "severity": "high",
      "status": "NON_COMPLIANT",
      "remediable": true,
      "remediation_policy": "auto",
      "ticket_required": false,
      "expected": 2
    }'::jsonb,
    '{
      "target_id": "target-reader-001",
      "selector": {
        "mode": "devices",
        "devices": ["leaf01"]
      },
      "devices": [
        {
          "name": "leaf01",
          "vendor": "frr",
          "platform": "frr"
        }
      ],
      "device_count": 1
    }'::jsonb
FROM lifecycle;
SQL

RC=$?

if [[ "${RC}" -ne 0 ]]; then
    fail "unable to seed valid activation source"
fi

echo "valid_activation_seed=PASS"


echo
echo "===== READER SUCCESS THROUGH RUNTIME ROLE ====="

RESULT="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -q \
            -U netauto_admin \
            -d "${DB}" \
            -v ON_ERROR_STOP=1 \
            -At \
            -F '|' \
            -c "
SET ROLE compliance_writer;

SELECT
    finding_event_id > 0,
    run_id,
    finding_id,
    lifecycle_event_type,
    activated_at =
        '2026-01-01 10:00:00+00'::timestamptz,
    finding_snapshot->>'expected',
    resolved_target->>'target_id'
FROM compliance.read_v3_activation_source(
    'reader-run-001',
    'finding-reader-001'
);
"
)"

echo "reader_result=${RESULT}"

if [[ "${RESULT}" != \
      "t|reader-run-001|finding-reader-001|DETECTED|t|2|target-reader-001" ]]
then
    fail "runtime reader returned unexpected source"
fi

echo "runtime_reader_success=PASS"


SNAPSHOT_MATCH="$(
    docker exec \
        "${CONTAINER}" \
        psql \
            -q \
            -U netauto_admin \
            -d "${DB}" \
            -At \
            -c "
SET ROLE compliance_writer;

SELECT
    finding_snapshot =
    '{
      \"finding_id\": \"finding-reader-001\",
      \"device\": \"leaf01\",
      \"vendor\": \"frr\",
      \"platform\": \"frr\",
      \"control\": \"maximum_paths\",
      \"severity\": \"high\",
      \"status\": \"NON_COMPLIANT\",
      \"remediable\": true,
      \"remediation_policy\": \"auto\",
      \"ticket_required\": false,
      \"expected\": 2
    }'::jsonb
    AND
    resolved_target =
    '{
      \"target_id\": \"target-reader-001\",
      \"selector\": {
        \"mode\": \"devices\",
        \"devices\": [\"leaf01\"]
      },
      \"devices\": [
        {
          \"name\": \"leaf01\",
          \"vendor\": \"frr\",
          \"platform\": \"frr\"
        }
      ],
      \"device_count\": 1
    }'::jsonb
FROM compliance.read_v3_activation_source(
    'reader-run-001',
    'finding-reader-001'
);
"
)"

if [[ "${SNAPSHOT_MATCH}" != "t" ]]; then
    fail "reader altered immutable snapshots"
fi

echo "snapshot_round_trip=PASS"


expect_reader_failure() {
    LABEL="$1"
    RUN_ID="$2"
    FINDING_ID="$3"
    EXPECTED_TEXT="$4"

    OUTPUT="$(
        docker exec \
            "${CONTAINER}" \
            psql \
                -q \
                -U netauto_admin \
                -d "${DB}" \
                -v ON_ERROR_STOP=1 \
                -c "
SET ROLE compliance_writer;

SELECT *
FROM compliance.read_v3_activation_source(
    '${RUN_ID}',
    '${FINDING_ID}'
);
" 2>&1
    )"

    RC=$?

    if [[ "${RC}" -eq 0 ]]; then
        fail "${LABEL} unexpectedly succeeded"
    fi

    if [[ "${OUTPUT}" != *"${EXPECTED_TEXT}"* ]]; then
        echo "${OUTPUT}"
        fail "${LABEL} failed for unexpected reason"
    fi

    echo "${LABEL}=PASS"
}


expect_reader_failure \
    "empty_run_id" \
    "" \
    "finding-reader-001" \
    "run_id must not be empty"

expect_reader_failure \
    "empty_finding_id" \
    "reader-run-001" \
    "" \
    "finding_id must not be empty"

expect_reader_failure \
    "unknown_source" \
    "reader-run-missing" \
    "finding-reader-001" \
    "V3 activation source not found"


echo
echo "===== DIRECT TABLE READ DENIAL ====="

for ROLE in compliance_ingest compliance_writer
do
    OUTPUT="$(
        docker exec \
            "${CONTAINER}" \
            psql \
                -q \
                -U netauto_admin \
                -d "${DB}" \
                -v ON_ERROR_STOP=1 \
                -c "
SET ROLE ${ROLE};

SELECT count(*)
FROM compliance.v3_activation_sources;
" 2>&1
    )"

    RC=$?

    if [[ "${RC}" -eq 0 ]]; then
        fail "${ROLE} unexpectedly has direct table SELECT"
    fi

    if [[ "${OUTPUT}" != *"permission denied"* ]]; then
        echo "${OUTPUT}"
        fail "${ROLE} direct SELECT failed for unexpected reason"
    fi

    echo "direct_select_denied=${ROLE}|PASS"
done


echo
echo "===== UNIQUE RUN/FINDING ENFORCEMENT ====="

DUPLICATE_OUTPUT="$(
    docker exec \
        -i \
        "${CONTAINER}" \
        psql \
            -U netauto_admin \
            -d "${DB}" \
            -v ON_ERROR_STOP=1 \
            2>&1 <<'SQL'
WITH lifecycle AS (
    INSERT INTO compliance.finding_events (
        finding_id,
        run_id,
        event_type,
        event_time,
        old_status,
        new_status,
        actor,
        details
    )
    VALUES (
        'finding-reader-001',
        'reader-run-001',
        'REOPENED',
        '2026-01-01 10:01:00+00',
        'RESOLVED',
        'OPEN',
        'test',
        '{}'::jsonb
    )
    RETURNING
        event_id,
        run_id,
        finding_id,
        event_type,
        event_time
)
INSERT INTO compliance.v3_activation_sources (
    finding_event_id,
    run_id,
    finding_id,
    lifecycle_event_type,
    activated_at,
    finding_snapshot,
    resolved_target
)
SELECT
    event_id,
    run_id,
    finding_id,
    event_type,
    event_time,
    '{
      "finding_id": "finding-reader-001",
      "device": "leaf01",
      "vendor": "frr",
      "platform": "frr",
      "control": "maximum_paths",
      "severity": "high",
      "status": "NON_COMPLIANT",
      "remediable": true,
      "remediation_policy": "auto",
      "ticket_required": false,
      "expected": 2
    }'::jsonb,
    '{
      "target_id": "target-reader-001",
      "selector": {},
      "devices": [
        {
          "name": "leaf01",
          "vendor": "frr",
          "platform": "frr"
        }
      ],
      "device_count": 1
    }'::jsonb
FROM lifecycle;
SQL
)"

RC=$?

if [[ "${RC}" -eq 0 ]]; then
    fail "duplicate run/finding activation unexpectedly succeeded"
fi

if [[ "${DUPLICATE_OUTPUT}" != \
      *"v3_activation_sources_run_finding_unique"* ]]
then
    echo "${DUPLICATE_OUTPUT}"
    fail "duplicate activation failed for unexpected reason"
fi

echo "unique_run_finding_enforced=PASS"


echo
echo "V3_ACTIVATION_SOURCE_READER_TEST=PASS"
