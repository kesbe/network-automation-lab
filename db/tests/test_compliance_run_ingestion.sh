#!/usr/bin/env bash

set -euo pipefail

CONTAINER="${POSTGRES_TEST_CONTAINER:-compliance-postgres-test}"
DB="${POSTGRES_TEST_DB:-compliance_ci_run_test}"
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


sql() {
    docker exec \
      "${CONTAINER}" \
      psql \
        -v ON_ERROR_STOP=1 \
        -U "${PGUSER}" \
        -d "${DB}" \
        -At \
        -F '|' \
        -c "$1"
}


assert_eq() {
    local actual="$1"
    local expected="$2"
    local label="$3"

    if [[ "${actual}" != "${expected}" ]]; then
        echo "FAIL: ${label}"
        echo "expected: ${expected}"
        echo "actual:   ${actual}"
        return 1
    fi

    echo "PASS: ${label}"
}


echo "===== RESET DATABASE ====="

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
      < "${migration}" \
      >/dev/null
done


echo
echo "===== FIRST WHOLE-RUN INGEST ====="

RESULT="$(
sql "
SELECT
    result_status,
    run_inserted,
    device_results_inserted,
    findings_processed,
    detected_count,
    seen_again_count,
    reopened_count,
    duplicate_finding_count
FROM compliance.ingest_compliance_run(
    p_compliance_run =>
        \$json\$
{
  \"schema_version\": \"1.0\",
  \"run_id\": \"compliance-ci-run-001\",
  \"generated_at\": \"2026-08-20T10:22:19Z\",

  \"summary\": {
    \"devices_checked\": 4,
    \"devices_compliant\": 3,
    \"devices_noncompliant\": 1,
    \"total_findings\": 1,
    \"critical_findings\": 0,
    \"high_findings\": 1,
    \"medium_findings\": 0,
    \"low_findings\": 0,
    \"info_findings\": 0
  },

  \"device_results\": [
    {
      \"device\": \"leaf01\",
      \"status\": \"NON-COMPLIANT\",
      \"total_checks\": \"11\",
      \"passed\": \"10\",
      \"failed\": \"1\",
      \"violations\": [
        {
          \"policy_id\": \"NET-BGP-002\",
          \"control\": \"maximum_paths\"
        }
      ]
    },
    {
      \"device\": \"leaf02\",
      \"status\": \"COMPLIANT\",
      \"total_checks\": \"11\",
      \"passed\": \"11\",
      \"failed\": \"0\",
      \"violations\": []
    },
    {
      \"device\": \"spine01\",
      \"status\": \"COMPLIANT\",
      \"total_checks\": \"10\",
      \"passed\": \"10\",
      \"failed\": \"0\",
      \"violations\": []
    },
    {
      \"device\": \"spine02\",
      \"status\": \"COMPLIANT\",
      \"total_checks\": \"10\",
      \"passed\": \"10\",
      \"failed\": \"0\",
      \"violations\": []
    }
  ],

  \"findings\": [
    {
      \"finding_id\": \"finding-ci-001\",
      \"finding_fingerprint\": \"leaf01|NET-BGP-002|device\",
      \"finding_scope\": \"device\",

      \"device\": \"leaf01\",
      \"device_status\": \"NON-COMPLIANT\",

      \"policy_id\": \"NET-BGP-002\",
      \"policy_name\": \"BGP ECMP maximum paths\",

      \"control\": \"maximum_paths\",
      \"category\": \"routing\",
      \"severity\": \"high\",

      \"ticket_required\": false,
      \"owner\": \"network_operations\",

      \"expected\": 2,
      \"actual\": \"missing or different\",

      \"remediation\": {
        \"supported\": true,
        \"mode\": \"auto\",
        \"risk\": \"low\"
      }
    }
  ],

  \"critical_findings\": []
}
\$json\$::jsonb,

    p_workflow_job_id =>
        1001,

    p_compliance_job_id =>
        1002,

    p_aggregator_job_id =>
        1003,

    p_source =>
        'awx',

    p_actor =>
        'automation'
);
"
)"

assert_eq \
  "${RESULT}" \
  "INSERTED|t|4|1|1|0|0|0" \
  "new JT38 run is persisted atomically"


echo
echo "===== VERIFY RELATIONAL STATE ====="

RUN_STATE="$(
sql "
SELECT
    devices_checked,
    devices_compliant,
    devices_noncompliant,
    total_findings,
    high_findings,
    workflow_job_id,
    compliance_job_id,
    aggregator_job_id
FROM compliance.compliance_runs
WHERE run_id =
    'compliance-ci-run-001';
"
)"

assert_eq \
  "${RUN_STATE}" \
  "4|3|1|1|1|1001|1002|1003" \
  "run summary and AWX identities persisted"


DEVICE_STATE="$(
sql "
SELECT
    device,
    status,
    total_checks,
    passed_checks,
    failed_checks,
    violations_count
FROM compliance.compliance_run_devices
WHERE run_id =
    'compliance-ci-run-001'
  AND device =
    'leaf01';
"
)"

assert_eq \
  "${DEVICE_STATE}" \
  "leaf01|NON-COMPLIANT|11|10|1|1" \
  "JT38 string counters cast to integers"


FINDING_STATE="$(
sql "
SELECT
    finding_id,
    finding_fingerprint,
    status,
    severity,
    ticket_required,
    remediation_mode,
    remediation_risk
FROM compliance.compliance_findings;
"
)"

assert_eq \
  "${FINDING_STATE}" \
  "finding-ci-001|leaf01|NET-BGP-002|device|OPEN|high|f|auto|low" \
  "canonical finding persisted"


COUNTS_BEFORE="$(
sql "
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

assert_eq \
  "${COUNTS_BEFORE}" \
  "1|4|1|1|1" \
  "initial child-table counts correct"


echo
echo "===== EXACT WHOLE-RUN RETRY ====="

RESULT="$(
sql "
SELECT
    result_status,
    run_inserted,
    device_results_inserted,
    findings_processed,
    detected_count,
    seen_again_count,
    reopened_count,
    duplicate_finding_count
FROM compliance.ingest_compliance_run(
    p_compliance_run =>
        (
            SELECT raw_result
            FROM compliance.compliance_runs
            WHERE run_id =
                'compliance-ci-run-001'
        ),

    p_workflow_job_id =>
        1001,

    p_compliance_job_id =>
        1002,

    p_aggregator_job_id =>
        1003,

    p_source =>
        'awx',

    p_actor =>
        'automation'
);
"
)"

assert_eq \
  "${RESULT}" \
  "DUPLICATE|f|0|0|0|0|0|0" \
  "exact whole-run retry is idempotent"


COUNTS_AFTER_RETRY="$(
sql "
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

assert_eq \
  "${COUNTS_AFTER_RETRY}" \
  "${COUNTS_BEFORE}" \
  "whole-run retry produces zero additional writes"


echo
echo "===== RUN-ID COLLISION ====="

COLLISION_OUTPUT="$(
    mktemp
)"

if docker exec \
    "${CONTAINER}" \
    psql \
      -v ON_ERROR_STOP=1 \
      -U "${PGUSER}" \
      -d "${DB}" \
      -At \
      -c "
SELECT *
FROM compliance.ingest_compliance_run(
    p_compliance_run =>
        (
            SELECT
                raw_result
                ||
                jsonb_build_object(
                    'collision_test',
                    true
                )
            FROM compliance.compliance_runs
            WHERE run_id =
                'compliance-ci-run-001'
        ),

    p_workflow_job_id =>
        1001,

    p_compliance_job_id =>
        1002,

    p_aggregator_job_id =>
        1003,

    p_source =>
        'awx',

    p_actor =>
        'automation'
);
" >"${COLLISION_OUTPUT}" 2>&1
then
    echo "FAIL: modified payload with same run_id was accepted"
    cat "${COLLISION_OUTPUT}"
    rm -f "${COLLISION_OUTPUT}"
    false
else
    if grep -q \
        'Compliance run identity collision' \
        "${COLLISION_OUTPUT}"
    then
        echo "PASS: run-ID collision rejected"
    else
        echo "FAIL: collision failed for unexpected reason"
        cat "${COLLISION_OUTPUT}"
        rm -f "${COLLISION_OUTPUT}"
        false
    fi
fi

rm -f "${COLLISION_OUTPUT}"


COUNTS_AFTER_COLLISION="$(
sql "
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

assert_eq \
  "${COUNTS_AFTER_COLLISION}" \
  "${COUNTS_BEFORE}" \
  "collision rejection leaves database unchanged"


COLLISION_FLAG="$(
sql "
SELECT
    raw_result ? 'collision_test'
FROM compliance.compliance_runs
WHERE run_id =
    'compliance-ci-run-001';
"
)"

assert_eq \
  "${COLLISION_FLAG}" \
  "f" \
  "rejected collision payload was not persisted"


echo
echo "========================================"
echo "COMPLIANCE RUN INGESTION TEST: PASS"
echo "========================================"
