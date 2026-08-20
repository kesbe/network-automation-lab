#!/usr/bin/env bash

set -euo pipefail

CONTAINER="${POSTGRES_TEST_CONTAINER:-compliance-postgres-test}"
DB="${POSTGRES_TEST_DB:-compliance_ci_lifecycle_test}"
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
echo "===== CREATE TEST RUNS ====="

sql "
INSERT INTO compliance.compliance_runs (
    run_id,
    schema_version,
    generated_at,
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
VALUES
(
    'lifecycle-initial',
    '1.0',
    '2026-08-20 11:00:00+00',
    1, 0, 1,
    1, 0, 1, 0, 0, 0,
    '{\"fixture\":\"initial\"}'::jsonb
),
(
    'lifecycle-newer',
    '1.0',
    '2026-08-20 12:00:00+00',
    1, 0, 1,
    1, 1, 0, 0, 0, 0,
    '{\"fixture\":\"newer\"}'::jsonb
),
(
    'lifecycle-historical',
    '1.0',
    '2026-08-20 10:00:00+00',
    1, 0, 1,
    1, 0, 0, 1, 0, 0,
    '{\"fixture\":\"historical\"}'::jsonb
),
(
    'lifecycle-old-after-resolve',
    '1.0',
    '2026-08-20 09:00:00+00',
    1, 0, 1,
    1, 0, 0, 1, 0, 0,
    '{\"fixture\":\"old-after-resolve\"}'::jsonb
);
" >/dev/null


echo
echo "===== DETECTED ====="

RESULT="$(
sql "
SELECT
    result_event_type,
    COALESCE(result_old_status, ''),
    result_new_status,
    occurrence_inserted
FROM compliance.ingest_finding(
    p_run_id :=
        'lifecycle-initial',

    p_finding_id :=
        'finding-lifecycle-test',

    p_finding_fingerprint :=
        'leaf01|NET-BGP-002|device',

    p_device :=
        'leaf01',

    p_policy_id :=
        'NET-BGP-002',

    p_control :=
        'maximum_paths',

    p_finding_scope :=
        'device',

    p_category :=
        'routing_initial',

    p_severity :=
        'high',

    p_ticket_required :=
        false,

    p_owner :=
        'initial_owner',

    p_remediation_supported :=
        true,

    p_remediation_mode :=
        'auto',

    p_remediation_risk :=
        'low',

    p_expected :=
        to_jsonb(2),

    p_actual :=
        to_jsonb('initial-current'::text),

    p_remediation :=
        '{\"supported\":true,\"mode\":\"auto\",\"risk\":\"low\"}'::jsonb,

    p_raw_finding :=
        '{\"fixture\":\"initial\"}'::jsonb,

    p_observed_at :=
        '2026-08-20 11:00:00+00'
);
"
)"

assert_eq \
  "${RESULT}" \
  "DETECTED||OPEN|t" \
  "new fingerprint becomes DETECTED"


echo
echo "===== NEWER OBSERVATION ====="

RESULT="$(
sql "
SELECT
    result_event_type,
    result_old_status,
    result_new_status,
    occurrence_inserted
FROM compliance.ingest_finding(
    p_run_id :=
        'lifecycle-newer',

    p_finding_id :=
        'finding-lifecycle-test',

    p_finding_fingerprint :=
        'leaf01|NET-BGP-002|device',

    p_device :=
        'leaf01',

    p_policy_id :=
        'NET-BGP-002',

    p_control :=
        'maximum_paths',

    p_finding_scope :=
        'device',

    p_category :=
        'routing_latest',

    p_severity :=
        'critical',

    p_ticket_required :=
        true,

    p_owner :=
        'latest_owner',

    p_remediation_supported :=
        true,

    p_remediation_mode :=
        'approval_required',

    p_remediation_risk :=
        'high',

    p_expected :=
        to_jsonb(4),

    p_actual :=
        to_jsonb('latest-current'::text),

    p_remediation :=
        '{\"supported\":true,\"mode\":\"approval_required\",\"risk\":\"high\"}'::jsonb,

    p_raw_finding :=
        '{\"fixture\":\"newer\"}'::jsonb,

    p_observed_at :=
        '2026-08-20 12:00:00+00'
);
"
)"

assert_eq \
  "${RESULT}" \
  "SEEN_AGAIN|OPEN|OPEN|t" \
  "newer OPEN observation becomes SEEN_AGAIN"


echo
echo "===== HISTORICAL OBSERVATION WHILE OPEN ====="

RESULT="$(
sql "
SELECT
    result_event_type,
    result_old_status,
    result_new_status,
    occurrence_inserted
FROM compliance.ingest_finding(
    p_run_id :=
        'lifecycle-historical',

    p_finding_id :=
        'finding-lifecycle-test',

    p_finding_fingerprint :=
        'leaf01|NET-BGP-002|device',

    p_device :=
        'leaf01',

    p_policy_id :=
        'NET-BGP-002',

    p_control :=
        'maximum_paths',

    p_finding_scope :=
        'device',

    p_category :=
        'historical_category',

    p_severity :=
        'medium',

    p_ticket_required :=
        false,

    p_owner :=
        'historical_owner',

    p_remediation_supported :=
        false,

    p_remediation_mode :=
        'manual',

    p_remediation_risk :=
        'medium',

    p_expected :=
        to_jsonb(1),

    p_actual :=
        to_jsonb('historical-actual'::text),

    p_remediation :=
        '{\"supported\":false,\"mode\":\"manual\",\"risk\":\"medium\"}'::jsonb,

    p_raw_finding :=
        '{\"fixture\":\"historical\"}'::jsonb,

    p_observed_at :=
        '2026-08-20 10:00:00+00'
);
"
)"

assert_eq \
  "${RESULT}" \
  "SEEN_AGAIN|OPEN|OPEN|t" \
  "historical OPEN observation is SEEN_AGAIN"


STATE="$(
sql "
SELECT
    status,

    to_char(
        first_seen AT TIME ZONE 'UTC',
        'YYYY-MM-DD HH24:MI:SS'
    ),

    to_char(
        last_seen AT TIME ZONE 'UTC',
        'YYYY-MM-DD HH24:MI:SS'
    ),

    category,
    severity,
    ticket_required,
    owner,

    remediation_supported,
    remediation_mode,
    remediation_risk,

    expected #>> '{}',
    current_actual #>> '{}'

FROM compliance.compliance_findings
WHERE finding_id =
    'finding-lifecycle-test';
"
)"

assert_eq \
  "${STATE}" \
  "OPEN|2026-08-20 10:00:00|2026-08-20 12:00:00|routing_latest|critical|t|latest_owner|t|approval_required|high|4|latest-current" \
  "historical observation preserves current state"


EVENT="$(
sql "
SELECT
    event_type,
    old_status,
    new_status,
    details->>'historical_observation'
FROM compliance.finding_events
WHERE run_id =
    'lifecycle-historical';
"
)"

assert_eq \
  "${EVENT}" \
  "SEEN_AGAIN|OPEN|OPEN|true" \
  "historical event is explicitly marked"


echo
echo "===== RESOLVE FINDING ====="

sql "
UPDATE compliance.compliance_findings
SET
    status = 'RESOLVED',
    resolved_at =
        '2026-08-20 13:00:00+00',
    updated_at =
        '2026-08-20 13:00:00+00'
WHERE finding_id =
    'finding-lifecycle-test';
" >/dev/null


echo
echo "===== OLDER OBSERVATION AFTER RESOLUTION ====="

RESULT="$(
sql "
SELECT
    result_event_type,
    result_old_status,
    result_new_status,
    occurrence_inserted
FROM compliance.ingest_finding(
    p_run_id :=
        'lifecycle-old-after-resolve',

    p_finding_id :=
        'finding-lifecycle-test',

    p_finding_fingerprint :=
        'leaf01|NET-BGP-002|device',

    p_device :=
        'leaf01',

    p_policy_id :=
        'NET-BGP-002',

    p_control :=
        'maximum_paths',

    p_finding_scope :=
        'device',

    p_category :=
        'old_category',

    p_severity :=
        'medium',

    p_ticket_required :=
        false,

    p_owner :=
        'old_owner',

    p_remediation_supported :=
        false,

    p_remediation_mode :=
        'manual',

    p_remediation_risk :=
        'medium',

    p_expected :=
        to_jsonb(1),

    p_actual :=
        to_jsonb('old-actual'::text),

    p_remediation :=
        '{\"supported\":false,\"mode\":\"manual\",\"risk\":\"medium\"}'::jsonb,

    p_raw_finding :=
        '{\"fixture\":\"old-after-resolve\"}'::jsonb,

    p_observed_at :=
        '2026-08-20 09:00:00+00'
);
"
)"

assert_eq \
  "${RESULT}" \
  "SEEN_AGAIN|RESOLVED|RESOLVED|t" \
  "historical observation does not reopen resolved finding"


STATE="$(
sql "
SELECT
    status,

    to_char(
        first_seen AT TIME ZONE 'UTC',
        'YYYY-MM-DD HH24:MI:SS'
    ),

    to_char(
        last_seen AT TIME ZONE 'UTC',
        'YYYY-MM-DD HH24:MI:SS'
    ),

    to_char(
        resolved_at AT TIME ZONE 'UTC',
        'YYYY-MM-DD HH24:MI:SS'
    ),

    category,
    severity,
    ticket_required,
    owner,

    remediation_supported,
    remediation_mode,
    remediation_risk,

    expected #>> '{}',
    current_actual #>> '{}'

FROM compliance.compliance_findings
WHERE finding_id =
    'finding-lifecycle-test';
"
)"

assert_eq \
  "${STATE}" \
  "RESOLVED|2026-08-20 09:00:00|2026-08-20 12:00:00|2026-08-20 13:00:00|routing_latest|critical|t|latest_owner|t|approval_required|high|4|latest-current" \
  "resolved lifecycle and latest state survive historical import"


echo
echo "===== SAME-RUN RETRY ====="

RESULT="$(
sql "
SELECT
    result_event_type,
    result_old_status,
    result_new_status,
    occurrence_inserted
FROM compliance.ingest_finding(
    p_run_id :=
        'lifecycle-old-after-resolve',

    p_finding_id :=
        'finding-lifecycle-test',

    p_finding_fingerprint :=
        'leaf01|NET-BGP-002|device',

    p_device :=
        'leaf01',

    p_policy_id :=
        'NET-BGP-002',

    p_control :=
        'maximum_paths',

    p_finding_scope :=
        'device',

    p_category :=
        'old_category',

    p_severity :=
        'medium',

    p_ticket_required :=
        false,

    p_owner :=
        'old_owner',

    p_remediation_supported :=
        false,

    p_remediation_mode :=
        'manual',

    p_remediation_risk :=
        'medium',

    p_expected :=
        to_jsonb(1),

    p_actual :=
        to_jsonb('old-actual'::text),

    p_remediation :=
        '{\"supported\":false,\"mode\":\"manual\",\"risk\":\"medium\"}'::jsonb,

    p_raw_finding :=
        '{\"fixture\":\"old-after-resolve\"}'::jsonb,

    p_observed_at :=
        '2026-08-20 09:00:00+00'
);
"
)"

assert_eq \
  "${RESULT}" \
  "DUPLICATE|RESOLVED|RESOLVED|f" \
  "same-run retry is idempotent"


COUNTS="$(
sql "
SELECT
    (SELECT count(*)
       FROM compliance.compliance_findings),

    (SELECT count(*)
       FROM compliance.finding_occurrences),

    (SELECT count(*)
       FROM compliance.finding_events);
"
)"

assert_eq \
  "${COUNTS}" \
  "1|4|4" \
  "retry creates no duplicate occurrence or event"


echo
echo "========================================"
echo "FINDING LIFECYCLE TEST: PASS"
echo "========================================"
