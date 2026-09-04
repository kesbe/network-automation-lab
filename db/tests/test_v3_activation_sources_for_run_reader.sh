#!/usr/bin/env bash

set -uo pipefail


PG_HOST="${NETAUTO_PG_HOST:-}"
PG_PORT="${NETAUTO_PG_PORT:-}"
PG_DATABASE="${NETAUTO_PG_DATABASE:-}"
PG_USERNAME="${NETAUTO_PG_USERNAME:-}"
PG_PASSWORD="${NETAUTO_PG_PASSWORD:-}"
PG_SSLMODE="${NETAUTO_PG_SSLMODE:-}"

ZERO_RUN_ID="${V3_ZERO_ACTIVATION_RUN_ID:-}"
ACTIVATION_RUN_ID="${V3_ACTIVATION_RUN_ID:-}"


echo
echo "===== V3 ACTIVATION SOURCES FOR RUN READER ====="


MISSING=0

for NAME in \
    PG_HOST \
    PG_PORT \
    PG_DATABASE \
    PG_USERNAME \
    PG_PASSWORD \
    PG_SSLMODE \
    ZERO_RUN_ID \
    ACTIVATION_RUN_ID
do
    VALUE="${!NAME:-}"

    if [[ -z "${VALUE}" ]]; then
        echo "missing_required_input=${NAME}"
        MISSING=1
    fi
done


if [[ "${MISSING}" -ne 0 ]]; then
    echo "v3_activation_run_reader_result=HOLD"
    exit 1
fi


if [[ "${PG_DATABASE}" != "network_compliance" ]]; then
    echo "database_identity=HOLD"
    exit 1
fi


if [[ "${PG_USERNAME}" != "compliance_writer" ]]; then
    echo "runtime_identity=HOLD"
    exit 1
fi


if [[ "${PG_SSLMODE}" != "disable" ]]; then
    echo "sslmode_identity=HOLD"
    exit 1
fi


if ! command -v psql >/dev/null 2>&1; then
    echo "psql_available=HOLD"
    exit 1
fi


export PGPASSWORD="${PG_PASSWORD}"
export PGSSLMODE="${PG_SSLMODE}"


PSQL=(
    psql
    -X
    -q
    -h "${PG_HOST}"
    -p "${PG_PORT}"
    -U "${PG_USERNAME}"
    -d "${PG_DATABASE}"
)


echo
echo "===== RUNTIME PRIVILEGE BOUNDARY ====="


IDENTITY="$(
    "${PSQL[@]}" \
        -v ON_ERROR_STOP=1 \
        -At \
        -F '|' \
        -c "
            SELECT
                current_user,
                has_function_privilege(
                    current_user,
                    'compliance.read_v3_activation_sources_for_run(text)',
                    'EXECUTE'
                ),
                has_table_privilege(
                    current_user,
                    'compliance.v3_activation_sources',
                    'SELECT'
                ),
                has_table_privilege(
                    current_user,
                    'compliance.v3_run_persistence_contexts',
                    'SELECT'
                );
        "
)"
IDENTITY_RC=$?


echo "identity_query_rc=${IDENTITY_RC}"
echo "identity_result=${IDENTITY}"


if [[ "${IDENTITY_RC}" -eq 0 ]] &&
   [[ "${IDENTITY}" == "compliance_writer|t|f|f" ]]
then
    echo "runtime_privilege_boundary=PASS"
else
    echo "runtime_privilege_boundary=HOLD"
    exit 1
fi


echo
echo "===== KNOWN ZERO-ACTIVATION RUN ====="


ZERO_COUNT="$(
    "${PSQL[@]}" \
        -v ON_ERROR_STOP=1 \
        -v run_id="${ZERO_RUN_ID}" \
        -At \
        -c "
            SELECT count(*)
            FROM compliance.read_v3_activation_sources_for_run(
                :'run_id'
            );
        "
)"
ZERO_RC=$?


echo "zero_run_query_rc=${ZERO_RC}"
echo "zero_run_count=${ZERO_COUNT}"


if [[ "${ZERO_RC}" -eq 0 ]] &&
   [[ "${ZERO_COUNT}" == "0" ]]
then
    echo "zero_activation_run=PASS"
else
    echo "zero_activation_run=HOLD"
    exit 1
fi


echo
echo "===== KNOWN ACTIVATION RUN ====="


ACTIVATION_RESULT="$(
    "${PSQL[@]}" \
        -v ON_ERROR_STOP=1 \
        -v run_id="${ACTIVATION_RUN_ID}" \
        -At \
        -F '|' \
        -c "
            SELECT
                count(*),
                bool_and(
                    lifecycle_event_type
                    IN ('DETECTED', 'REOPENED')
                ),
                bool_and(
                    finding_snapshot->>'finding_id'
                    = finding_id
                ),
                bool_and(
                    jsonb_typeof(resolved_target)
                    = 'object'
                )
            FROM compliance.read_v3_activation_sources_for_run(
                :'run_id'
            );
        "
)"
ACTIVATION_RC=$?


echo "activation_run_query_rc=${ACTIVATION_RC}"
echo "activation_run_result=${ACTIVATION_RESULT}"


IFS='|' read -r \
    ACTIVATION_COUNT \
    ACTIVATION_LIFECYCLE_OK \
    ACTIVATION_FINDING_OK \
    ACTIVATION_TARGET_OK \
    <<< "${ACTIVATION_RESULT}"


if [[ "${ACTIVATION_RC}" -eq 0 ]] &&
   [[ "${ACTIVATION_COUNT:-0}" -gt 0 ]] &&
   [[ "${ACTIVATION_LIFECYCLE_OK:-}" == "t" ]] &&
   [[ "${ACTIVATION_FINDING_OK:-}" == "t" ]] &&
   [[ "${ACTIVATION_TARGET_OK:-}" == "t" ]]
then
    echo "activation_run=PASS"
else
    echo "activation_run=HOLD"
    exit 1
fi


probe_sqlstate() {
    local RUN_ID="$1"

    local OUTPUT

    OUTPUT="$(
        "${PSQL[@]}" \
            -v ON_ERROR_STOP=0 \
            -v run_id="${RUN_ID}" \
            2>&1 <<'SQL'
SELECT count(*)
FROM compliance.read_v3_activation_sources_for_run(
    :'run_id'
);
\echo observed_sqlstate=:SQLSTATE
SQL
    )"

    printf '%s\n' "${OUTPUT}" |
        awk -F= '
            /^observed_sqlstate=/ {
                print $2
            }
        ' |
        tail -1
}


echo
echo "===== EMPTY RUN ID FAIL-CLOSED ====="


EMPTY_STATE="$(
    probe_sqlstate ""
)"


echo "empty_run_sqlstate=${EMPTY_STATE}"


if [[ "${EMPTY_STATE}" == "22023" ]]; then
    echo "empty_run_failclosed=PASS"
else
    echo "empty_run_failclosed=HOLD"
    exit 1
fi


echo
echo "===== UNKNOWN RUN ID FAIL-CLOSED ====="


UNKNOWN_RUN_ID="v3-reader-missing-$PPID-$$"

UNKNOWN_STATE="$(
    probe_sqlstate "${UNKNOWN_RUN_ID}"
)"


echo "unknown_run_sqlstate=${UNKNOWN_STATE}"


if [[ "${UNKNOWN_STATE}" == "P0002" ]]; then
    echo "unknown_run_failclosed=PASS"
else
    echo "unknown_run_failclosed=HOLD"
    exit 1
fi


unset PGPASSWORD


echo
echo "v3_activation_run_reader_result=PASS"
