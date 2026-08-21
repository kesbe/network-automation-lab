\set ON_ERROR_STOP on

\echo
\echo '===== TEST 1: NEWER CLEAN SCAN RESOLVES OPEN FINDING ====='

TRUNCATE
    compliance.finding_events,
    compliance.finding_occurrences,
    compliance.compliance_run_devices,
    compliance.compliance_findings,
    compliance.compliance_runs
RESTART IDENTITY CASCADE;


INSERT INTO compliance.compliance_findings
(
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
VALUES
(
    'finding-test-open',
    'leaf01|TEST-001|device',
    'leaf01',
    'TEST-001',
    'test_control',
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


BEGIN;

INSERT INTO compliance.compliance_runs
(
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
VALUES
(
    'clean-newer',
    '1.0',
    '2026-01-01 10:05:00+00',
    'test',
    100,
    101,
    102,
    1,
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    '{}'::jsonb
);


INSERT INTO compliance.compliance_run_devices
(
    run_id,
    device,
    status,
    total_checks,
    passed_checks,
    failed_checks,
    violations_count,
    raw_result
)
VALUES
(
    'clean-newer',
    'leaf01',
    'COMPLIANT',
    1,
    1,
    0,
    0,
    '{}'::jsonb
);

COMMIT;


DO $$
BEGIN

    IF NOT EXISTS
    (
        SELECT 1
        FROM compliance.compliance_findings
        WHERE finding_id = 'finding-test-open'
          AND status = 'RESOLVED'
          AND resolved_at =
              '2026-01-01 10:05:00+00'::timestamptz
    )
    THEN
        RAISE EXCEPTION
            'TEST 1 FAIL: OPEN finding was not resolved';
    END IF;


    IF
    (
        SELECT count(*)
        FROM compliance.finding_events
        WHERE finding_id = 'finding-test-open'
          AND run_id = 'clean-newer'
          AND event_type = 'RESOLVED'
          AND old_status = 'OPEN'
          AND new_status = 'RESOLVED'
    ) <> 1
    THEN
        RAISE EXCEPTION
            'TEST 1 FAIL: expected exactly one RESOLVED event';
    END IF;

END;
$$;

\echo 'TEST 1 PASS'


\echo
\echo '===== TEST 2: DEVICE ABSENT FROM RUN MUST NOT RESOLVE ====='

TRUNCATE
    compliance.finding_events,
    compliance.finding_occurrences,
    compliance.compliance_run_devices,
    compliance.compliance_findings,
    compliance.compliance_runs
RESTART IDENTITY CASCADE;


INSERT INTO compliance.compliance_findings
(
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
VALUES
(
    'finding-partial',
    'leaf01|TEST-002|device',
    'leaf01',
    'TEST-002',
    'test_control',
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
    '{}'::jsonb,
    '{}'::jsonb,
    '2026-01-01 10:00:00+00',
    '2026-01-01 10:00:00+00'
);


BEGIN;

INSERT INTO compliance.compliance_runs
(
    run_id, schema_version, generated_at, source,
    workflow_job_id, compliance_job_id, aggregator_job_id,
    devices_checked, devices_compliant, devices_noncompliant,
    total_findings, critical_findings, high_findings,
    medium_findings, low_findings, info_findings,
    raw_result
)
VALUES
(
    'partial-other-device',
    '1.0',
    '2026-01-01 10:05:00+00',
    'test',
    200, 201, 202,
    1, 1, 0,
    0, 0, 0, 0, 0, 0,
    '{}'::jsonb
);


INSERT INTO compliance.compliance_run_devices
(
    run_id, device, status,
    total_checks, passed_checks, failed_checks,
    violations_count, raw_result
)
VALUES
(
    'partial-other-device',
    'leaf02',
    'COMPLIANT',
    1, 1, 0,
    0,
    '{}'::jsonb
);

COMMIT;


DO $$
BEGIN

    IF NOT EXISTS
    (
        SELECT 1
        FROM compliance.compliance_findings
        WHERE finding_id = 'finding-partial'
          AND status = 'OPEN'
          AND resolved_at IS NULL
    )
    THEN
        RAISE EXCEPTION
            'TEST 2 FAIL: finding for unscanned device changed';
    END IF;

    IF EXISTS
    (
        SELECT 1
        FROM compliance.finding_events
        WHERE finding_id = 'finding-partial'
          AND event_type = 'RESOLVED'
    )
    THEN
        RAISE EXCEPTION
            'TEST 2 FAIL: unexpected RESOLVED event';
    END IF;

END;
$$;

\echo 'TEST 2 PASS'


\echo
\echo '===== TEST 3: HISTORICAL CLEAN RUN MUST NOT RESOLVE NEWER FINDING ====='

TRUNCATE
    compliance.finding_events,
    compliance.finding_occurrences,
    compliance.compliance_run_devices,
    compliance.compliance_findings,
    compliance.compliance_runs
RESTART IDENTITY CASCADE;


INSERT INTO compliance.compliance_findings
(
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
VALUES
(
    'finding-newer',
    'leaf01|TEST-003|device',
    'leaf01',
    'TEST-003',
    'test_control',
    'device',
    'routing',
    'high',
    false,
    'network',
    'OPEN',
    '2026-01-01 10:10:00+00',
    '2026-01-01 10:10:00+00',
    NULL,
    true,
    'auto',
    'low',
    '{}'::jsonb,
    '{}'::jsonb,
    '2026-01-01 10:10:00+00',
    '2026-01-01 10:10:00+00'
);


BEGIN;

INSERT INTO compliance.compliance_runs
(
    run_id, schema_version, generated_at, source,
    workflow_job_id, compliance_job_id, aggregator_job_id,
    devices_checked, devices_compliant, devices_noncompliant,
    total_findings, critical_findings, high_findings,
    medium_findings, low_findings, info_findings,
    raw_result
)
VALUES
(
    'historical-clean',
    '1.0',
    '2026-01-01 10:05:00+00',
    'test',
    300, 301, 302,
    1, 1, 0,
    0, 0, 0, 0, 0, 0,
    '{}'::jsonb
);


INSERT INTO compliance.compliance_run_devices
(
    run_id, device, status,
    total_checks, passed_checks, failed_checks,
    violations_count, raw_result
)
VALUES
(
    'historical-clean',
    'leaf01',
    'COMPLIANT',
    1, 1, 0,
    0,
    '{}'::jsonb
);

COMMIT;


DO $$
BEGIN

    IF NOT EXISTS
    (
        SELECT 1
        FROM compliance.compliance_findings
        WHERE finding_id = 'finding-newer'
          AND status = 'OPEN'
          AND resolved_at IS NULL
    )
    THEN
        RAISE EXCEPTION
            'TEST 3 FAIL: historical run resolved newer finding';
    END IF;

END;
$$;

\echo 'TEST 3 PASS'


\echo
\echo '===== TEST 4: REMEDIATING FINDING CAN RESOLVE ====='

TRUNCATE
    compliance.finding_events,
    compliance.finding_occurrences,
    compliance.compliance_run_devices,
    compliance.compliance_findings,
    compliance.compliance_runs
RESTART IDENTITY CASCADE;


INSERT INTO compliance.compliance_findings
(
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
VALUES
(
    'finding-remediating',
    'leaf01|TEST-004|device',
    'leaf01',
    'TEST-004',
    'test_control',
    'device',
    'routing',
    'high',
    false,
    'network',
    'REMEDIATING',
    '2026-01-01 10:00:00+00',
    '2026-01-01 10:00:00+00',
    NULL,
    true,
    'auto',
    'low',
    '{}'::jsonb,
    '{}'::jsonb,
    '2026-01-01 10:00:00+00',
    '2026-01-01 10:00:00+00'
);


BEGIN;

INSERT INTO compliance.compliance_runs
(
    run_id, schema_version, generated_at, source,
    workflow_job_id, compliance_job_id, aggregator_job_id,
    devices_checked, devices_compliant, devices_noncompliant,
    total_findings, critical_findings, high_findings,
    medium_findings, low_findings, info_findings,
    raw_result
)
VALUES
(
    'remediation-clean',
    '1.0',
    '2026-01-01 10:05:00+00',
    'test',
    400, 401, 402,
    1, 1, 0,
    0, 0, 0, 0, 0, 0,
    '{}'::jsonb
);


INSERT INTO compliance.compliance_run_devices
(
    run_id, device, status,
    total_checks, passed_checks, failed_checks,
    violations_count, raw_result
)
VALUES
(
    'remediation-clean',
    'leaf01',
    'COMPLIANT',
    1, 1, 0,
    0,
    '{}'::jsonb
);

COMMIT;


DO $$
BEGIN

    IF NOT EXISTS
    (
        SELECT 1
        FROM compliance.compliance_findings
        WHERE finding_id = 'finding-remediating'
          AND status = 'RESOLVED'
    )
    THEN
        RAISE EXCEPTION
            'TEST 4 FAIL: REMEDIATING finding not resolved';
    END IF;

    IF
    (
        SELECT count(*)
        FROM compliance.finding_events
        WHERE finding_id = 'finding-remediating'
          AND event_type = 'RESOLVED'
          AND old_status = 'REMEDIATING'
          AND new_status = 'RESOLVED'
    ) <> 1
    THEN
        RAISE EXCEPTION
            'TEST 4 FAIL: lifecycle event incorrect';
    END IF;

END;
$$;

\echo 'TEST 4 PASS'


\echo
\echo '===== TEST 5: SUPPRESSED FINDING MUST REMAIN SUPPRESSED ====='

TRUNCATE
    compliance.finding_events,
    compliance.finding_occurrences,
    compliance.compliance_run_devices,
    compliance.compliance_findings,
    compliance.compliance_runs
RESTART IDENTITY CASCADE;


INSERT INTO compliance.compliance_findings
(
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
VALUES
(
    'finding-suppressed',
    'leaf01|TEST-005|device',
    'leaf01',
    'TEST-005',
    'test_control',
    'device',
    'routing',
    'medium',
    false,
    'network',
    'SUPPRESSED',
    '2026-01-01 10:00:00+00',
    '2026-01-01 10:00:00+00',
    NULL,
    false,
    'report_only',
    'low',
    '{}'::jsonb,
    '{}'::jsonb,
    '2026-01-01 10:00:00+00',
    '2026-01-01 10:00:00+00'
);


BEGIN;

INSERT INTO compliance.compliance_runs
(
    run_id, schema_version, generated_at, source,
    workflow_job_id, compliance_job_id, aggregator_job_id,
    devices_checked, devices_compliant, devices_noncompliant,
    total_findings, critical_findings, high_findings,
    medium_findings, low_findings, info_findings,
    raw_result
)
VALUES
(
    'suppressed-clean',
    '1.0',
    '2026-01-01 10:05:00+00',
    'test',
    500, 501, 502,
    1, 1, 0,
    0, 0, 0, 0, 0, 0,
    '{}'::jsonb
);


INSERT INTO compliance.compliance_run_devices
(
    run_id, device, status,
    total_checks, passed_checks, failed_checks,
    violations_count, raw_result
)
VALUES
(
    'suppressed-clean',
    'leaf01',
    'COMPLIANT',
    1, 1, 0,
    0,
    '{}'::jsonb
);

COMMIT;


DO $$
BEGIN

    IF NOT EXISTS
    (
        SELECT 1
        FROM compliance.compliance_findings
        WHERE finding_id = 'finding-suppressed'
          AND status = 'SUPPRESSED'
          AND resolved_at IS NULL
    )
    THEN
        RAISE EXCEPTION
            'TEST 5 FAIL: SUPPRESSED finding changed';
    END IF;

    IF EXISTS
    (
        SELECT 1
        FROM compliance.finding_events
        WHERE finding_id = 'finding-suppressed'
          AND event_type = 'RESOLVED'
    )
    THEN
        RAISE EXCEPTION
            'TEST 5 FAIL: SUPPRESSED finding generated RESOLVED event';
    END IF;

END;
$$;

\echo 'TEST 5 PASS'


\echo
\echo '===== ALL ABSENCE RESOLUTION TESTS PASSED ====='
