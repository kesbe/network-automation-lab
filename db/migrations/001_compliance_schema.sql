BEGIN;

CREATE SCHEMA compliance;


-- ============================================================
-- 1. COMPLIANCE RUNS
--
-- One row per execution of JT38 / compliance aggregation.
--
-- run_id is TEXT rather than PostgreSQL UUID because the
-- application contract also permits explicit external IDs.
-- Automatically generated IDs use:
--
--   compliance-<UUID4>
-- ============================================================

CREATE TABLE compliance.compliance_runs (
    run_id                  TEXT PRIMARY KEY,

    schema_version          TEXT NOT NULL,
    generated_at            TIMESTAMPTZ NOT NULL,
    ingested_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    source                  TEXT NOT NULL DEFAULT 'awx',

    workflow_job_id         BIGINT,
    compliance_job_id       BIGINT,
    aggregator_job_id       BIGINT,

    devices_checked         INTEGER NOT NULL,
    devices_compliant       INTEGER NOT NULL,
    devices_noncompliant    INTEGER NOT NULL,

    total_findings          INTEGER NOT NULL,
    critical_findings       INTEGER NOT NULL,
    high_findings           INTEGER NOT NULL,
    medium_findings         INTEGER NOT NULL,
    low_findings            INTEGER NOT NULL,
    info_findings           INTEGER NOT NULL,

    raw_result              JSONB NOT NULL,

    CONSTRAINT compliance_runs_run_id_nonempty
        CHECK (btrim(run_id) <> ''),

    CONSTRAINT compliance_runs_device_counts_nonnegative
        CHECK (
            devices_checked >= 0
            AND devices_compliant >= 0
            AND devices_noncompliant >= 0
        ),

    CONSTRAINT compliance_runs_device_counts_consistent
        CHECK (
            devices_compliant + devices_noncompliant
            = devices_checked
        ),

    CONSTRAINT compliance_runs_finding_counts_nonnegative
        CHECK (
            total_findings >= 0
            AND critical_findings >= 0
            AND high_findings >= 0
            AND medium_findings >= 0
            AND low_findings >= 0
            AND info_findings >= 0
        ),

    CONSTRAINT compliance_runs_finding_counts_consistent
        CHECK (
            critical_findings
            + high_findings
            + medium_findings
            + low_findings
            + info_findings
            = total_findings
        )
);


CREATE INDEX idx_compliance_runs_generated_at
    ON compliance.compliance_runs (
        generated_at DESC
    );

CREATE INDEX idx_compliance_runs_workflow_job
    ON compliance.compliance_runs (
        workflow_job_id
    );

CREATE INDEX idx_compliance_runs_aggregator_job
    ON compliance.compliance_runs (
        aggregator_job_id
    );


-- ============================================================
-- 2. PER-DEVICE RESULT FOR EACH RUN
--
-- This is important for reporting clean devices as well as
-- failed devices.
--
-- Without this table, device-level compliance trends would
-- require querying raw JSON for every clean execution.
-- ============================================================

CREATE TABLE compliance.compliance_run_devices (
    run_id              TEXT NOT NULL,
    device              TEXT NOT NULL,

    status              TEXT NOT NULL,

    total_checks        INTEGER NOT NULL,
    passed_checks       INTEGER NOT NULL,
    failed_checks       INTEGER NOT NULL,
    violations_count    INTEGER NOT NULL,

    raw_result          JSONB NOT NULL,

    PRIMARY KEY (
        run_id,
        device
    ),

    CONSTRAINT fk_run_devices_run
        FOREIGN KEY (run_id)
        REFERENCES compliance.compliance_runs(run_id)
        ON DELETE CASCADE,

    CONSTRAINT run_devices_device_nonempty
        CHECK (btrim(device) <> ''),

    CONSTRAINT run_devices_status
        CHECK (
            status IN (
                'COMPLIANT',
                'NON-COMPLIANT'
            )
        ),

    CONSTRAINT run_devices_counts_nonnegative
        CHECK (
            total_checks >= 0
            AND passed_checks >= 0
            AND failed_checks >= 0
            AND violations_count >= 0
        ),

    CONSTRAINT run_devices_check_counts_consistent
        CHECK (
            passed_checks + failed_checks
            = total_checks
        )
);


CREATE INDEX idx_run_devices_device
    ON compliance.compliance_run_devices (
        device
    );

CREATE INDEX idx_run_devices_status
    ON compliance.compliance_run_devices (
        status
    );


-- ============================================================
-- 3. CANONICAL COMPLIANCE FINDINGS
--
-- One row represents one persistent underlying compliance
-- problem.
--
-- This is NOT one row per scan.
--
-- Example:
--
-- leaf01|NET-BGP-002|device
--
-- remains the same finding while that underlying issue exists.
-- ============================================================

CREATE TABLE compliance.compliance_findings (
    finding_id              TEXT PRIMARY KEY,
    finding_fingerprint     TEXT NOT NULL UNIQUE,

    device                  TEXT NOT NULL,
    policy_id               TEXT NOT NULL,
    control                 TEXT NOT NULL,
    finding_scope           TEXT NOT NULL,

    category                TEXT NOT NULL,
    severity                TEXT NOT NULL,
    ticket_required         BOOLEAN NOT NULL,
    owner                   TEXT NOT NULL,

    status                  TEXT NOT NULL DEFAULT 'OPEN',

    first_seen              TIMESTAMPTZ NOT NULL,
    last_seen               TIMESTAMPTZ NOT NULL,
    resolved_at             TIMESTAMPTZ,

    remediation_supported   BOOLEAN NOT NULL,
    remediation_mode        TEXT NOT NULL,
    remediation_risk        TEXT NOT NULL,

    expected                JSONB,
    current_actual          JSONB,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT findings_id_nonempty
        CHECK (btrim(finding_id) <> ''),

    CONSTRAINT findings_fingerprint_nonempty
        CHECK (btrim(finding_fingerprint) <> ''),

    CONSTRAINT findings_severity
        CHECK (
            severity IN (
                'critical',
                'high',
                'medium',
                'low',
                'info'
            )
        ),

    CONSTRAINT findings_status
        CHECK (
            status IN (
                'OPEN',
                'REMEDIATING',
                'RESOLVED',
                'SUPPRESSED'
            )
        ),

    CONSTRAINT findings_remediation_mode
        CHECK (
            remediation_mode IN (
                'auto',
                'approval_required',
                'manual',
                'report_only'
            )
        ),

    CONSTRAINT findings_remediation_risk
        CHECK (
            remediation_risk IN (
                'low',
                'medium',
                'high'
            )
        ),

    CONSTRAINT findings_seen_time_order
        CHECK (
            last_seen >= first_seen
        ),

    CONSTRAINT findings_resolved_timestamp
        CHECK (
            (
                status = 'RESOLVED'
                AND resolved_at IS NOT NULL
            )
            OR
            (
                status <> 'RESOLVED'
                AND resolved_at IS NULL
            )
        )
);


CREATE INDEX idx_findings_status_severity
    ON compliance.compliance_findings (
        status,
        severity
    );

CREATE INDEX idx_findings_device_status
    ON compliance.compliance_findings (
        device,
        status
    );

CREATE INDEX idx_findings_policy_status
    ON compliance.compliance_findings (
        policy_id,
        status
    );

CREATE INDEX idx_findings_last_seen
    ON compliance.compliance_findings (
        last_seen DESC
    );

CREATE INDEX idx_findings_ticket_required
    ON compliance.compliance_findings (
        severity,
        last_seen DESC
    )
    WHERE ticket_required = true;


-- ============================================================
-- 4. FINDING OCCURRENCES
--
-- Links persistent findings to individual compliance runs.
--
-- Same finding:
--
-- run A ----\
-- run B -----+---- finding-c4773...
-- run C ----/
--
-- Primary key ensures the same finding cannot be written twice
-- for the same compliance run.
-- ============================================================

CREATE TABLE compliance.finding_occurrences (
    run_id                  TEXT NOT NULL,
    finding_id              TEXT NOT NULL,

    observed_at             TIMESTAMPTZ NOT NULL,

    device_status           TEXT NOT NULL,
    severity                TEXT NOT NULL,
    ticket_required         BOOLEAN NOT NULL,

    expected                JSONB,
    actual                  JSONB,
    remediation             JSONB NOT NULL,

    raw_finding             JSONB NOT NULL,

    PRIMARY KEY (
        run_id,
        finding_id
    ),

    CONSTRAINT fk_occurrence_run
        FOREIGN KEY (run_id)
        REFERENCES compliance.compliance_runs(run_id)
        ON DELETE CASCADE,

    CONSTRAINT fk_occurrence_finding
        FOREIGN KEY (finding_id)
        REFERENCES compliance.compliance_findings(finding_id),

    CONSTRAINT occurrence_severity
        CHECK (
            severity IN (
                'critical',
                'high',
                'medium',
                'low',
                'info'
            )
        )
);


CREATE INDEX idx_occurrences_finding_time
    ON compliance.finding_occurrences (
        finding_id,
        observed_at DESC
    );

CREATE INDEX idx_occurrences_observed_at
    ON compliance.finding_occurrences (
        observed_at DESC
    );


-- ============================================================
-- 5. FINDING LIFECYCLE EVENTS
--
-- Append-only audit history.
--
-- Examples:
--
-- DETECTED
-- SEEN_AGAIN
-- REMEDIATION_STARTED
-- REMEDIATION_SUCCEEDED
-- REMEDIATION_FAILED
-- VERIFIED
-- RESOLVED
-- REOPENED
-- TICKET_CREATED
-- TICKET_UPDATED
-- SUPPRESSED
-- ============================================================

CREATE TABLE compliance.finding_events (
    event_id            BIGINT GENERATED ALWAYS AS IDENTITY
                        PRIMARY KEY,

    finding_id          TEXT NOT NULL,
    run_id              TEXT,

    event_type          TEXT NOT NULL,
    event_time          TIMESTAMPTZ NOT NULL DEFAULT now(),

    old_status          TEXT,
    new_status          TEXT,

    actor               TEXT NOT NULL DEFAULT 'automation',

    details             JSONB NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT fk_event_finding
        FOREIGN KEY (finding_id)
        REFERENCES compliance.compliance_findings(finding_id),

    CONSTRAINT fk_event_run
        FOREIGN KEY (run_id)
        REFERENCES compliance.compliance_runs(run_id),

    CONSTRAINT event_type_nonempty
        CHECK (
            btrim(event_type) <> ''
        ),

    CONSTRAINT event_old_status
        CHECK (
            old_status IS NULL
            OR old_status IN (
                'OPEN',
                'REMEDIATING',
                'RESOLVED',
                'SUPPRESSED'
            )
        ),

    CONSTRAINT event_new_status
        CHECK (
            new_status IS NULL
            OR new_status IN (
                'OPEN',
                'REMEDIATING',
                'RESOLVED',
                'SUPPRESSED'
            )
        )
);


CREATE INDEX idx_finding_events_finding_time
    ON compliance.finding_events (
        finding_id,
        event_time DESC
    );

CREATE INDEX idx_finding_events_run
    ON compliance.finding_events (
        run_id
    );

CREATE INDEX idx_finding_events_type_time
    ON compliance.finding_events (
        event_type,
        event_time DESC
    );


COMMIT;
