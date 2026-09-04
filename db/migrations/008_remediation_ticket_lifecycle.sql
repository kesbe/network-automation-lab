-- ============================================================================
-- 008_remediation_ticket_lifecycle.sql
--
-- V3 durable remediation, approval and ticket lifecycle.
--
-- Design principles:
--
-- * compliance_findings remains the compliance source of truth.
-- * remediation success does NOT itself resolve a finding.
-- * only a later compliant recheck / compliance lifecycle may resolve it.
-- * application roles receive no direct table DML.
-- * ticket and remediation operations are exposed through SECURITY DEFINER APIs.
-- * repeated API calls are idempotent where practical.
-- ============================================================================

BEGIN;


-- ============================================================================
-- 1. REMEDIATION ATTEMPTS
-- ============================================================================

CREATE TABLE compliance.remediation_attempts (
    remediation_attempt_id   TEXT PRIMARY KEY,

    finding_id               TEXT NOT NULL,
    event_id                 TEXT,
    compliance_run_id        TEXT,

    target_id                TEXT NOT NULL,

    device                   TEXT NOT NULL,
    platform                 TEXT NOT NULL,
    control                  TEXT NOT NULL,

    remediation_policy       TEXT NOT NULL,
    attempt_number           INTEGER NOT NULL,

    approval_state           TEXT NOT NULL,
    remediation_state        TEXT NOT NULL,

    workflow_job_id          BIGINT,
    remediation_job_id       BIGINT,
    recheck_job_id           BIGINT,

    failure_class            TEXT,
    failure_message          TEXT,

    details                  JSONB NOT NULL
                             DEFAULT '{}'::jsonb,

    started_at               TIMESTAMPTZ,
    finished_at              TIMESTAMPTZ,

    created_at               TIMESTAMPTZ NOT NULL
                             DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL
                             DEFAULT now(),

    CONSTRAINT fk_remediation_finding
        FOREIGN KEY (finding_id)
        REFERENCES compliance.compliance_findings(finding_id),

    CONSTRAINT remediation_attempt_id_nonempty
        CHECK (
            btrim(remediation_attempt_id) <> ''
        ),

    CONSTRAINT remediation_target_id_nonempty
        CHECK (
            btrim(target_id) <> ''
        ),

    CONSTRAINT remediation_target_id_format
        CHECK (
            target_id LIKE 'target-%'
            AND length(target_id) > 7
        ),

    CONSTRAINT remediation_device_nonempty
        CHECK (
            btrim(device) <> ''
        ),

    CONSTRAINT remediation_platform_nonempty
        CHECK (
            btrim(platform) <> ''
        ),

    CONSTRAINT remediation_control_nonempty
        CHECK (
            btrim(control) <> ''
        ),

    CONSTRAINT remediation_attempt_positive
        CHECK (
            attempt_number > 0
        ),

    CONSTRAINT remediation_policy_allowed
        CHECK (
            remediation_policy IN (
                'auto',
                'approval_required',
                'manual',
                'report_only',
                'observe_only',
                'blocked'
            )
        ),

    CONSTRAINT remediation_approval_state_allowed
        CHECK (
            approval_state IN (
                'NOT_REQUIRED',
                'PENDING',
                'APPROVED',
                'REJECTED',
                'EXPIRED'
            )
        ),

    CONSTRAINT remediation_state_allowed
        CHECK (
            remediation_state IN (
                'READY',
                'WAITING_FOR_APPROVAL',
                'RUNNING',
                'SUCCEEDED',
                'FAILED',
                'SAFETY_BLOCKED',
                'RECHECK_FAILED',
                'COMPLETED',
                'BLOCKED'
            )
        ),

    CONSTRAINT remediation_failure_class_allowed
        CHECK (
            failure_class IS NULL
            OR failure_class IN (
                'TRANSIENT',
                'CONFIGURATION',
                'AUTHENTICATION',
                'SAFETY',
                'UNKNOWN'
            )
        ),

    CONSTRAINT remediation_policy_approval_consistency
        CHECK (
            (
                remediation_policy = 'approval_required'
                AND approval_state IN (
                    'PENDING',
                    'APPROVED',
                    'REJECTED',
                    'EXPIRED'
                )
            )
            OR
            (
                remediation_policy <> 'approval_required'
                AND approval_state = 'NOT_REQUIRED'
            )
        ),

    CONSTRAINT remediation_finished_time_order
        CHECK (
            finished_at IS NULL
            OR started_at IS NULL
            OR finished_at >= started_at
        ),

    CONSTRAINT remediation_failure_fields
        CHECK (
            remediation_state NOT IN (
                'FAILED',
                'SAFETY_BLOCKED',
                'RECHECK_FAILED'
            )
            OR failure_class IS NOT NULL
        )
);


CREATE UNIQUE INDEX idx_remediation_finding_event_attempt
    ON compliance.remediation_attempts (
        finding_id,
        event_id,
        attempt_number
    )
    WHERE event_id IS NOT NULL;


CREATE INDEX idx_remediation_finding_state
    ON compliance.remediation_attempts (
        finding_id,
        remediation_state
    );


CREATE INDEX idx_remediation_target_state
    ON compliance.remediation_attempts (
        target_id,
        remediation_state
    );


CREATE INDEX idx_remediation_state_updated
    ON compliance.remediation_attempts (
        remediation_state,
        updated_at DESC
    );


CREATE INDEX idx_remediation_approval_state
    ON compliance.remediation_attempts (
        approval_state,
        updated_at DESC
    );


-- ============================================================================
-- 2. TICKET RECORDS
-- ============================================================================

CREATE TABLE compliance.ticket_records (
    ticket_record_id         TEXT PRIMARY KEY,

    finding_id               TEXT NOT NULL,

    provider                 TEXT NOT NULL,
    ticket_type              TEXT NOT NULL,

    external_ticket_id       TEXT,
    external_ticket_number   TEXT,

    ticket_state             TEXT NOT NULL,
    approval_state           TEXT NOT NULL,

    remediation_allowed      BOOLEAN NOT NULL
                             DEFAULT false,

    last_error               TEXT,

    details                  JSONB NOT NULL
                             DEFAULT '{}'::jsonb,

    created_at               TIMESTAMPTZ NOT NULL
                             DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL
                             DEFAULT now(),
    last_sync_at             TIMESTAMPTZ,

    CONSTRAINT fk_ticket_finding
        FOREIGN KEY (finding_id)
        REFERENCES compliance.compliance_findings(finding_id),

    CONSTRAINT ticket_record_id_nonempty
        CHECK (
            btrim(ticket_record_id) <> ''
        ),

    CONSTRAINT ticket_provider_nonempty
        CHECK (
            btrim(provider) <> ''
        ),

    CONSTRAINT ticket_type_allowed
        CHECK (
            ticket_type IN (
                'CHANGE',
                'INCIDENT',
                'TASK'
            )
        ),

    CONSTRAINT ticket_state_allowed
        CHECK (
            ticket_state IN (
                'PENDING_CREATE',
                'OPEN',
                'APPROVAL_PENDING',
                'APPROVED',
                'REJECTED',
                'REMEDIATION_RUNNING',
                'REMEDIATION_FAILED',
                'RESOLVED',
                'CLOSED',
                'ERROR'
            )
        ),

    CONSTRAINT ticket_approval_state_allowed
        CHECK (
            approval_state IN (
                'NOT_REQUIRED',
                'PENDING',
                'APPROVED',
                'REJECTED',
                'EXPIRED'
            )
        ),

    CONSTRAINT ticket_remediation_allowed_consistency
        CHECK (
            remediation_allowed = false
            OR approval_state IN (
                'NOT_REQUIRED',
                'APPROVED'
            )
        )
);


CREATE INDEX idx_ticket_finding
    ON compliance.ticket_records (
        finding_id
    );


CREATE INDEX idx_ticket_state_updated
    ON compliance.ticket_records (
        ticket_state,
        updated_at DESC
    );


CREATE INDEX idx_ticket_approval
    ON compliance.ticket_records (
        approval_state,
        updated_at DESC
    );


-- Only one active ticket of a given provider/type may exist
-- for the same persistent finding.

CREATE UNIQUE INDEX idx_ticket_one_active_per_finding
    ON compliance.ticket_records (
        finding_id,
        provider,
        ticket_type
    )
    WHERE ticket_state NOT IN (
        'RESOLVED',
        'CLOSED'
    );


-- ============================================================================
-- 3. APPLICATION CAPABILITY ROLES
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_roles
        WHERE rolname = 'compliance_remediation'
    ) THEN
        CREATE ROLE compliance_remediation
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_roles
        WHERE rolname = 'compliance_ticketing'
    ) THEN
        CREATE ROLE compliance_ticketing
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS;
    END IF;
END
$$;


ALTER ROLE compliance_remediation
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;


ALTER ROLE compliance_ticketing
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;


GRANT USAGE ON SCHEMA compliance
    TO compliance_remediation;

GRANT USAGE ON SCHEMA compliance
    TO compliance_ticketing;


REVOKE ALL PRIVILEGES
    ON compliance.remediation_attempts
    FROM compliance_remediation;

REVOKE ALL PRIVILEGES
    ON compliance.ticket_records
    FROM compliance_remediation;

REVOKE ALL PRIVILEGES
    ON compliance.remediation_attempts
    FROM compliance_ticketing;

REVOKE ALL PRIVILEGES
    ON compliance.ticket_records
    FROM compliance_ticketing;


-- Internal API owner needs DML on the new tables.

GRANT SELECT, INSERT, UPDATE
    ON compliance.remediation_attempts
    TO compliance_api_owner;

GRANT SELECT, INSERT, UPDATE
    ON compliance.ticket_records
    TO compliance_api_owner;


-- ============================================================================
-- 4. CREATE / CLAIM REMEDIATION ATTEMPT
-- ============================================================================

CREATE FUNCTION compliance.create_remediation_attempt(
    p_remediation_attempt_id TEXT,
    p_finding_id             TEXT,
    p_event_id               TEXT,
    p_compliance_run_id      TEXT,
    p_target_id              TEXT,
    p_device                 TEXT,
    p_platform               TEXT,
    p_control                TEXT,
    p_remediation_policy     TEXT,
    p_attempt_number         INTEGER,
    p_workflow_job_id        BIGINT,
    p_details                JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_finding               compliance.compliance_findings%ROWTYPE;
    v_existing              compliance.remediation_attempts%ROWTYPE;

    v_approval_state        TEXT;
    v_remediation_state     TEXT;

    v_inserted              BOOLEAN := false;
BEGIN
    IF p_remediation_attempt_id IS NULL
       OR btrim(p_remediation_attempt_id) = ''
    THEN
        RAISE EXCEPTION
            'remediation_attempt_id must not be empty';
    END IF;

    IF p_finding_id IS NULL
       OR btrim(p_finding_id) = ''
    THEN
        RAISE EXCEPTION
            'finding_id must not be empty';
    END IF;

    IF p_target_id IS NULL
       OR btrim(p_target_id) = ''
    THEN
        RAISE EXCEPTION
            'target_id must not be empty';
    END IF;

    IF p_target_id NOT LIKE 'target-%'
       OR length(p_target_id) <= 7
    THEN
        RAISE EXCEPTION
            'target_id has invalid format: %',
            p_target_id;
    END IF;

    IF p_device IS NULL
       OR btrim(p_device) = ''
    THEN
        RAISE EXCEPTION
            'device must not be empty';
    END IF;

    IF p_platform IS NULL
       OR btrim(p_platform) = ''
    THEN
        RAISE EXCEPTION
            'platform must not be empty';
    END IF;

    IF p_control IS NULL
       OR btrim(p_control) = ''
    THEN
        RAISE EXCEPTION
            'control must not be empty';
    END IF;

    IF p_attempt_number IS NULL
       OR p_attempt_number < 1
    THEN
        RAISE EXCEPTION
            'attempt_number must be positive';
    END IF;

    IF p_remediation_policy NOT IN (
        'auto',
        'approval_required',
        'manual',
        'report_only',
        'observe_only',
        'blocked'
    ) THEN
        RAISE EXCEPTION
            'unsupported remediation policy: %',
            p_remediation_policy;
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            p_remediation_attempt_id,
            0
        )
    );

    SELECT *
    INTO v_finding
    FROM compliance.compliance_findings
    WHERE finding_id = p_finding_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'finding does not exist: %',
            p_finding_id;
    END IF;

    IF v_finding.device <> p_device THEN
        RAISE EXCEPTION
            'remediation device mismatch: stored=%, supplied=%',
            v_finding.device,
            p_device;
    END IF;

    IF v_finding.control <> p_control THEN
        RAISE EXCEPTION
            'remediation control mismatch: stored=%, supplied=%',
            v_finding.control,
            p_control;
    END IF;

    -- --------------------------------------------------------
    -- Durable finding policy is authoritative.
    --
    -- A caller may reduce privilege to blocked, but may never
    -- upgrade or bypass the persisted remediation policy.
    -- --------------------------------------------------------

    IF p_remediation_policy <> 'blocked' THEN

        IF v_finding.remediation_mode = 'report_only' THEN

            IF p_remediation_policy NOT IN (
                'report_only',
                'observe_only'
            ) THEN
                RAISE EXCEPTION
                    'remediation policy mismatch: '
                    'finding mode %, requested %',
                    v_finding.remediation_mode,
                    p_remediation_policy;
            END IF;

        ELSIF p_remediation_policy <>
              v_finding.remediation_mode
        THEN
            RAISE EXCEPTION
                'remediation policy mismatch: '
                'finding mode %, requested %',
                v_finding.remediation_mode,
                p_remediation_policy;
        END IF;

    END IF;


    IF p_remediation_policy = 'approval_required'
       AND NOT v_finding.ticket_required
    THEN
        RAISE EXCEPTION
            'approval_required remediation requires '
            'ticket_required finding';
    END IF;


    IF NOT v_finding.remediation_supported
       AND p_remediation_policy IN (
           'auto',
           'approval_required'
       )
    THEN
        RAISE EXCEPTION
            'finding does not support executable remediation';
    END IF;


    IF p_remediation_policy = 'approval_required' THEN
        v_approval_state := 'PENDING';
        v_remediation_state :=
            'WAITING_FOR_APPROVAL';

    ELSIF p_remediation_policy = 'auto' THEN
        v_approval_state := 'NOT_REQUIRED';
        v_remediation_state := 'READY';

    ELSE
        v_approval_state := 'NOT_REQUIRED';
        v_remediation_state := 'BLOCKED';
    END IF;

    INSERT INTO compliance.remediation_attempts (
        remediation_attempt_id,
        finding_id,
        event_id,
        compliance_run_id,
        target_id,
        device,
        platform,
        control,
        remediation_policy,
        attempt_number,
        approval_state,
        remediation_state,
        workflow_job_id,
        details
    )
    VALUES (
        p_remediation_attempt_id,
        p_finding_id,
        NULLIF(btrim(p_event_id), ''),
        NULLIF(btrim(p_compliance_run_id), ''),
        p_target_id,
        p_device,
        p_platform,
        p_control,
        p_remediation_policy,
        p_attempt_number,
        v_approval_state,
        v_remediation_state,
        p_workflow_job_id,
        COALESCE(
            p_details,
            '{}'::jsonb
        )
    )
    ON CONFLICT (remediation_attempt_id)
    DO NOTHING
    RETURNING *
    INTO v_existing;

    IF FOUND THEN
        v_inserted := true;

        INSERT INTO compliance.finding_events (
            finding_id,
            run_id,
            event_type,
            old_status,
            new_status,
            actor,
            details
        )
        VALUES (
            p_finding_id,
            NULLIF(
                btrim(p_compliance_run_id),
                ''
            ),
            CASE
                WHEN p_remediation_policy =
                     'approval_required'
                THEN 'REMEDIATION_APPROVAL_REQUIRED'
                WHEN p_remediation_policy = 'auto'
                THEN 'REMEDIATION_READY'
                ELSE 'REMEDIATION_BLOCKED'
            END,
            v_finding.status,
            v_finding.status,
            'automation',
            jsonb_build_object(
                'remediation_attempt_id',
                p_remediation_attempt_id,
                'target_id',
                p_target_id,
                'remediation_policy',
                p_remediation_policy,
                'finding_remediation_mode',
                v_finding.remediation_mode,
                'approval_state',
                v_approval_state,
                'remediation_state',
                v_remediation_state
            )
        );
    ELSE
        SELECT *
        INTO v_existing
        FROM compliance.remediation_attempts
        WHERE remediation_attempt_id =
              p_remediation_attempt_id;

        IF NOT FOUND THEN
            RAISE EXCEPTION
                'remediation attempt disappeared: %',
                p_remediation_attempt_id;
        END IF;

        IF v_existing.finding_id <> p_finding_id
           OR v_existing.target_id <> p_target_id
           OR v_existing.device <> p_device
           OR v_existing.control <> p_control
           OR v_existing.remediation_policy <>
              p_remediation_policy
           OR v_existing.attempt_number <>
              p_attempt_number
        THEN
            RAISE EXCEPTION
                'remediation attempt identity reuse with different content';
        END IF;
    END IF;

    RETURN jsonb_build_object(
        'remediation_attempt_id',
        v_existing.remediation_attempt_id,
        'finding_id',
        v_existing.finding_id,
        'target_id',
        v_existing.target_id,
        'remediation_policy',
        v_existing.remediation_policy,
        'approval_state',
        v_existing.approval_state,
        'remediation_state',
        v_existing.remediation_state,
        'attempt_number',
        v_existing.attempt_number,
        'inserted',
        v_inserted,
        'duplicate',
        NOT v_inserted
    );
END;
$$;


-- ============================================================================
-- 5. APPROVAL DECISION
-- ============================================================================

CREATE FUNCTION compliance.record_remediation_approval(
    p_remediation_attempt_id TEXT,
    p_decision               TEXT,
    p_actor                  TEXT,
    p_details                JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_row        compliance.remediation_attempts%ROWTYPE;
    v_new_state  TEXT;
BEGIN
    IF p_decision NOT IN (
        'APPROVED',
        'REJECTED',
        'EXPIRED'
    ) THEN
        RAISE EXCEPTION
            'invalid approval decision: %',
            p_decision;
    END IF;

    IF p_actor IS NULL
       OR btrim(p_actor) = ''
    THEN
        RAISE EXCEPTION
            'approval actor must not be empty';
    END IF;

    SELECT *
    INTO v_row
    FROM compliance.remediation_attempts
    WHERE remediation_attempt_id =
          p_remediation_attempt_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'remediation attempt does not exist: %',
            p_remediation_attempt_id;
    END IF;

    IF v_row.remediation_policy <>
       'approval_required'
    THEN
        RAISE EXCEPTION
            'approval decision is only valid for approval_required remediation';
    END IF;

    IF v_row.approval_state = p_decision THEN
        RETURN jsonb_build_object(
            'remediation_attempt_id',
            v_row.remediation_attempt_id,
            'approval_state',
            v_row.approval_state,
            'remediation_state',
            v_row.remediation_state,
            'duplicate',
            true
        );
    END IF;

    IF v_row.approval_state <> 'PENDING' THEN
        RAISE EXCEPTION
            'approval already terminal: %',
            v_row.approval_state;
    END IF;

    v_new_state :=
        CASE p_decision
            WHEN 'APPROVED'
                THEN 'READY'
            WHEN 'REJECTED'
                THEN 'BLOCKED'
            WHEN 'EXPIRED'
                THEN 'BLOCKED'
        END;

    UPDATE compliance.remediation_attempts
    SET
        approval_state = p_decision,
        remediation_state = v_new_state,
        updated_at = now()
    WHERE remediation_attempt_id =
          p_remediation_attempt_id
    RETURNING *
    INTO v_row;

    INSERT INTO compliance.finding_events (
        finding_id,
        run_id,
        event_type,
        actor,
        details
    )
    VALUES (
        v_row.finding_id,
        NULLIF(
            btrim(v_row.compliance_run_id),
            ''
        ),
        CASE p_decision
            WHEN 'APPROVED'
                THEN 'REMEDIATION_APPROVED'
            WHEN 'REJECTED'
                THEN 'REMEDIATION_REJECTED'
            WHEN 'EXPIRED'
                THEN 'REMEDIATION_APPROVAL_EXPIRED'
        END,
        p_actor,
        COALESCE(
            p_details,
            '{}'::jsonb
        )
        ||
        jsonb_build_object(
            'remediation_attempt_id',
            p_remediation_attempt_id,
            'approval_state',
            p_decision
        )
    );

    RETURN jsonb_build_object(
        'remediation_attempt_id',
        v_row.remediation_attempt_id,
        'approval_state',
        v_row.approval_state,
        'remediation_state',
        v_row.remediation_state,
        'duplicate',
        false
    );
END;
$$;


-- ============================================================================
-- 6. REMEDIATION STATE TRANSITION
--
-- No transition here directly resolves compliance_findings.
-- Resolution remains owned by compliance recheck / lifecycle ingestion.
-- ============================================================================

CREATE FUNCTION compliance.transition_remediation_attempt(
    p_remediation_attempt_id TEXT,
    p_expected_state         TEXT,
    p_new_state              TEXT,
    p_workflow_job_id        BIGINT DEFAULT NULL,
    p_remediation_job_id     BIGINT DEFAULT NULL,
    p_recheck_job_id         BIGINT DEFAULT NULL,
    p_failure_class          TEXT DEFAULT NULL,
    p_failure_message        TEXT DEFAULT NULL,
    p_actor                  TEXT DEFAULT 'automation',
    p_details                JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_row         compliance.remediation_attempts%ROWTYPE;
    v_old_state   TEXT;
    v_allowed     BOOLEAN := false;
BEGIN
    IF p_expected_state IS NULL
       OR btrim(p_expected_state) = ''
       OR p_new_state IS NULL
       OR btrim(p_new_state) = ''
    THEN
        RAISE EXCEPTION
            'expected_state and new_state are required';
    END IF;

    SELECT *
    INTO v_row
    FROM compliance.remediation_attempts
    WHERE remediation_attempt_id =
          p_remediation_attempt_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'remediation attempt does not exist: %',
            p_remediation_attempt_id;
    END IF;

    -- Idempotent replay of an already completed transition.
    IF v_row.remediation_state = p_new_state THEN
        RETURN jsonb_build_object(
            'remediation_attempt_id',
            v_row.remediation_attempt_id,
            'remediation_state',
            v_row.remediation_state,
            'duplicate',
            true
        );
    END IF;

    IF v_row.remediation_state <>
       p_expected_state
    THEN
        RAISE EXCEPTION
            'remediation state mismatch: expected %, actual %',
            p_expected_state,
            v_row.remediation_state;
    END IF;

    v_allowed :=
        (
            p_expected_state = 'READY'
            AND p_new_state = 'RUNNING'
        )
        OR
        (
            p_expected_state = 'RUNNING'
            AND p_new_state IN (
                'SUCCEEDED',
                'FAILED',
                'SAFETY_BLOCKED'
            )
        )
        OR
        (
            p_expected_state = 'SUCCEEDED'
            AND p_new_state IN (
                'COMPLETED',
                'RECHECK_FAILED'
            )
        );

    IF NOT v_allowed THEN
        RAISE EXCEPTION
            'invalid remediation transition: % -> %',
            p_expected_state,
            p_new_state;
    END IF;

    -- A terminal post-remediation decision must be correlated
    -- with an actual independent targeted recheck job.
    --
    -- This does not itself prove COMPLIANT. Phase 7K owns the
    -- independent recheck result and finding resolution boundary.
    IF p_new_state IN (
        'COMPLETED',
        'RECHECK_FAILED'
    )
       AND p_recheck_job_id IS NULL
       AND v_row.recheck_job_id IS NULL
    THEN
        RAISE EXCEPTION
            'recheck_job_id is required for remediation state %',
            p_new_state;
    END IF;

    IF p_new_state IN (
        'FAILED',
        'SAFETY_BLOCKED',
        'RECHECK_FAILED'
    )
       AND p_failure_class IS NULL
    THEN
        RAISE EXCEPTION
            'failure_class is required for failure states';
    END IF;

    IF p_failure_class IS NOT NULL
       AND p_failure_class NOT IN (
           'TRANSIENT',
           'CONFIGURATION',
           'AUTHENTICATION',
           'SAFETY',
           'UNKNOWN'
       )
    THEN
        RAISE EXCEPTION
            'unsupported failure_class: %',
            p_failure_class;
    END IF;

    v_old_state := v_row.remediation_state;

    UPDATE compliance.remediation_attempts
    SET
        remediation_state = p_new_state,

        workflow_job_id =
            COALESCE(
                p_workflow_job_id,
                workflow_job_id
            ),

        remediation_job_id =
            COALESCE(
                p_remediation_job_id,
                remediation_job_id
            ),

        recheck_job_id =
            COALESCE(
                p_recheck_job_id,
                recheck_job_id
            ),

        failure_class =
            CASE
                WHEN p_new_state IN (
                    'FAILED',
                    'SAFETY_BLOCKED',
                    'RECHECK_FAILED'
                )
                THEN p_failure_class
                ELSE failure_class
            END,

        failure_message =
            CASE
                WHEN p_new_state IN (
                    'FAILED',
                    'SAFETY_BLOCKED',
                    'RECHECK_FAILED'
                )
                THEN p_failure_message
                ELSE failure_message
            END,

        started_at =
            CASE
                WHEN p_new_state = 'RUNNING'
                THEN COALESCE(
                    started_at,
                    now()
                )
                ELSE started_at
            END,

        finished_at =
            CASE
                WHEN p_new_state IN (
                    'FAILED',
                    'SAFETY_BLOCKED',
                    'RECHECK_FAILED',
                    'COMPLETED'
                )
                THEN now()
                ELSE finished_at
            END,

        details =
            details
            ||
            COALESCE(
                p_details,
                '{}'::jsonb
            ),

        updated_at = now()

    WHERE remediation_attempt_id =
          p_remediation_attempt_id
    RETURNING *
    INTO v_row;

    -- Finding is marked REMEDIATING only while actual automation runs.
    -- A successful remediation does NOT mark it RESOLVED.

    IF p_new_state = 'RUNNING' THEN
        UPDATE compliance.compliance_findings
        SET
            status = 'REMEDIATING',
            resolved_at = NULL,
            updated_at = now()
        WHERE finding_id = v_row.finding_id
          AND status = 'OPEN';

    ELSIF p_new_state IN (
        'FAILED',
        'SAFETY_BLOCKED',
        'RECHECK_FAILED'
    ) THEN
        UPDATE compliance.compliance_findings
        SET
            status = 'OPEN',
            resolved_at = NULL,
            updated_at = now()
        WHERE finding_id = v_row.finding_id
          AND status = 'REMEDIATING';
    END IF;

    INSERT INTO compliance.finding_events (
        finding_id,
        run_id,
        event_type,
        actor,
        details
    )
    VALUES (
        v_row.finding_id,
        NULLIF(
            btrim(v_row.compliance_run_id),
            ''
        ),
        CASE p_new_state
            WHEN 'RUNNING'
                THEN 'REMEDIATION_STARTED'
            WHEN 'SUCCEEDED'
                THEN 'REMEDIATION_SUCCEEDED'
            WHEN 'FAILED'
                THEN 'REMEDIATION_FAILED'
            WHEN 'SAFETY_BLOCKED'
                THEN 'REMEDIATION_SAFETY_BLOCKED'
            WHEN 'RECHECK_FAILED'
                THEN 'REMEDIATION_RECHECK_FAILED'
            WHEN 'COMPLETED'
                THEN 'REMEDIATION_COMPLETED'
        END,
        p_actor,
        jsonb_build_object(
            'remediation_attempt_id',
            p_remediation_attempt_id,
            'old_remediation_state',
            v_old_state,
            'new_remediation_state',
            p_new_state,
            'workflow_job_id',
            v_row.workflow_job_id,
            'remediation_job_id',
            v_row.remediation_job_id,
            'recheck_job_id',
            v_row.recheck_job_id,
            'failure_class',
            v_row.failure_class
        )
        ||
        COALESCE(
            p_details,
            '{}'::jsonb
        )
    );

    RETURN jsonb_build_object(
        'remediation_attempt_id',
        v_row.remediation_attempt_id,
        'remediation_state',
        v_row.remediation_state,
        'approval_state',
        v_row.approval_state,
        'duplicate',
        false
    );
END;
$$;


-- ============================================================================
-- 7. TICKET UPSERT / DEDUP
-- ============================================================================

CREATE FUNCTION compliance.upsert_ticket_record(
    p_ticket_record_id       TEXT,
    p_finding_id             TEXT,
    p_provider               TEXT,
    p_ticket_type            TEXT,
    p_external_ticket_id     TEXT DEFAULT NULL,
    p_external_ticket_number TEXT DEFAULT NULL,
    p_ticket_state           TEXT DEFAULT 'PENDING_CREATE',
    p_approval_state         TEXT DEFAULT 'NOT_REQUIRED',
    p_remediation_allowed    BOOLEAN DEFAULT false,
    p_details                JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_existing compliance.ticket_records%ROWTYPE;
    v_inserted BOOLEAN := false;
BEGIN
    IF p_ticket_record_id IS NULL
       OR btrim(p_ticket_record_id) = ''
    THEN
        RAISE EXCEPTION
            'ticket_record_id must not be empty';
    END IF;

    IF p_finding_id IS NULL
       OR btrim(p_finding_id) = ''
    THEN
        RAISE EXCEPTION
            'finding_id must not be empty';
    END IF;

    IF p_provider IS NULL
       OR btrim(p_provider) = ''
    THEN
        RAISE EXCEPTION
            'provider must not be empty';
    END IF;

    IF p_ticket_type NOT IN (
        'CHANGE',
        'INCIDENT',
        'TASK'
    ) THEN
        RAISE EXCEPTION
            'unsupported ticket_type: %',
            p_ticket_type;
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            p_finding_id
            || '|'
            || p_provider
            || '|'
            || p_ticket_type,
            0
        )
    );

    PERFORM 1
    FROM compliance.compliance_findings
    WHERE finding_id = p_finding_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'finding does not exist: %',
            p_finding_id;
    END IF;

    SELECT *
    INTO v_existing
    FROM compliance.ticket_records
    WHERE finding_id = p_finding_id
      AND provider = p_provider
      AND ticket_type = p_ticket_type
      AND ticket_state NOT IN (
          'RESOLVED',
          'CLOSED'
      )
    FOR UPDATE;

    IF FOUND THEN
        UPDATE compliance.ticket_records
        SET
            external_ticket_id =
                COALESCE(
                    NULLIF(
                        btrim(
                            p_external_ticket_id
                        ),
                        ''
                    ),
                    external_ticket_id
                ),

            external_ticket_number =
                COALESCE(
                    NULLIF(
                        btrim(
                            p_external_ticket_number
                        ),
                        ''
                    ),
                    external_ticket_number
                ),

            details =
                details
                ||
                COALESCE(
                    p_details,
                    '{}'::jsonb
                ),

            updated_at = now(),

            last_sync_at =
                CASE
                    WHEN p_external_ticket_id IS NOT NULL
                         OR p_external_ticket_number IS NOT NULL
                    THEN now()
                    ELSE last_sync_at
                END

        WHERE ticket_record_id =
              v_existing.ticket_record_id
        RETURNING *
        INTO v_existing;

    ELSE
        INSERT INTO compliance.ticket_records (
            ticket_record_id,
            finding_id,
            provider,
            ticket_type,
            external_ticket_id,
            external_ticket_number,
            ticket_state,
            approval_state,
            remediation_allowed,
            details,
            last_sync_at
        )
        VALUES (
            p_ticket_record_id,
            p_finding_id,
            p_provider,
            p_ticket_type,
            NULLIF(
                btrim(p_external_ticket_id),
                ''
            ),
            NULLIF(
                btrim(p_external_ticket_number),
                ''
            ),
            p_ticket_state,
            p_approval_state,
            p_remediation_allowed,
            COALESCE(
                p_details,
                '{}'::jsonb
            ),
            CASE
                WHEN p_external_ticket_id IS NOT NULL
                     OR p_external_ticket_number IS NOT NULL
                THEN now()
                ELSE NULL
            END
        )
        RETURNING *
        INTO v_existing;

        v_inserted := true;

        INSERT INTO compliance.finding_events (
            finding_id,
            event_type,
            actor,
            details
        )
        VALUES (
            p_finding_id,
            'TICKET_CREATED',
            'ticketing',
            jsonb_build_object(
                'ticket_record_id',
                v_existing.ticket_record_id,
                'provider',
                v_existing.provider,
                'ticket_type',
                v_existing.ticket_type,
                'external_ticket_number',
                v_existing.external_ticket_number
            )
        );
    END IF;

    RETURN jsonb_build_object(
        'ticket_record_id',
        v_existing.ticket_record_id,
        'finding_id',
        v_existing.finding_id,
        'ticket_state',
        v_existing.ticket_state,
        'approval_state',
        v_existing.approval_state,
        'external_ticket_id',
        v_existing.external_ticket_id,
        'external_ticket_number',
        v_existing.external_ticket_number,
        'inserted',
        v_inserted,
        'duplicate',
        NOT v_inserted
    );
END;
$$;


-- ============================================================================
-- 8. TICKET STATE UPDATE
-- ============================================================================

CREATE FUNCTION compliance.update_ticket_record(
    p_ticket_record_id       TEXT,
    p_expected_state         TEXT,
    p_new_state              TEXT,
    p_approval_state         TEXT DEFAULT NULL,
    p_remediation_allowed    BOOLEAN DEFAULT NULL,
    p_external_ticket_id     TEXT DEFAULT NULL,
    p_external_ticket_number TEXT DEFAULT NULL,
    p_last_error             TEXT DEFAULT NULL,
    p_details                JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
    v_row compliance.ticket_records%ROWTYPE;
BEGIN
    SELECT *
    INTO v_row
    FROM compliance.ticket_records
    WHERE ticket_record_id =
          p_ticket_record_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'ticket record does not exist: %',
            p_ticket_record_id;
    END IF;

    IF v_row.ticket_state = p_new_state THEN
        RETURN jsonb_build_object(
            'ticket_record_id',
            v_row.ticket_record_id,
            'ticket_state',
            v_row.ticket_state,
            'approval_state',
            v_row.approval_state,
            'duplicate',
            true
        );
    END IF;

    IF v_row.ticket_state <> p_expected_state THEN
        RAISE EXCEPTION
            'ticket state mismatch: expected %, actual %',
            p_expected_state,
            v_row.ticket_state;
    END IF;

    UPDATE compliance.ticket_records
    SET
        ticket_state = p_new_state,

        approval_state =
            COALESCE(
                p_approval_state,
                approval_state
            ),

        remediation_allowed =
            COALESCE(
                p_remediation_allowed,
                remediation_allowed
            ),

        external_ticket_id =
            COALESCE(
                NULLIF(
                    btrim(
                        p_external_ticket_id
                    ),
                    ''
                ),
                external_ticket_id
            ),

        external_ticket_number =
            COALESCE(
                NULLIF(
                    btrim(
                        p_external_ticket_number
                    ),
                    ''
                ),
                external_ticket_number
            ),

        last_error =
            COALESCE(
                p_last_error,
                last_error
            ),

        details =
            details
            ||
            COALESCE(
                p_details,
                '{}'::jsonb
            ),

        last_sync_at = now(),
        updated_at = now()

    WHERE ticket_record_id =
          p_ticket_record_id
    RETURNING *
    INTO v_row;

    INSERT INTO compliance.finding_events (
        finding_id,
        event_type,
        actor,
        details
    )
    VALUES (
        v_row.finding_id,
        'TICKET_UPDATED',
        'ticketing',
        jsonb_build_object(
            'ticket_record_id',
            v_row.ticket_record_id,
            'ticket_state',
            v_row.ticket_state,
            'approval_state',
            v_row.approval_state,
            'external_ticket_number',
            v_row.external_ticket_number
        )
        ||
        COALESCE(
            p_details,
            '{}'::jsonb
        )
    );

    RETURN jsonb_build_object(
        'ticket_record_id',
        v_row.ticket_record_id,
        'ticket_state',
        v_row.ticket_state,
        'approval_state',
        v_row.approval_state,
        'remediation_allowed',
        v_row.remediation_allowed,
        'duplicate',
        false
    );
END;
$$;


-- ============================================================================
-- 9. FUNCTION SECURITY
-- ============================================================================

REVOKE EXECUTE ON FUNCTION
    compliance.create_remediation_attempt(
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        integer,
        bigint,
        jsonb
    )
FROM PUBLIC;


REVOKE EXECUTE ON FUNCTION
    compliance.record_remediation_approval(
        text,
        text,
        text,
        jsonb
    )
FROM PUBLIC;


REVOKE EXECUTE ON FUNCTION
    compliance.transition_remediation_attempt(
        text,
        text,
        text,
        bigint,
        bigint,
        bigint,
        text,
        text,
        text,
        jsonb
    )
FROM PUBLIC;


REVOKE EXECUTE ON FUNCTION
    compliance.upsert_ticket_record(
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        boolean,
        jsonb
    )
FROM PUBLIC;


REVOKE EXECUTE ON FUNCTION
    compliance.update_ticket_record(
        text,
        text,
        text,
        text,
        boolean,
        text,
        text,
        text,
        jsonb
    )
FROM PUBLIC;


GRANT CREATE ON SCHEMA compliance
    TO compliance_api_owner;


ALTER FUNCTION
    compliance.create_remediation_attempt(
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        integer,
        bigint,
        jsonb
    )
OWNER TO compliance_api_owner;


ALTER FUNCTION
    compliance.record_remediation_approval(
        text,
        text,
        text,
        jsonb
    )
OWNER TO compliance_api_owner;


ALTER FUNCTION
    compliance.transition_remediation_attempt(
        text,
        text,
        text,
        bigint,
        bigint,
        bigint,
        text,
        text,
        text,
        jsonb
    )
OWNER TO compliance_api_owner;


ALTER FUNCTION
    compliance.upsert_ticket_record(
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        boolean,
        jsonb
    )
OWNER TO compliance_api_owner;


ALTER FUNCTION
    compliance.update_ticket_record(
        text,
        text,
        text,
        text,
        boolean,
        text,
        text,
        text,
        jsonb
    )
OWNER TO compliance_api_owner;


REVOKE CREATE ON SCHEMA compliance
    FROM compliance_api_owner;


ALTER FUNCTION
    compliance.create_remediation_attempt(
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        integer,
        bigint,
        jsonb
    )
SECURITY DEFINER;


ALTER FUNCTION
    compliance.create_remediation_attempt(
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        integer,
        bigint,
        jsonb
    )
SET search_path = pg_catalog, compliance;


ALTER FUNCTION
    compliance.record_remediation_approval(
        text,
        text,
        text,
        jsonb
    )
SECURITY DEFINER;


ALTER FUNCTION
    compliance.record_remediation_approval(
        text,
        text,
        text,
        jsonb
    )
SET search_path = pg_catalog, compliance;


ALTER FUNCTION
    compliance.transition_remediation_attempt(
        text,
        text,
        text,
        bigint,
        bigint,
        bigint,
        text,
        text,
        text,
        jsonb
    )
SECURITY DEFINER;


ALTER FUNCTION
    compliance.transition_remediation_attempt(
        text,
        text,
        text,
        bigint,
        bigint,
        bigint,
        text,
        text,
        text,
        jsonb
    )
SET search_path = pg_catalog, compliance;


ALTER FUNCTION
    compliance.upsert_ticket_record(
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        boolean,
        jsonb
    )
SECURITY DEFINER;


ALTER FUNCTION
    compliance.upsert_ticket_record(
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        boolean,
        jsonb
    )
SET search_path = pg_catalog, compliance;


ALTER FUNCTION
    compliance.update_ticket_record(
        text,
        text,
        text,
        text,
        boolean,
        text,
        text,
        text,
        jsonb
    )
SECURITY DEFINER;


ALTER FUNCTION
    compliance.update_ticket_record(
        text,
        text,
        text,
        text,
        boolean,
        text,
        text,
        text,
        jsonb
    )
SET search_path = pg_catalog, compliance;


-- Remediation worker capability.

GRANT EXECUTE ON FUNCTION
    compliance.create_remediation_attempt(
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        integer,
        bigint,
        jsonb
    )
TO compliance_remediation;


GRANT EXECUTE ON FUNCTION
    compliance.transition_remediation_attempt(
        text,
        text,
        text,
        bigint,
        bigint,
        bigint,
        text,
        text,
        text,
        jsonb
    )
TO compliance_remediation;


-- Ticketing capability owns ticket synchronization and approval events.

GRANT EXECUTE ON FUNCTION
    compliance.upsert_ticket_record(
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        boolean,
        jsonb
    )
TO compliance_ticketing;


GRANT EXECUTE ON FUNCTION
    compliance.update_ticket_record(
        text,
        text,
        text,
        text,
        boolean,
        text,
        text,
        text,
        jsonb
    )
TO compliance_ticketing;


GRANT EXECUTE ON FUNCTION
    compliance.record_remediation_approval(
        text,
        text,
        text,
        jsonb
    )
TO compliance_ticketing;


-- Explicit cross-capability restrictions.

REVOKE EXECUTE ON FUNCTION
    compliance.record_remediation_approval(
        text,
        text,
        text,
        jsonb
    )
FROM compliance_remediation;


REVOKE EXECUTE ON FUNCTION
    compliance.create_remediation_attempt(
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        integer,
        bigint,
        jsonb
    )
FROM compliance_ticketing;


REVOKE EXECUTE ON FUNCTION
    compliance.transition_remediation_attempt(
        text,
        text,
        text,
        bigint,
        bigint,
        bigint,
        text,
        text,
        text,
        jsonb
    )
FROM compliance_ticketing;


COMMENT ON TABLE compliance.remediation_attempts IS
    'Durable V3 remediation and targeted recheck lifecycle ledger';


COMMENT ON TABLE compliance.ticket_records IS
    'Durable external ticket mapping and approval lifecycle';


COMMENT ON FUNCTION
    compliance.create_remediation_attempt(
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        integer,
        bigint,
        jsonb
    )
IS
    'Creates an idempotent remediation attempt after validating immutable target, finding/device/control, and durable remediation-policy correlation';


COMMENT ON FUNCTION
    compliance.record_remediation_approval(
        text,
        text,
        text,
        jsonb
    )
IS
    'Records an idempotent approval, rejection, or expiry decision for approval-gated remediation';


COMMENT ON FUNCTION
    compliance.transition_remediation_attempt(
        text,
        text,
        text,
        bigint,
        bigint,
        bigint,
        text,
        text,
        text,
        jsonb
    )
IS
    'Performs optimistic, validated remediation lifecycle transitions without resolving the compliance finding';


COMMENT ON FUNCTION
    compliance.upsert_ticket_record(
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        text,
        boolean,
        jsonb
    )
IS
    'Creates or returns the active ticket mapping for a persistent finding using finding/provider/type deduplication';


COMMENT ON FUNCTION
    compliance.update_ticket_record(
        text,
        text,
        text,
        text,
        boolean,
        text,
        text,
        text,
        jsonb
    )
IS
    'Updates external ticket state through an optimistic state boundary';


COMMIT;
