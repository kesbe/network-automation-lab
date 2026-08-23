BEGIN;

-- ===========================================================================
-- Durable transport-event idempotency
--
-- This ledger is intentionally separate from compliance.finding_events.
-- finding_events records finding lifecycle transitions.
-- transport_events controls Kafka -> EDA -> AWX delivery exactly-once intent.
-- ===========================================================================

CREATE TABLE compliance.transport_events (
    event_id text PRIMARY KEY,
    event_type text NOT NULL,
    compliance_run_id text NOT NULL,

    state text NOT NULL,

    first_seen_at timestamp with time zone
        NOT NULL DEFAULT now(),

    last_seen_at timestamp with time zone
        NOT NULL DEFAULT now(),

    claimed_at timestamp with time zone,
    lease_expires_at timestamp with time zone,

    completed_at timestamp with time zone,
    failed_at timestamp with time zone,

    attempt_count integer
        NOT NULL DEFAULT 1,

    duplicate_count integer
        NOT NULL DEFAULT 0,

    claim_workflow_job_id bigint NOT NULL,

    last_error text,

    details jsonb
        NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT transport_events_event_id_nonempty
        CHECK (btrim(event_id) <> ''),

    CONSTRAINT transport_events_event_type_nonempty
        CHECK (btrim(event_type) <> ''),

    CONSTRAINT transport_events_run_id_nonempty
        CHECK (btrim(compliance_run_id) <> ''),

    CONSTRAINT transport_events_state
        CHECK (
            state IN (
                'CLAIMED',
                'COMPLETED',
                'FAILED'
            )
        ),

    CONSTRAINT transport_events_attempt_count_positive
        CHECK (attempt_count >= 1),

    CONSTRAINT transport_events_duplicate_count_nonnegative
        CHECK (duplicate_count >= 0),

    CONSTRAINT transport_events_workflow_job_positive
        CHECK (claim_workflow_job_id > 0),

    CONSTRAINT transport_events_state_timestamps
        CHECK (
            (
                state = 'CLAIMED'
                AND claimed_at IS NOT NULL
                AND lease_expires_at IS NOT NULL
                AND completed_at IS NULL
                AND failed_at IS NULL
            )
            OR
            (
                state = 'COMPLETED'
                AND claimed_at IS NOT NULL
                AND lease_expires_at IS NULL
                AND completed_at IS NOT NULL
                AND failed_at IS NULL
            )
            OR
            (
                state = 'FAILED'
                AND claimed_at IS NOT NULL
                AND lease_expires_at IS NULL
                AND completed_at IS NULL
                AND failed_at IS NOT NULL
            )
        ),

    CONSTRAINT transport_events_logical_event_unique
        UNIQUE (
            event_type,
            compliance_run_id
        )
);

CREATE INDEX idx_transport_events_state
    ON compliance.transport_events (
        state
    );

CREATE INDEX idx_transport_events_lease
    ON compliance.transport_events (
        lease_expires_at
    )
    WHERE state = 'CLAIMED';

CREATE INDEX idx_transport_events_run
    ON compliance.transport_events (
        compliance_run_id
    );


-- ===========================================================================
-- Internal API owner access
--
-- compliance_ingest receives no direct table access.
-- ===========================================================================

GRANT SELECT, INSERT, UPDATE
    ON compliance.transport_events
    TO compliance_api_owner;

REVOKE ALL PRIVILEGES
    ON compliance.transport_events
    FROM compliance_ingest;


-- ===========================================================================
-- claim_transport_event()
--
-- CLAIMED_NEW
--     First observation of this event.
--
-- DUPLICATE_INFLIGHT
--     Event is already owned by a live lease.
--
-- DUPLICATE_COMPLETED
--     Event was already processed successfully.
--
-- STALE_CLAIM
--     Lease expired. This function deliberately does NOT transfer ownership.
--     A reconciler must verify the prior AWX workflow before reclaiming it.
--
-- CLAIMED_RETRY
--     Previous wrapper explicitly recorded FAILED, therefore ownership can
--     safely move to the new wrapper.
-- ===========================================================================

CREATE FUNCTION compliance.claim_transport_event(
    p_event_id text,
    p_event_type text,
    p_compliance_run_id text,
    p_workflow_job_id bigint,
    p_lease_seconds integer,
    p_details jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    v_now timestamp with time zone;
    v_lease timestamp with time zone;
    v_row compliance.transport_events%ROWTYPE;
BEGIN
    IF p_event_id IS NULL
       OR btrim(p_event_id) = '' THEN
        RAISE EXCEPTION
            'event_id must be non-empty'
            USING ERRCODE = '22023';
    END IF;

    IF p_event_type IS NULL
       OR btrim(p_event_type) = '' THEN
        RAISE EXCEPTION
            'event_type must be non-empty'
            USING ERRCODE = '22023';
    END IF;

    IF p_compliance_run_id IS NULL
       OR btrim(p_compliance_run_id) = '' THEN
        RAISE EXCEPTION
            'compliance_run_id must be non-empty'
            USING ERRCODE = '22023';
    END IF;

    IF p_workflow_job_id IS NULL
       OR p_workflow_job_id < 1 THEN
        RAISE EXCEPTION
            'workflow_job_id must be greater than zero'
            USING ERRCODE = '22023';
    END IF;

    IF p_lease_seconds IS NULL
       OR p_lease_seconds < 60
       OR p_lease_seconds > 86400 THEN
        RAISE EXCEPTION
            'lease_seconds must be between 60 and 86400'
            USING ERRCODE = '22023';
    END IF;

    IF p_details IS NOT NULL
       AND jsonb_typeof(p_details) <> 'object' THEN
        RAISE EXCEPTION
            'details must be a JSON object'
            USING ERRCODE = '22023';
    END IF;

    v_now := clock_timestamp();

    v_lease :=
        v_now
        + make_interval(
            secs => p_lease_seconds
        );

    INSERT INTO compliance.transport_events (
        event_id,
        event_type,
        compliance_run_id,
        state,
        first_seen_at,
        last_seen_at,
        claimed_at,
        lease_expires_at,
        attempt_count,
        duplicate_count,
        claim_workflow_job_id,
        details
    )
    VALUES (
        p_event_id,
        p_event_type,
        p_compliance_run_id,
        'CLAIMED',
        v_now,
        v_now,
        v_now,
        v_lease,
        1,
        0,
        p_workflow_job_id,
        COALESCE(
            p_details,
            '{}'::jsonb
        )
    )
    ON CONFLICT
    DO NOTHING;

    IF FOUND THEN
        RETURN jsonb_build_object(
            'decision',
            'CLAIMED_NEW',
            'event_id',
            p_event_id,
            'state',
            'CLAIMED',
            'attempt_count',
            1,
            'duplicate_count',
            0,
            'claim_workflow_job_id',
            p_workflow_job_id,
            'lease_expires_at',
            v_lease
        );
    END IF;

    SELECT *
    INTO v_row
    FROM compliance.transport_events
    WHERE event_id = p_event_id
    FOR UPDATE;

    IF NOT FOUND THEN
        -- The INSERT may have been rejected by the secondary
        -- logical-event uniqueness boundary rather than by event_id.
        --
        -- This deliberately remains fail-closed. A producer must never
        -- represent one logical compliance event with multiple event IDs.

        SELECT *
        INTO v_row
        FROM compliance.transport_events
        WHERE event_type = p_event_type
          AND compliance_run_id = p_compliance_run_id
        FOR UPDATE;

        IF FOUND THEN
            RAISE EXCEPTION
                'logical event identity conflict: existing event_id %, received event_id %',
                v_row.event_id,
                p_event_id
                USING ERRCODE = '23505';
        END IF;

        RAISE EXCEPTION
            'transport event conflict could not be resolved for event_id %',
            p_event_id
            USING ERRCODE = '23505';
    END IF;

    IF v_row.event_type <> p_event_type
       OR v_row.compliance_run_id <> p_compliance_run_id THEN
        RAISE EXCEPTION
            'event_id % correlation mismatch',
            p_event_id
            USING ERRCODE = '23505';
    END IF;

    IF v_row.state = 'COMPLETED' THEN
        UPDATE compliance.transport_events
        SET
            last_seen_at = v_now,
            duplicate_count = duplicate_count + 1
        WHERE event_id = p_event_id
        RETURNING *
        INTO v_row;

        RETURN jsonb_build_object(
            'decision',
            'DUPLICATE_COMPLETED',
            'event_id',
            v_row.event_id,
            'state',
            v_row.state,
            'attempt_count',
            v_row.attempt_count,
            'duplicate_count',
            v_row.duplicate_count,
            'claim_workflow_job_id',
            v_row.claim_workflow_job_id
        );
    END IF;

    IF v_row.state = 'CLAIMED' THEN
        UPDATE compliance.transport_events
        SET
            last_seen_at = v_now,
            duplicate_count = duplicate_count + 1
        WHERE event_id = p_event_id
        RETURNING *
        INTO v_row;

        IF v_row.lease_expires_at > v_now THEN
            RETURN jsonb_build_object(
                'decision',
                'DUPLICATE_INFLIGHT',
                'event_id',
                v_row.event_id,
                'state',
                v_row.state,
                'attempt_count',
                v_row.attempt_count,
                'duplicate_count',
                v_row.duplicate_count,
                'claim_workflow_job_id',
                v_row.claim_workflow_job_id,
                'lease_expires_at',
                v_row.lease_expires_at
            );
        END IF;

        RETURN jsonb_build_object(
            'decision',
            'STALE_CLAIM',
            'event_id',
            v_row.event_id,
            'state',
            v_row.state,
            'attempt_count',
            v_row.attempt_count,
            'duplicate_count',
            v_row.duplicate_count,
            'claim_workflow_job_id',
            v_row.claim_workflow_job_id,
            'lease_expires_at',
            v_row.lease_expires_at
        );
    END IF;

    IF v_row.state = 'FAILED' THEN
        UPDATE compliance.transport_events
        SET
            state = 'CLAIMED',
            last_seen_at = v_now,
            claimed_at = v_now,
            lease_expires_at = v_lease,
            completed_at = NULL,
            failed_at = NULL,
            attempt_count = attempt_count + 1,
            duplicate_count = duplicate_count + 1,
            claim_workflow_job_id = p_workflow_job_id,
            last_error = NULL
        WHERE event_id = p_event_id
        RETURNING *
        INTO v_row;

        RETURN jsonb_build_object(
            'decision',
            'CLAIMED_RETRY',
            'event_id',
            v_row.event_id,
            'state',
            v_row.state,
            'attempt_count',
            v_row.attempt_count,
            'duplicate_count',
            v_row.duplicate_count,
            'claim_workflow_job_id',
            v_row.claim_workflow_job_id,
            'lease_expires_at',
            v_row.lease_expires_at
        );
    END IF;

    RAISE EXCEPTION
        'unsupported transport event state %',
        v_row.state
        USING ERRCODE = '22023';
END;
$$;


-- ===========================================================================
-- complete_transport_event()
--
-- Idempotent when called again by the same owning workflow.
-- ===========================================================================

CREATE FUNCTION compliance.complete_transport_event(
    p_event_id text,
    p_workflow_job_id bigint
)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    v_now timestamp with time zone;
    v_row compliance.transport_events%ROWTYPE;
BEGIN
    v_now := clock_timestamp();

    SELECT *
    INTO v_row
    FROM compliance.transport_events
    WHERE event_id = p_event_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'transport event % does not exist',
            p_event_id
            USING ERRCODE = '22023';
    END IF;

    IF v_row.claim_workflow_job_id <> p_workflow_job_id THEN
        RAISE EXCEPTION
            'transport event % ownership mismatch',
            p_event_id
            USING ERRCODE = '22023';
    END IF;

    IF v_row.state = 'COMPLETED' THEN
        RETURN jsonb_build_object(
            'decision',
            'ALREADY_COMPLETED',
            'event_id',
            v_row.event_id,
            'state',
            v_row.state
        );
    END IF;

    IF v_row.state <> 'CLAIMED' THEN
        RAISE EXCEPTION
            'transport event % cannot complete from state %',
            p_event_id,
            v_row.state
            USING ERRCODE = '22023';
    END IF;

    UPDATE compliance.transport_events
    SET
        state = 'COMPLETED',
        last_seen_at = v_now,
        lease_expires_at = NULL,
        completed_at = v_now,
        failed_at = NULL,
        last_error = NULL
    WHERE event_id = p_event_id
    RETURNING *
    INTO v_row;

    RETURN jsonb_build_object(
        'decision',
        'COMPLETED',
        'event_id',
        v_row.event_id,
        'state',
        v_row.state,
        'attempt_count',
        v_row.attempt_count,
        'duplicate_count',
        v_row.duplicate_count,
        'claim_workflow_job_id',
        v_row.claim_workflow_job_id,
        'completed_at',
        v_row.completed_at
    );
END;
$$;


-- ===========================================================================
-- fail_transport_event()
--
-- Explicit wrapper failure makes the event retryable on its next delivery.
-- ===========================================================================

CREATE FUNCTION compliance.fail_transport_event(
    p_event_id text,
    p_workflow_job_id bigint,
    p_error text
)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    v_now timestamp with time zone;
    v_row compliance.transport_events%ROWTYPE;
BEGIN
    v_now := clock_timestamp();

    SELECT *
    INTO v_row
    FROM compliance.transport_events
    WHERE event_id = p_event_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'transport event % does not exist',
            p_event_id
            USING ERRCODE = '22023';
    END IF;

    IF v_row.claim_workflow_job_id <> p_workflow_job_id THEN
        RAISE EXCEPTION
            'transport event % ownership mismatch',
            p_event_id
            USING ERRCODE = '22023';
    END IF;

    IF v_row.state = 'FAILED' THEN
        RETURN jsonb_build_object(
            'decision',
            'ALREADY_FAILED',
            'event_id',
            v_row.event_id,
            'state',
            v_row.state
        );
    END IF;

    IF v_row.state = 'COMPLETED' THEN
        RAISE EXCEPTION
            'completed transport event % cannot be failed',
            p_event_id
            USING ERRCODE = '22023';
    END IF;

    UPDATE compliance.transport_events
    SET
        state = 'FAILED',
        last_seen_at = v_now,
        lease_expires_at = NULL,
        completed_at = NULL,
        failed_at = v_now,
        last_error = NULLIF(
            btrim(
                COALESCE(
                    p_error,
                    ''
                )
            ),
            ''
        )
    WHERE event_id = p_event_id
    RETURNING *
    INTO v_row;

    RETURN jsonb_build_object(
        'decision',
        'FAILED',
        'event_id',
        v_row.event_id,
        'state',
        v_row.state,
        'attempt_count',
        v_row.attempt_count,
        'duplicate_count',
        v_row.duplicate_count,
        'claim_workflow_job_id',
        v_row.claim_workflow_job_id,
        'failed_at',
        v_row.failed_at
    );
END;
$$;


-- ===========================================================================
-- reclaim_stale_transport_event()
--
-- NOT exposed to compliance_ingest.
--
-- A future reconciliation component must first inspect the previous AWX
-- wrapper job and prove that ownership can safely move.
-- ===========================================================================

CREATE FUNCTION compliance.reclaim_stale_transport_event(
    p_event_id text,
    p_expected_workflow_job_id bigint,
    p_new_workflow_job_id bigint,
    p_lease_seconds integer,
    p_reason text
)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    v_now timestamp with time zone;
    v_lease timestamp with time zone;
    v_row compliance.transport_events%ROWTYPE;
BEGIN
    IF p_expected_workflow_job_id IS NULL
       OR p_expected_workflow_job_id < 1
       OR p_new_workflow_job_id IS NULL
       OR p_new_workflow_job_id < 1 THEN
        RAISE EXCEPTION
            'workflow job ids must be greater than zero'
            USING ERRCODE = '22023';
    END IF;

    IF p_lease_seconds IS NULL
       OR p_lease_seconds < 60
       OR p_lease_seconds > 86400 THEN
        RAISE EXCEPTION
            'lease_seconds must be between 60 and 86400'
            USING ERRCODE = '22023';
    END IF;

    v_now := clock_timestamp();

    v_lease :=
        v_now
        + make_interval(
            secs => p_lease_seconds
        );

    SELECT *
    INTO v_row
    FROM compliance.transport_events
    WHERE event_id = p_event_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'transport event % does not exist',
            p_event_id
            USING ERRCODE = '22023';
    END IF;

    IF v_row.state <> 'CLAIMED' THEN
        RAISE EXCEPTION
            'transport event % is not CLAIMED',
            p_event_id
            USING ERRCODE = '22023';
    END IF;

    IF v_row.claim_workflow_job_id
       <> p_expected_workflow_job_id THEN
        RAISE EXCEPTION
            'transport event % prior ownership mismatch',
            p_event_id
            USING ERRCODE = '22023';
    END IF;

    IF v_row.lease_expires_at > v_now THEN
        RAISE EXCEPTION
            'transport event % lease has not expired',
            p_event_id
            USING ERRCODE = '22023';
    END IF;

    UPDATE compliance.transport_events
    SET
        last_seen_at = v_now,
        claimed_at = v_now,
        lease_expires_at = v_lease,
        attempt_count = attempt_count + 1,
        claim_workflow_job_id = p_new_workflow_job_id,
        last_error =
            'STALE_RECLAIM: '
            || COALESCE(
                NULLIF(
                    btrim(p_reason),
                    ''
                ),
                'reconciled'
            )
    WHERE event_id = p_event_id
    RETURNING *
    INTO v_row;

    RETURN jsonb_build_object(
        'decision',
        'CLAIMED_RECONCILED',
        'event_id',
        v_row.event_id,
        'state',
        v_row.state,
        'attempt_count',
        v_row.attempt_count,
        'duplicate_count',
        v_row.duplicate_count,
        'claim_workflow_job_id',
        v_row.claim_workflow_job_id,
        'lease_expires_at',
        v_row.lease_expires_at
    );
END;
$$;


-- ===========================================================================
-- Function security
-- ===========================================================================

REVOKE EXECUTE ON FUNCTION
    compliance.claim_transport_event(
        text,
        text,
        text,
        bigint,
        integer,
        jsonb
    )
FROM PUBLIC;

REVOKE EXECUTE ON FUNCTION
    compliance.complete_transport_event(
        text,
        bigint
    )
FROM PUBLIC;

REVOKE EXECUTE ON FUNCTION
    compliance.fail_transport_event(
        text,
        bigint,
        text
    )
FROM PUBLIC;

REVOKE EXECUTE ON FUNCTION
    compliance.reclaim_stale_transport_event(
        text,
        bigint,
        bigint,
        integer,
        text
    )
FROM PUBLIC;


-- Temporarily permit ownership transfer, following migration 004.

GRANT CREATE ON SCHEMA compliance
    TO compliance_api_owner;

ALTER FUNCTION compliance.claim_transport_event(
    text,
    text,
    text,
    bigint,
    integer,
    jsonb
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.complete_transport_event(
    text,
    bigint
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.fail_transport_event(
    text,
    bigint,
    text
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.reclaim_stale_transport_event(
    text,
    bigint,
    bigint,
    integer,
    text
)
OWNER TO compliance_api_owner;

REVOKE CREATE ON SCHEMA compliance
    FROM compliance_api_owner;


-- SECURITY DEFINER with fixed object-resolution boundary.

ALTER FUNCTION compliance.claim_transport_event(
    text,
    text,
    text,
    bigint,
    integer,
    jsonb
)
SECURITY DEFINER;

ALTER FUNCTION compliance.claim_transport_event(
    text,
    text,
    text,
    bigint,
    integer,
    jsonb
)
SET search_path = pg_catalog, compliance;

ALTER FUNCTION compliance.complete_transport_event(
    text,
    bigint
)
SECURITY DEFINER;

ALTER FUNCTION compliance.complete_transport_event(
    text,
    bigint
)
SET search_path = pg_catalog, compliance;

ALTER FUNCTION compliance.fail_transport_event(
    text,
    bigint,
    text
)
SECURITY DEFINER;

ALTER FUNCTION compliance.fail_transport_event(
    text,
    bigint,
    text
)
SET search_path = pg_catalog, compliance;

ALTER FUNCTION compliance.reclaim_stale_transport_event(
    text,
    bigint,
    bigint,
    integer,
    text
)
SECURITY DEFINER;

ALTER FUNCTION compliance.reclaim_stale_transport_event(
    text,
    bigint,
    bigint,
    integer,
    text
)
SET search_path = pg_catalog, compliance;


-- Application role receives only controlled transport APIs.

GRANT EXECUTE ON FUNCTION
    compliance.claim_transport_event(
        text,
        text,
        text,
        bigint,
        integer,
        jsonb
    )
TO compliance_ingest;

GRANT EXECUTE ON FUNCTION
    compliance.complete_transport_event(
        text,
        bigint
    )
TO compliance_ingest;

GRANT EXECUTE ON FUNCTION
    compliance.fail_transport_event(
        text,
        bigint,
        text
    )
TO compliance_ingest;


-- Stale claim reconciliation remains deliberately inaccessible to AWX.

REVOKE EXECUTE ON FUNCTION
    compliance.reclaim_stale_transport_event(
        text,
        bigint,
        bigint,
        integer,
        text
    )
FROM compliance_ingest;


COMMENT ON TABLE compliance.transport_events IS
    'Durable Kafka-to-AWX transport idempotency and processing ledger';

COMMENT ON FUNCTION compliance.claim_transport_event(
    text,
    text,
    text,
    bigint,
    integer,
    jsonb
) IS
    'Atomically claims a compliance transport event or returns its duplicate state';

COMMENT ON FUNCTION compliance.complete_transport_event(
    text,
    bigint
) IS
    'Marks an owned transport event successfully completed';

COMMENT ON FUNCTION compliance.fail_transport_event(
    text,
    bigint,
    text
) IS
    'Marks an owned transport event failed and eligible for retry';

COMMENT ON FUNCTION compliance.reclaim_stale_transport_event(
    text,
    bigint,
    bigint,
    integer,
    text
) IS
    'Transfers an expired claim only after external AWX reconciliation';

COMMIT;
