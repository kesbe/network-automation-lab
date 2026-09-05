-- ============================================================================
-- 016_ticketing_lifecycle_transport.sql
--
-- Provider-neutral ticketing lifecycle publication and consumer-receipt
-- idempotency.
--
-- This migration deliberately does NOT modify:
--
--   compliance.transport_events
--   compliance.v3_activation_sources
--   existing V3 remediation transport roles/functions
--
-- Source lifecycle identity:
--
--   compliance.finding_events.event_id
--
-- Ticket lifecycle:
--
--   DETECTED
--   SEEN_AGAIN
--   REOPENED
--   RESOLVED
--
-- Security:
--
-- * application roles are NOLOGIN / NOINHERIT
-- * no direct application-role table DML
-- * all application access is through SECURITY DEFINER functions
-- * PUBLIC EXECUTE is revoked
-- * Zammad runtime wrappers are provider-restricted
-- ============================================================================

BEGIN;


-- ============================================================================
-- 1. NARROW APPLICATION ROLES
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_roles
        WHERE rolname = 'compliance_lifecycle_publisher'
    ) THEN
        CREATE ROLE compliance_lifecycle_publisher
            NOLOGIN
            NOINHERIT;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_roles
        WHERE rolname = 'compliance_zammad_runtime_api'
    ) THEN
        CREATE ROLE compliance_zammad_runtime_api
            NOLOGIN
            NOINHERIT;
    END IF;
END;
$$;


-- ============================================================================
-- 2. LIFECYCLE EVENT PUBLICATION LEDGER
-- ============================================================================

CREATE TABLE compliance.lifecycle_event_publications (
    topic                   TEXT NOT NULL,
    source_event_id         BIGINT NOT NULL,
    source_finding_id       TEXT NOT NULL,
    lifecycle_event_type    TEXT NOT NULL,

    state                   TEXT NOT NULL,

    publisher_instance_id   TEXT NOT NULL,

    attempt_count           INTEGER NOT NULL
                            DEFAULT 1,

    duplicate_count         INTEGER NOT NULL
                            DEFAULT 0,

    claimed_at              TIMESTAMPTZ NOT NULL,
    lease_expires_at        TIMESTAMPTZ,

    completed_at            TIMESTAMPTZ,
    failed_at               TIMESTAMPTZ,

    last_error              TEXT,

    details                 JSONB NOT NULL
                            DEFAULT '{}'::jsonb,

    PRIMARY KEY (
        topic,
        source_event_id
    ),

    CONSTRAINT fk_lifecycle_publication_event
        FOREIGN KEY (source_event_id)
        REFERENCES compliance.finding_events(event_id),

    CONSTRAINT fk_lifecycle_publication_finding
        FOREIGN KEY (source_finding_id)
        REFERENCES compliance.compliance_findings(finding_id),

    CONSTRAINT lifecycle_publication_topic_nonempty
        CHECK (
            btrim(topic) <> ''
        ),

    CONSTRAINT lifecycle_publication_instance_nonempty
        CHECK (
            btrim(publisher_instance_id) <> ''
        ),

    CONSTRAINT lifecycle_publication_event_type_allowed
        CHECK (
            lifecycle_event_type IN (
                'DETECTED',
                'SEEN_AGAIN',
                'REOPENED',
                'RESOLVED'
            )
        ),

    CONSTRAINT lifecycle_publication_state_allowed
        CHECK (
            state IN (
                'CLAIMED',
                'COMPLETED',
                'FAILED'
            )
        ),

    CONSTRAINT lifecycle_publication_attempt_positive
        CHECK (
            attempt_count >= 1
        ),

    CONSTRAINT lifecycle_publication_duplicate_nonnegative
        CHECK (
            duplicate_count >= 0
        ),

    CONSTRAINT lifecycle_publication_state_timestamps
        CHECK (
            (
                state = 'CLAIMED'
                AND lease_expires_at IS NOT NULL
                AND completed_at IS NULL
                AND failed_at IS NULL
            )
            OR
            (
                state = 'COMPLETED'
                AND lease_expires_at IS NULL
                AND completed_at IS NOT NULL
                AND failed_at IS NULL
            )
            OR
            (
                state = 'FAILED'
                AND lease_expires_at IS NULL
                AND completed_at IS NULL
                AND failed_at IS NOT NULL
            )
        )
);


CREATE INDEX idx_lifecycle_publication_state
    ON compliance.lifecycle_event_publications (
        state,
        source_event_id
    );


CREATE INDEX idx_lifecycle_publication_lease
    ON compliance.lifecycle_event_publications (
        lease_expires_at
    )
    WHERE state = 'CLAIMED';


CREATE INDEX idx_lifecycle_publication_finding
    ON compliance.lifecycle_event_publications (
        source_finding_id,
        source_event_id
    );


-- ============================================================================
-- 3. TICKET EVENT RECEIPT LEDGER
-- ============================================================================

CREATE TABLE compliance.ticket_event_receipts (
    provider                 TEXT NOT NULL,
    source_event_id          BIGINT NOT NULL,
    source_finding_id        TEXT NOT NULL,
    lifecycle_event_type     TEXT NOT NULL,

    ticket_record_id         TEXT,

    state                    TEXT NOT NULL,

    consumer_instance_id     TEXT NOT NULL,

    attempt_count            INTEGER NOT NULL
                             DEFAULT 1,

    duplicate_count          INTEGER NOT NULL
                             DEFAULT 0,

    claimed_at               TIMESTAMPTZ NOT NULL,
    lease_expires_at         TIMESTAMPTZ,

    completed_at             TIMESTAMPTZ,
    failed_at                TIMESTAMPTZ,

    last_error               TEXT,

    details                  JSONB NOT NULL
                             DEFAULT '{}'::jsonb,

    PRIMARY KEY (
        provider,
        source_event_id
    ),

    CONSTRAINT fk_ticket_receipt_event
        FOREIGN KEY (source_event_id)
        REFERENCES compliance.finding_events(event_id),

    CONSTRAINT fk_ticket_receipt_finding
        FOREIGN KEY (source_finding_id)
        REFERENCES compliance.compliance_findings(finding_id),

    CONSTRAINT fk_ticket_receipt_ticket
        FOREIGN KEY (ticket_record_id)
        REFERENCES compliance.ticket_records(ticket_record_id),

    CONSTRAINT ticket_receipt_provider_nonempty
        CHECK (
            btrim(provider) <> ''
        ),

    CONSTRAINT ticket_receipt_instance_nonempty
        CHECK (
            btrim(consumer_instance_id) <> ''
        ),

    CONSTRAINT ticket_receipt_event_type_allowed
        CHECK (
            lifecycle_event_type IN (
                'DETECTED',
                'SEEN_AGAIN',
                'REOPENED',
                'RESOLVED'
            )
        ),

    CONSTRAINT ticket_receipt_state_allowed
        CHECK (
            state IN (
                'CLAIMED',
                'COMPLETED',
                'FAILED'
            )
        ),

    CONSTRAINT ticket_receipt_attempt_positive
        CHECK (
            attempt_count >= 1
        ),

    CONSTRAINT ticket_receipt_duplicate_nonnegative
        CHECK (
            duplicate_count >= 0
        ),

    CONSTRAINT ticket_receipt_state_timestamps
        CHECK (
            (
                state = 'CLAIMED'
                AND lease_expires_at IS NOT NULL
                AND completed_at IS NULL
                AND failed_at IS NULL
            )
            OR
            (
                state = 'COMPLETED'
                AND lease_expires_at IS NULL
                AND completed_at IS NOT NULL
                AND failed_at IS NULL
            )
            OR
            (
                state = 'FAILED'
                AND lease_expires_at IS NULL
                AND completed_at IS NULL
                AND failed_at IS NOT NULL
            )
        )
);


CREATE INDEX idx_ticket_receipt_state
    ON compliance.ticket_event_receipts (
        provider,
        state,
        source_event_id
    );


CREATE INDEX idx_ticket_receipt_lease
    ON compliance.ticket_event_receipts (
        lease_expires_at
    )
    WHERE state = 'CLAIMED';


CREATE INDEX idx_ticket_receipt_finding
    ON compliance.ticket_event_receipts (
        provider,
        source_finding_id,
        source_event_id
    );


-- ============================================================================
-- 4. OWNER BOUNDARY
-- ============================================================================

ALTER TABLE compliance.lifecycle_event_publications
    OWNER TO compliance_api_owner;

ALTER TABLE compliance.ticket_event_receipts
    OWNER TO compliance_api_owner;


-- ============================================================================
-- 5. READ UNPUBLISHED TICKET-REQUIRED LIFECYCLE EVENTS
--
-- No high-water cursor is used.
--
-- A source event remains readable until its publication ledger row reaches
-- COMPLETED for the requested topic.
-- ============================================================================

CREATE FUNCTION compliance.read_unpublished_ticket_lifecycle_events(
    p_topic TEXT,
    p_limit INTEGER DEFAULT 100
)
RETURNS TABLE (
    source_event_id        BIGINT,
    source_finding_id      TEXT,
    run_id                 TEXT,
    lifecycle_event_type   TEXT,
    event_time             TIMESTAMPTZ,
    old_status             TEXT,
    new_status             TEXT,
    event_details          JSONB,
    finding_snapshot       JSONB
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, compliance
AS $$
BEGIN
    IF p_topic IS NULL
       OR btrim(p_topic) = ''
    THEN
        RAISE EXCEPTION
            'topic must not be empty';
    END IF;

    IF p_limit IS NULL
       OR p_limit < 1
       OR p_limit > 1000
    THEN
        RAISE EXCEPTION
            'limit must be between 1 and 1000';
    END IF;

    RETURN QUERY
    SELECT
        fe.event_id,
        fe.finding_id,
        fe.run_id,
        fe.event_type,
        fe.event_time,
        fe.old_status,
        fe.new_status,
        fe.details,

        jsonb_build_object(
            'finding_id',
            cf.finding_id,
            'finding_fingerprint',
            cf.finding_fingerprint,
            'device',
            cf.device,
            'policy_id',
            cf.policy_id,
            'control',
            cf.control,
            'finding_scope',
            cf.finding_scope,
            'category',
            cf.category,
            'severity',
            cf.severity,
            'ticket_required',
            cf.ticket_required,
            'owner',
            cf.owner,
            'status',
            cf.status,
            'first_seen',
            cf.first_seen,
            'last_seen',
            cf.last_seen,
            'resolved_at',
            cf.resolved_at,
            'remediation_supported',
            cf.remediation_supported,
            'remediation_mode',
            cf.remediation_mode,
            'remediation_risk',
            cf.remediation_risk,
            'expected',
            cf.expected,
            'current_actual',
            cf.current_actual
        )

    FROM compliance.finding_events AS fe

    JOIN compliance.compliance_findings AS cf
      ON cf.finding_id = fe.finding_id

    LEFT JOIN compliance.lifecycle_event_publications AS pub
      ON pub.topic = p_topic
     AND pub.source_event_id = fe.event_id

    WHERE fe.event_type IN (
        'DETECTED',
        'SEEN_AGAIN',
        'REOPENED',
        'RESOLVED'
    )

      AND cf.ticket_required

      AND (
          pub.source_event_id IS NULL
          OR pub.state <> 'COMPLETED'
      )

    ORDER BY fe.event_id

    LIMIT p_limit;
END;
$$;


-- ============================================================================
-- 6. CLAIM LIFECYCLE PUBLICATION
-- ============================================================================

CREATE FUNCTION compliance.claim_lifecycle_event_publication(
    p_topic                 TEXT,
    p_source_event_id       BIGINT,
    p_publisher_instance_id TEXT,
    p_lease_seconds         INTEGER DEFAULT 300,
    p_details               JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, compliance
AS $$
DECLARE
    v_now        TIMESTAMPTZ;
    v_lease      TIMESTAMPTZ;
    v_source     RECORD;
    v_row        compliance.lifecycle_event_publications%ROWTYPE;
BEGIN
    IF p_topic IS NULL
       OR btrim(p_topic) = ''
    THEN
        RAISE EXCEPTION
            'topic must not be empty';
    END IF;

    IF p_publisher_instance_id IS NULL
       OR btrim(p_publisher_instance_id) = ''
    THEN
        RAISE EXCEPTION
            'publisher_instance_id must not be empty';
    END IF;

    IF p_lease_seconds IS NULL
       OR p_lease_seconds < 60
       OR p_lease_seconds > 86400
    THEN
        RAISE EXCEPTION
            'lease_seconds must be between 60 and 86400';
    END IF;

    IF p_details IS NOT NULL
       AND jsonb_typeof(p_details) <> 'object'
    THEN
        RAISE EXCEPTION
            'details must be a JSON object';
    END IF;

    SELECT
        fe.finding_id,
        fe.event_type,
        cf.ticket_required
    INTO v_source
    FROM compliance.finding_events AS fe
    JOIN compliance.compliance_findings AS cf
      ON cf.finding_id = fe.finding_id
    WHERE fe.event_id = p_source_event_id
      AND fe.event_type IN (
          'DETECTED',
          'SEEN_AGAIN',
          'REOPENED',
          'RESOLVED'
      );

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'eligible lifecycle event does not exist: %',
            p_source_event_id;
    END IF;

    IF NOT v_source.ticket_required THEN
        RAISE EXCEPTION
            'finding does not require ticketing for source event %',
            p_source_event_id;
    END IF;

    v_now := clock_timestamp();

    v_lease :=
        v_now
        + make_interval(
            secs => p_lease_seconds
        );

    INSERT INTO compliance.lifecycle_event_publications (
        topic,
        source_event_id,
        source_finding_id,
        lifecycle_event_type,
        state,
        publisher_instance_id,
        attempt_count,
        duplicate_count,
        claimed_at,
        lease_expires_at,
        details
    )
    VALUES (
        p_topic,
        p_source_event_id,
        v_source.finding_id,
        v_source.event_type,
        'CLAIMED',
        p_publisher_instance_id,
        1,
        0,
        v_now,
        v_lease,
        COALESCE(
            p_details,
            '{}'::jsonb
        )
    )
    ON CONFLICT DO NOTHING;

    IF FOUND THEN
        RETURN jsonb_build_object(
            'decision',
            'CLAIMED_NEW',
            'topic',
            p_topic,
            'source_event_id',
            p_source_event_id,
            'state',
            'CLAIMED',
            'attempt_count',
            1,
            'duplicate_count',
            0,
            'publisher_instance_id',
            p_publisher_instance_id,
            'lease_expires_at',
            v_lease
        );
    END IF;

    SELECT *
    INTO v_row
    FROM compliance.lifecycle_event_publications
    WHERE topic = p_topic
      AND source_event_id = p_source_event_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'publication conflict could not be reconciled';
    END IF;

    IF v_row.source_finding_id <> v_source.finding_id
       OR v_row.lifecycle_event_type <> v_source.event_type
    THEN
        RAISE EXCEPTION
            'publication source correlation mismatch';
    END IF;

    IF v_row.state = 'COMPLETED' THEN
        UPDATE compliance.lifecycle_event_publications
        SET
            duplicate_count = duplicate_count + 1,
            details =
                details
                ||
                COALESCE(
                    p_details,
                    '{}'::jsonb
                )
        WHERE topic = p_topic
          AND source_event_id = p_source_event_id
        RETURNING *
        INTO v_row;

        RETURN jsonb_build_object(
            'decision',
            'DUPLICATE_COMPLETED',
            'topic',
            v_row.topic,
            'source_event_id',
            v_row.source_event_id,
            'state',
            v_row.state,
            'attempt_count',
            v_row.attempt_count,
            'duplicate_count',
            v_row.duplicate_count
        );
    END IF;

    IF v_row.state = 'CLAIMED'
       AND v_row.lease_expires_at > v_now
    THEN
        UPDATE compliance.lifecycle_event_publications
        SET
            duplicate_count = duplicate_count + 1
        WHERE topic = p_topic
          AND source_event_id = p_source_event_id
        RETURNING *
        INTO v_row;

        RETURN jsonb_build_object(
            'decision',
            'DUPLICATE_INFLIGHT',
            'topic',
            v_row.topic,
            'source_event_id',
            v_row.source_event_id,
            'state',
            v_row.state,
            'attempt_count',
            v_row.attempt_count,
            'duplicate_count',
            v_row.duplicate_count,
            'publisher_instance_id',
            v_row.publisher_instance_id,
            'lease_expires_at',
            v_row.lease_expires_at
        );
    END IF;

    IF v_row.state IN (
        'CLAIMED',
        'FAILED'
    ) THEN
        UPDATE compliance.lifecycle_event_publications
        SET
            state = 'CLAIMED',
            publisher_instance_id =
                p_publisher_instance_id,
            attempt_count = attempt_count + 1,
            duplicate_count = duplicate_count + 1,
            claimed_at = v_now,
            lease_expires_at = v_lease,
            completed_at = NULL,
            failed_at = NULL,
            last_error = NULL,
            details =
                details
                ||
                COALESCE(
                    p_details,
                    '{}'::jsonb
                )
        WHERE topic = p_topic
          AND source_event_id = p_source_event_id
        RETURNING *
        INTO v_row;

        RETURN jsonb_build_object(
            'decision',
            'CLAIMED_RETRY',
            'topic',
            v_row.topic,
            'source_event_id',
            v_row.source_event_id,
            'state',
            v_row.state,
            'attempt_count',
            v_row.attempt_count,
            'duplicate_count',
            v_row.duplicate_count,
            'publisher_instance_id',
            v_row.publisher_instance_id,
            'lease_expires_at',
            v_row.lease_expires_at
        );
    END IF;

    RAISE EXCEPTION
        'unsupported publication state: %',
        v_row.state;
END;
$$;


-- ============================================================================
-- 7. COMPLETE / FAIL LIFECYCLE PUBLICATION
-- ============================================================================

CREATE FUNCTION compliance.complete_lifecycle_event_publication(
    p_topic                 TEXT,
    p_source_event_id       BIGINT,
    p_publisher_instance_id TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, compliance
AS $$
DECLARE
    v_row compliance.lifecycle_event_publications%ROWTYPE;
BEGIN
    SELECT *
    INTO v_row
    FROM compliance.lifecycle_event_publications
    WHERE topic = p_topic
      AND source_event_id = p_source_event_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'publication does not exist';
    END IF;

    IF v_row.state = 'COMPLETED' THEN
        RETURN jsonb_build_object(
            'decision',
            'ALREADY_COMPLETED',
            'topic',
            v_row.topic,
            'source_event_id',
            v_row.source_event_id,
            'state',
            v_row.state
        );
    END IF;

    IF v_row.state <> 'CLAIMED' THEN
        RAISE EXCEPTION
            'publication cannot complete from state %',
            v_row.state;
    END IF;

    IF v_row.publisher_instance_id
       <> p_publisher_instance_id
    THEN
        RAISE EXCEPTION
            'publication ownership mismatch';
    END IF;

    UPDATE compliance.lifecycle_event_publications
    SET
        state = 'COMPLETED',
        lease_expires_at = NULL,
        completed_at = clock_timestamp(),
        failed_at = NULL,
        last_error = NULL
    WHERE topic = p_topic
      AND source_event_id = p_source_event_id
    RETURNING *
    INTO v_row;

    RETURN jsonb_build_object(
        'decision',
        'COMPLETED',
        'topic',
        v_row.topic,
        'source_event_id',
        v_row.source_event_id,
        'state',
        v_row.state,
        'attempt_count',
        v_row.attempt_count,
        'duplicate_count',
        v_row.duplicate_count,
        'completed_at',
        v_row.completed_at
    );
END;
$$;


CREATE FUNCTION compliance.fail_lifecycle_event_publication(
    p_topic                 TEXT,
    p_source_event_id       BIGINT,
    p_publisher_instance_id TEXT,
    p_error                 TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, compliance
AS $$
DECLARE
    v_row compliance.lifecycle_event_publications%ROWTYPE;
BEGIN
    SELECT *
    INTO v_row
    FROM compliance.lifecycle_event_publications
    WHERE topic = p_topic
      AND source_event_id = p_source_event_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'publication does not exist';
    END IF;

    IF v_row.state = 'FAILED' THEN
        RETURN jsonb_build_object(
            'decision',
            'ALREADY_FAILED',
            'topic',
            v_row.topic,
            'source_event_id',
            v_row.source_event_id,
            'state',
            v_row.state
        );
    END IF;

    IF v_row.state = 'COMPLETED' THEN
        RAISE EXCEPTION
            'completed publication cannot be failed';
    END IF;

    IF v_row.publisher_instance_id
       <> p_publisher_instance_id
    THEN
        RAISE EXCEPTION
            'publication ownership mismatch';
    END IF;

    UPDATE compliance.lifecycle_event_publications
    SET
        state = 'FAILED',
        lease_expires_at = NULL,
        completed_at = NULL,
        failed_at = clock_timestamp(),
        last_error =
            NULLIF(
                btrim(
                    COALESCE(
                        p_error,
                        ''
                    )
                ),
                ''
            )
    WHERE topic = p_topic
      AND source_event_id = p_source_event_id
    RETURNING *
    INTO v_row;

    RETURN jsonb_build_object(
        'decision',
        'FAILED',
        'topic',
        v_row.topic,
        'source_event_id',
        v_row.source_event_id,
        'state',
        v_row.state,
        'attempt_count',
        v_row.attempt_count,
        'duplicate_count',
        v_row.duplicate_count,
        'failed_at',
        v_row.failed_at
    );
END;
$$;


-- ============================================================================
-- 8. GENERIC TICKET EVENT RECEIPT CORE
--
-- These generic functions are intentionally NOT granted directly to the
-- Zammad runtime role.
-- ============================================================================

CREATE FUNCTION compliance.claim_ticket_event_receipt(
    p_provider             TEXT,
    p_source_event_id      BIGINT,
    p_consumer_instance_id TEXT,
    p_lease_seconds        INTEGER DEFAULT 300,
    p_details              JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, compliance
AS $$
DECLARE
    v_now        TIMESTAMPTZ;
    v_lease      TIMESTAMPTZ;
    v_source     RECORD;
    v_row        compliance.ticket_event_receipts%ROWTYPE;
BEGIN
    IF p_provider IS NULL
       OR btrim(p_provider) = ''
    THEN
        RAISE EXCEPTION
            'provider must not be empty';
    END IF;

    IF p_consumer_instance_id IS NULL
       OR btrim(p_consumer_instance_id) = ''
    THEN
        RAISE EXCEPTION
            'consumer_instance_id must not be empty';
    END IF;

    IF p_lease_seconds IS NULL
       OR p_lease_seconds < 60
       OR p_lease_seconds > 86400
    THEN
        RAISE EXCEPTION
            'lease_seconds must be between 60 and 86400';
    END IF;

    IF p_details IS NOT NULL
       AND jsonb_typeof(p_details) <> 'object'
    THEN
        RAISE EXCEPTION
            'details must be a JSON object';
    END IF;

    SELECT
        fe.finding_id,
        fe.event_type,
        cf.ticket_required
    INTO v_source
    FROM compliance.finding_events AS fe
    JOIN compliance.compliance_findings AS cf
      ON cf.finding_id = fe.finding_id
    WHERE fe.event_id = p_source_event_id
      AND fe.event_type IN (
          'DETECTED',
          'SEEN_AGAIN',
          'REOPENED',
          'RESOLVED'
      );

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'eligible lifecycle event does not exist: %',
            p_source_event_id;
    END IF;

    IF NOT v_source.ticket_required THEN
        RAISE EXCEPTION
            'finding does not require ticketing for source event %',
            p_source_event_id;
    END IF;

    v_now := clock_timestamp();

    v_lease :=
        v_now
        + make_interval(
            secs => p_lease_seconds
        );

    INSERT INTO compliance.ticket_event_receipts (
        provider,
        source_event_id,
        source_finding_id,
        lifecycle_event_type,
        state,
        consumer_instance_id,
        attempt_count,
        duplicate_count,
        claimed_at,
        lease_expires_at,
        details
    )
    VALUES (
        p_provider,
        p_source_event_id,
        v_source.finding_id,
        v_source.event_type,
        'CLAIMED',
        p_consumer_instance_id,
        1,
        0,
        v_now,
        v_lease,
        COALESCE(
            p_details,
            '{}'::jsonb
        )
    )
    ON CONFLICT DO NOTHING;

    IF FOUND THEN
        RETURN jsonb_build_object(
            'decision',
            'CLAIMED_NEW',
            'provider',
            p_provider,
            'source_event_id',
            p_source_event_id,
            'state',
            'CLAIMED',
            'attempt_count',
            1,
            'duplicate_count',
            0,
            'consumer_instance_id',
            p_consumer_instance_id,
            'lease_expires_at',
            v_lease
        );
    END IF;

    SELECT *
    INTO v_row
    FROM compliance.ticket_event_receipts
    WHERE provider = p_provider
      AND source_event_id = p_source_event_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'ticket receipt conflict could not be reconciled';
    END IF;

    IF v_row.source_finding_id <> v_source.finding_id
       OR v_row.lifecycle_event_type <> v_source.event_type
    THEN
        RAISE EXCEPTION
            'ticket receipt source correlation mismatch';
    END IF;

    IF v_row.state = 'COMPLETED' THEN
        UPDATE compliance.ticket_event_receipts
        SET
            duplicate_count = duplicate_count + 1
        WHERE provider = p_provider
          AND source_event_id = p_source_event_id
        RETURNING *
        INTO v_row;

        RETURN jsonb_build_object(
            'decision',
            'DUPLICATE_COMPLETED',
            'provider',
            v_row.provider,
            'source_event_id',
            v_row.source_event_id,
            'state',
            v_row.state,
            'attempt_count',
            v_row.attempt_count,
            'duplicate_count',
            v_row.duplicate_count,
            'ticket_record_id',
            v_row.ticket_record_id
        );
    END IF;

    IF v_row.state = 'CLAIMED'
       AND v_row.lease_expires_at > v_now
    THEN
        UPDATE compliance.ticket_event_receipts
        SET
            duplicate_count = duplicate_count + 1
        WHERE provider = p_provider
          AND source_event_id = p_source_event_id
        RETURNING *
        INTO v_row;

        RETURN jsonb_build_object(
            'decision',
            'DUPLICATE_INFLIGHT',
            'provider',
            v_row.provider,
            'source_event_id',
            v_row.source_event_id,
            'state',
            v_row.state,
            'attempt_count',
            v_row.attempt_count,
            'duplicate_count',
            v_row.duplicate_count,
            'consumer_instance_id',
            v_row.consumer_instance_id,
            'lease_expires_at',
            v_row.lease_expires_at
        );
    END IF;

    IF v_row.state IN (
        'CLAIMED',
        'FAILED'
    ) THEN
        UPDATE compliance.ticket_event_receipts
        SET
            state = 'CLAIMED',
            consumer_instance_id =
                p_consumer_instance_id,
            attempt_count = attempt_count + 1,
            duplicate_count = duplicate_count + 1,
            claimed_at = v_now,
            lease_expires_at = v_lease,
            completed_at = NULL,
            failed_at = NULL,
            last_error = NULL,
            details =
                details
                ||
                COALESCE(
                    p_details,
                    '{}'::jsonb
                )
        WHERE provider = p_provider
          AND source_event_id = p_source_event_id
        RETURNING *
        INTO v_row;

        RETURN jsonb_build_object(
            'decision',
            'CLAIMED_RETRY',
            'provider',
            v_row.provider,
            'source_event_id',
            v_row.source_event_id,
            'state',
            v_row.state,
            'attempt_count',
            v_row.attempt_count,
            'duplicate_count',
            v_row.duplicate_count,
            'consumer_instance_id',
            v_row.consumer_instance_id,
            'lease_expires_at',
            v_row.lease_expires_at
        );
    END IF;

    RAISE EXCEPTION
        'unsupported ticket receipt state: %',
        v_row.state;
END;
$$;


CREATE FUNCTION compliance.complete_ticket_event_receipt(
    p_provider             TEXT,
    p_source_event_id      BIGINT,
    p_consumer_instance_id TEXT,
    p_ticket_record_id     TEXT DEFAULT NULL,
    p_details              JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, compliance
AS $$
DECLARE
    v_row compliance.ticket_event_receipts%ROWTYPE;
BEGIN
    SELECT *
    INTO v_row
    FROM compliance.ticket_event_receipts
    WHERE provider = p_provider
      AND source_event_id = p_source_event_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'ticket receipt does not exist';
    END IF;

    IF v_row.state = 'COMPLETED' THEN
        RETURN jsonb_build_object(
            'decision',
            'ALREADY_COMPLETED',
            'provider',
            v_row.provider,
            'source_event_id',
            v_row.source_event_id,
            'state',
            v_row.state,
            'ticket_record_id',
            v_row.ticket_record_id
        );
    END IF;

    IF v_row.state <> 'CLAIMED' THEN
        RAISE EXCEPTION
            'ticket receipt cannot complete from state %',
            v_row.state;
    END IF;

    IF v_row.consumer_instance_id
       <> p_consumer_instance_id
    THEN
        RAISE EXCEPTION
            'ticket receipt ownership mismatch';
    END IF;

    IF p_ticket_record_id IS NOT NULL THEN
        PERFORM 1
        FROM compliance.ticket_records
        WHERE ticket_record_id = p_ticket_record_id
          AND provider = p_provider
          AND finding_id = v_row.source_finding_id;

        IF NOT FOUND THEN
            RAISE EXCEPTION
                'ticket receipt ticket correlation mismatch';
        END IF;
    END IF;

    UPDATE compliance.ticket_event_receipts
    SET
        state = 'COMPLETED',
        ticket_record_id =
            COALESCE(
                p_ticket_record_id,
                ticket_record_id
            ),
        lease_expires_at = NULL,
        completed_at = clock_timestamp(),
        failed_at = NULL,
        last_error = NULL,
        details =
            details
            ||
            COALESCE(
                p_details,
                '{}'::jsonb
            )
    WHERE provider = p_provider
      AND source_event_id = p_source_event_id
    RETURNING *
    INTO v_row;

    RETURN jsonb_build_object(
        'decision',
        'COMPLETED',
        'provider',
        v_row.provider,
        'source_event_id',
        v_row.source_event_id,
        'state',
        v_row.state,
        'ticket_record_id',
        v_row.ticket_record_id,
        'attempt_count',
        v_row.attempt_count,
        'duplicate_count',
        v_row.duplicate_count,
        'completed_at',
        v_row.completed_at
    );
END;
$$;


CREATE FUNCTION compliance.fail_ticket_event_receipt(
    p_provider             TEXT,
    p_source_event_id      BIGINT,
    p_consumer_instance_id TEXT,
    p_error                TEXT,
    p_details              JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, compliance
AS $$
DECLARE
    v_row compliance.ticket_event_receipts%ROWTYPE;
BEGIN
    SELECT *
    INTO v_row
    FROM compliance.ticket_event_receipts
    WHERE provider = p_provider
      AND source_event_id = p_source_event_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'ticket receipt does not exist';
    END IF;

    IF v_row.state = 'FAILED' THEN
        RETURN jsonb_build_object(
            'decision',
            'ALREADY_FAILED',
            'provider',
            v_row.provider,
            'source_event_id',
            v_row.source_event_id,
            'state',
            v_row.state
        );
    END IF;

    IF v_row.state = 'COMPLETED' THEN
        RAISE EXCEPTION
            'completed ticket receipt cannot be failed';
    END IF;

    IF v_row.consumer_instance_id
       <> p_consumer_instance_id
    THEN
        RAISE EXCEPTION
            'ticket receipt ownership mismatch';
    END IF;

    UPDATE compliance.ticket_event_receipts
    SET
        state = 'FAILED',
        lease_expires_at = NULL,
        completed_at = NULL,
        failed_at = clock_timestamp(),
        last_error =
            NULLIF(
                btrim(
                    COALESCE(
                        p_error,
                        ''
                    )
                ),
                ''
            ),
        details =
            details
            ||
            COALESCE(
                p_details,
                '{}'::jsonb
            )
    WHERE provider = p_provider
      AND source_event_id = p_source_event_id
    RETURNING *
    INTO v_row;

    RETURN jsonb_build_object(
        'decision',
        'FAILED',
        'provider',
        v_row.provider,
        'source_event_id',
        v_row.source_event_id,
        'state',
        v_row.state,
        'attempt_count',
        v_row.attempt_count,
        'duplicate_count',
        v_row.duplicate_count,
        'failed_at',
        v_row.failed_at
    );
END;
$$;


-- ============================================================================
-- 9. ZAMMAD-RESTRICTED RECEIPT WRAPPERS
-- ============================================================================

CREATE FUNCTION compliance.claim_zammad_ticket_event_receipt(
    p_source_event_id      BIGINT,
    p_consumer_instance_id TEXT,
    p_lease_seconds        INTEGER DEFAULT 300,
    p_details              JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, compliance
AS $$
    SELECT compliance.claim_ticket_event_receipt(
        'zammad',
        p_source_event_id,
        p_consumer_instance_id,
        p_lease_seconds,
        p_details
    );
$$;


CREATE FUNCTION compliance.complete_zammad_ticket_event_receipt(
    p_source_event_id      BIGINT,
    p_consumer_instance_id TEXT,
    p_ticket_record_id     TEXT DEFAULT NULL,
    p_details              JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, compliance
AS $$
    SELECT compliance.complete_ticket_event_receipt(
        'zammad',
        p_source_event_id,
        p_consumer_instance_id,
        p_ticket_record_id,
        p_details
    );
$$;


CREATE FUNCTION compliance.fail_zammad_ticket_event_receipt(
    p_source_event_id      BIGINT,
    p_consumer_instance_id TEXT,
    p_error                TEXT,
    p_details              JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, compliance
AS $$
    SELECT compliance.fail_ticket_event_receipt(
        'zammad',
        p_source_event_id,
        p_consumer_instance_id,
        p_error,
        p_details
    );
$$;


-- ============================================================================
-- 10. ZAMMAD TICKET CORRELATION READER
-- ============================================================================

CREATE FUNCTION compliance.read_zammad_ticket_record(
    p_finding_id TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, compliance
AS $$
DECLARE
    v_row compliance.ticket_records%ROWTYPE;
BEGIN
    IF p_finding_id IS NULL
       OR btrim(p_finding_id) = ''
    THEN
        RAISE EXCEPTION
            'finding_id must not be empty';
    END IF;

    SELECT *
    INTO v_row
    FROM compliance.ticket_records
    WHERE finding_id = p_finding_id
      AND provider = 'zammad'
      AND ticket_type = 'INCIDENT'
    ORDER BY
        CASE
            WHEN ticket_state NOT IN (
                'RESOLVED',
                'CLOSED'
            )
            THEN 0
            ELSE 1
        END,
        updated_at DESC,
        created_at DESC
    LIMIT 1;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'found',
            false,
            'finding_id',
            p_finding_id,
            'provider',
            'zammad',
            'ticket_type',
            'INCIDENT'
        );
    END IF;

    RETURN jsonb_build_object(
        'found',
        true,
        'ticket_record_id',
        v_row.ticket_record_id,
        'finding_id',
        v_row.finding_id,
        'provider',
        v_row.provider,
        'ticket_type',
        v_row.ticket_type,
        'external_ticket_id',
        v_row.external_ticket_id,
        'external_ticket_number',
        v_row.external_ticket_number,
        'ticket_state',
        v_row.ticket_state,
        'approval_state',
        v_row.approval_state,
        'remediation_allowed',
        v_row.remediation_allowed,
        'details',
        v_row.details,
        'created_at',
        v_row.created_at,
        'updated_at',
        v_row.updated_at,
        'last_sync_at',
        v_row.last_sync_at
    );
END;
$$;


-- ============================================================================
-- 11. ZAMMAD-RESTRICTED TICKET WRITE WRAPPERS
-- ============================================================================

CREATE FUNCTION compliance.upsert_zammad_ticket_record(
    p_ticket_record_id       TEXT,
    p_finding_id             TEXT,
    p_external_ticket_id     TEXT DEFAULT NULL,
    p_external_ticket_number TEXT DEFAULT NULL,
    p_ticket_state           TEXT DEFAULT 'PENDING_CREATE',
    p_details                JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, compliance
AS $$
    SELECT compliance.upsert_ticket_record(
        p_ticket_record_id,
        p_finding_id,
        'zammad',
        'INCIDENT',
        p_external_ticket_id,
        p_external_ticket_number,
        p_ticket_state,
        'NOT_REQUIRED',
        false,
        p_details
    );
$$;


CREATE FUNCTION compliance.update_zammad_ticket_record(
    p_ticket_record_id       TEXT,
    p_expected_state         TEXT,
    p_new_state              TEXT,
    p_external_ticket_id     TEXT DEFAULT NULL,
    p_external_ticket_number TEXT DEFAULT NULL,
    p_last_error             TEXT DEFAULT NULL,
    p_details                JSONB DEFAULT '{}'::jsonb
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, compliance
AS $$
DECLARE
    v_provider TEXT;
    v_type     TEXT;
BEGIN
    SELECT
        provider,
        ticket_type
    INTO
        v_provider,
        v_type
    FROM compliance.ticket_records
    WHERE ticket_record_id = p_ticket_record_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'ticket record does not exist: %',
            p_ticket_record_id;
    END IF;

    IF v_provider <> 'zammad'
       OR v_type <> 'INCIDENT'
    THEN
        RAISE EXCEPTION
            'ticket record is not a Zammad incident';
    END IF;

    RETURN compliance.update_ticket_record(
        p_ticket_record_id,
        p_expected_state,
        p_new_state,
        NULL,
        NULL,
        p_external_ticket_id,
        p_external_ticket_number,
        p_last_error,
        p_details
    );
END;
$$;


-- ============================================================================
-- 12. FUNCTION OWNERSHIP
-- ============================================================================

ALTER FUNCTION compliance.read_unpublished_ticket_lifecycle_events(
    TEXT,
    INTEGER
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.claim_lifecycle_event_publication(
    TEXT,
    BIGINT,
    TEXT,
    INTEGER,
    JSONB
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.complete_lifecycle_event_publication(
    TEXT,
    BIGINT,
    TEXT
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.fail_lifecycle_event_publication(
    TEXT,
    BIGINT,
    TEXT,
    TEXT
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.claim_ticket_event_receipt(
    TEXT,
    BIGINT,
    TEXT,
    INTEGER,
    JSONB
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.complete_ticket_event_receipt(
    TEXT,
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.fail_ticket_event_receipt(
    TEXT,
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.claim_zammad_ticket_event_receipt(
    BIGINT,
    TEXT,
    INTEGER,
    JSONB
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.complete_zammad_ticket_event_receipt(
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.fail_zammad_ticket_event_receipt(
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.read_zammad_ticket_record(
    TEXT
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.upsert_zammad_ticket_record(
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    JSONB
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.update_zammad_ticket_record(
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    JSONB
)
OWNER TO compliance_api_owner;


-- ============================================================================
-- 13. PRIVILEGE BOUNDARY
-- ============================================================================

REVOKE ALL
ON TABLE compliance.lifecycle_event_publications
FROM PUBLIC,
     compliance_lifecycle_publisher,
     compliance_zammad_runtime_api;

REVOKE ALL
ON TABLE compliance.ticket_event_receipts
FROM PUBLIC,
     compliance_lifecycle_publisher,
     compliance_zammad_runtime_api;


GRANT USAGE
ON SCHEMA compliance
TO compliance_lifecycle_publisher,
   compliance_zammad_runtime_api;


-- Publisher API.

REVOKE ALL
ON FUNCTION compliance.read_unpublished_ticket_lifecycle_events(
    TEXT,
    INTEGER
)
FROM PUBLIC;

REVOKE ALL
ON FUNCTION compliance.claim_lifecycle_event_publication(
    TEXT,
    BIGINT,
    TEXT,
    INTEGER,
    JSONB
)
FROM PUBLIC;

REVOKE ALL
ON FUNCTION compliance.complete_lifecycle_event_publication(
    TEXT,
    BIGINT,
    TEXT
)
FROM PUBLIC;

REVOKE ALL
ON FUNCTION compliance.fail_lifecycle_event_publication(
    TEXT,
    BIGINT,
    TEXT,
    TEXT
)
FROM PUBLIC;


GRANT EXECUTE
ON FUNCTION compliance.read_unpublished_ticket_lifecycle_events(
    TEXT,
    INTEGER
)
TO compliance_lifecycle_publisher;

GRANT EXECUTE
ON FUNCTION compliance.claim_lifecycle_event_publication(
    TEXT,
    BIGINT,
    TEXT,
    INTEGER,
    JSONB
)
TO compliance_lifecycle_publisher;

GRANT EXECUTE
ON FUNCTION compliance.complete_lifecycle_event_publication(
    TEXT,
    BIGINT,
    TEXT
)
TO compliance_lifecycle_publisher;

GRANT EXECUTE
ON FUNCTION compliance.fail_lifecycle_event_publication(
    TEXT,
    BIGINT,
    TEXT,
    TEXT
)
TO compliance_lifecycle_publisher;


-- Generic receipt core: owner-only, no application-role grant.

REVOKE ALL
ON FUNCTION compliance.claim_ticket_event_receipt(
    TEXT,
    BIGINT,
    TEXT,
    INTEGER,
    JSONB
)
FROM PUBLIC;

REVOKE ALL
ON FUNCTION compliance.complete_ticket_event_receipt(
    TEXT,
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
FROM PUBLIC;

REVOKE ALL
ON FUNCTION compliance.fail_ticket_event_receipt(
    TEXT,
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
FROM PUBLIC;


-- Zammad-only API.

REVOKE ALL
ON FUNCTION compliance.claim_zammad_ticket_event_receipt(
    BIGINT,
    TEXT,
    INTEGER,
    JSONB
)
FROM PUBLIC;

REVOKE ALL
ON FUNCTION compliance.complete_zammad_ticket_event_receipt(
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
FROM PUBLIC;

REVOKE ALL
ON FUNCTION compliance.fail_zammad_ticket_event_receipt(
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
FROM PUBLIC;

REVOKE ALL
ON FUNCTION compliance.read_zammad_ticket_record(
    TEXT
)
FROM PUBLIC;

REVOKE ALL
ON FUNCTION compliance.upsert_zammad_ticket_record(
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    JSONB
)
FROM PUBLIC;

REVOKE ALL
ON FUNCTION compliance.update_zammad_ticket_record(
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    JSONB
)
FROM PUBLIC;


GRANT EXECUTE
ON FUNCTION compliance.claim_zammad_ticket_event_receipt(
    BIGINT,
    TEXT,
    INTEGER,
    JSONB
)
TO compliance_zammad_runtime_api;

GRANT EXECUTE
ON FUNCTION compliance.complete_zammad_ticket_event_receipt(
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
TO compliance_zammad_runtime_api;

GRANT EXECUTE
ON FUNCTION compliance.fail_zammad_ticket_event_receipt(
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
TO compliance_zammad_runtime_api;

GRANT EXECUTE
ON FUNCTION compliance.read_zammad_ticket_record(
    TEXT
)
TO compliance_zammad_runtime_api;

GRANT EXECUTE
ON FUNCTION compliance.upsert_zammad_ticket_record(
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    JSONB
)
TO compliance_zammad_runtime_api;

GRANT EXECUTE
ON FUNCTION compliance.update_zammad_ticket_record(
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    JSONB
)
TO compliance_zammad_runtime_api;


-- Explicitly prove Zammad role cannot execute existing remediation/approval API.

REVOKE EXECUTE
ON FUNCTION compliance.record_remediation_approval(
    TEXT,
    TEXT,
    TEXT,
    JSONB
)
FROM compliance_zammad_runtime_api;

REVOKE EXECUTE
ON FUNCTION compliance.create_remediation_attempt(
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    INTEGER,
    BIGINT,
    JSONB
)
FROM compliance_zammad_runtime_api;

REVOKE EXECUTE
ON FUNCTION compliance.transition_remediation_attempt(
    TEXT,
    TEXT,
    TEXT,
    BIGINT,
    BIGINT,
    BIGINT,
    TEXT,
    TEXT,
    TEXT,
    JSONB
)
FROM compliance_zammad_runtime_api;


COMMENT ON TABLE compliance.lifecycle_event_publications IS
'Provider-neutral publication idempotency ledger for ticket-required finding lifecycle events.';

COMMENT ON TABLE compliance.ticket_event_receipts IS
'Provider-neutral consumer receipt ledger preventing repeated external ticketing side effects for one immutable finding lifecycle event.';

COMMENT ON FUNCTION compliance.read_unpublished_ticket_lifecycle_events(
    TEXT,
    INTEGER
) IS
'Reads ticket-required DETECTED, SEEN_AGAIN, REOPENED and RESOLVED source events that are not COMPLETED for the requested lifecycle topic.';


COMMIT;
