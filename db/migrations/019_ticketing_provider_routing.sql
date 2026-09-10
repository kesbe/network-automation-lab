-- 019_ticketing_provider_routing.sql
--
-- Provider-target routing and explicit terminal SKIPPED
-- publication semantics.
--
-- SOURCE PATCH ONLY in Phase 5D-9AK.
-- Live application requires separate authorization.

BEGIN;


-------------------------------------------------------------------------------
-- PRECONDITION: legacy event 21 remains the frozen
-- Fast-Track Zammad E2E event and has no transport/provider side effects.
-------------------------------------------------------------------------------

DO $migration019_precheck$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT count(*)
    INTO v_count
    FROM compliance.finding_events AS fe
    WHERE
        fe.event_id = 21
        AND fe.finding_id = 'ft-zammad-e2e-16be64f033'
        AND fe.run_id = 'ft-zammad-e2e-16be64f033-detected'
        AND fe.event_type = 'DETECTED'
        AND NOT (
            COALESCE(
                fe.details,
                '{}'::jsonb
            )
            ? 'target_providers'
        )
        AND NOT EXISTS (
            SELECT 1
            FROM compliance.lifecycle_event_publications AS p
            WHERE
                p.source_event_id
                = fe.event_id
        )
        AND NOT EXISTS (
            SELECT 1
            FROM compliance.ticket_event_receipts AS r
            WHERE
                r.source_event_id
                = fe.event_id
        )
        AND NOT EXISTS (
            SELECT 1
            FROM compliance.ticket_records AS tr
            WHERE
                tr.finding_id
                = fe.finding_id
        );

    IF v_count <> 1 THEN
        RAISE EXCEPTION
            'migration019 legacy event 21 precondition failed';
    END IF;
END;
$migration019_precheck$;


-------------------------------------------------------------------------------
-- PUBLICATION TABLE: explicit SKIPPED terminal state.
-------------------------------------------------------------------------------

ALTER TABLE compliance.lifecycle_event_publications
    ALTER COLUMN claimed_at DROP NOT NULL;

ALTER TABLE compliance.lifecycle_event_publications
    ADD COLUMN skipped_at TIMESTAMPTZ;


ALTER TABLE compliance.lifecycle_event_publications
    DROP CONSTRAINT
        lifecycle_publication_state_allowed;

ALTER TABLE compliance.lifecycle_event_publications
    DROP CONSTRAINT
        lifecycle_publication_state_timestamps;

ALTER TABLE compliance.lifecycle_event_publications
    DROP CONSTRAINT
        lifecycle_publication_attempt_positive;


ALTER TABLE compliance.lifecycle_event_publications
    ADD CONSTRAINT
        lifecycle_publication_state_allowed
    CHECK (
        state IN (
            'CLAIMED',
            'COMPLETED',
            'FAILED',
            'SKIPPED'
        )
    );


ALTER TABLE compliance.lifecycle_event_publications
    ADD CONSTRAINT
        lifecycle_publication_attempt_positive
    CHECK (
        (
            state = 'SKIPPED'
            AND attempt_count = 0
        )
        OR
        (
            state <> 'SKIPPED'
            AND attempt_count >= 1
        )
    );


ALTER TABLE compliance.lifecycle_event_publications
    ADD CONSTRAINT
        lifecycle_publication_state_timestamps
    CHECK (
        (
            state = 'CLAIMED'
            AND claimed_at IS NOT NULL
            AND lease_expires_at IS NOT NULL
            AND completed_at IS NULL
            AND failed_at IS NULL
            AND skipped_at IS NULL
        )
        OR
        (
            state = 'COMPLETED'
            AND claimed_at IS NOT NULL
            AND lease_expires_at IS NULL
            AND completed_at IS NOT NULL
            AND failed_at IS NULL
            AND skipped_at IS NULL
        )
        OR
        (
            state = 'FAILED'
            AND claimed_at IS NOT NULL
            AND lease_expires_at IS NULL
            AND completed_at IS NULL
            AND failed_at IS NOT NULL
            AND skipped_at IS NULL
        )
        OR
        (
            state = 'SKIPPED'
            AND claimed_at IS NULL
            AND lease_expires_at IS NULL
            AND completed_at IS NULL
            AND failed_at IS NULL
            AND skipped_at IS NOT NULL
            AND last_error IS NULL
        )
    );


COMMENT ON COLUMN
    compliance.lifecycle_event_publications.skipped_at
IS
    'Terminal timestamp for lifecycle events intentionally not published to Kafka.';


-------------------------------------------------------------------------------
-- UNPUBLISHED READERS:
-- COMPLETED and SKIPPED are both terminal.
-------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION compliance.read_unpublished_ticket_lifecycle_events(p_topic text, p_limit integer DEFAULT 100)
 RETURNS TABLE(source_event_id bigint, source_finding_id text, run_id text, lifecycle_event_type text, event_time timestamp with time zone, old_status text, new_status text, event_details jsonb, finding_snapshot jsonb)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'compliance'
AS $function$
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
          OR pub.state NOT IN ('COMPLETED', 'SKIPPED')
      )

    ORDER BY fe.event_id

    LIMIT p_limit;
END;
$function$;


CREATE OR REPLACE FUNCTION compliance.read_unpublished_ticket_lifecycle_events_for_run(p_topic text, p_run_id text, p_limit integer DEFAULT 100)
 RETURNS TABLE(source_event_id bigint, source_finding_id text, run_id text, lifecycle_event_type text, event_time timestamp with time zone, old_status text, new_status text, event_details jsonb, finding_snapshot jsonb)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'compliance'
AS $function$
BEGIN
    IF p_topic IS NULL
       OR btrim(p_topic) = ''
    THEN
        RAISE EXCEPTION
            'topic must not be empty';
    END IF;

    IF p_run_id IS NULL
       OR btrim(p_run_id) = ''
    THEN
        RAISE EXCEPTION
            'run_id must not be empty';
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

      AND fe.run_id = p_run_id

      AND cf.ticket_required

      AND (
          pub.source_event_id IS NULL
          OR pub.state NOT IN ('COMPLETED', 'SKIPPED')
      )

    ORDER BY fe.event_id

    LIMIT p_limit;
END;
$function$;


-------------------------------------------------------------------------------
-- PUBLICATION CLAIM / COMPLETE / FAIL STATE MACHINE.
-------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION compliance.claim_lifecycle_event_publication(p_topic text, p_source_event_id bigint, p_publisher_instance_id text, p_lease_seconds integer DEFAULT 300, p_details jsonb DEFAULT '{}'::jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'compliance'
AS $function$
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

    IF v_row.state = 'SKIPPED' THEN

        RETURN jsonb_build_object(

            'claim_status',

            'ALREADY_SKIPPED',

            'state',

            'SKIPPED',

            'topic',

            p_topic,

            'source_event_id',

            p_source_event_id,

            'publisher_instance_id',

            v_row.publisher_instance_id,

            'attempt_count',

            v_row.attempt_count,

            'duplicate_count',

            v_row.duplicate_count

        );

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
$function$;


CREATE OR REPLACE FUNCTION compliance.complete_lifecycle_event_publication(p_topic text, p_source_event_id bigint, p_publisher_instance_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'compliance'
AS $function$
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

    IF v_row.state = 'SKIPPED' THEN

        RAISE EXCEPTION

            'SKIPPED lifecycle publication cannot be completed';

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
$function$;


CREATE OR REPLACE FUNCTION compliance.fail_lifecycle_event_publication(p_topic text, p_source_event_id bigint, p_publisher_instance_id text, p_error text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'compliance'
AS $function$
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

    IF v_row.state = 'SKIPPED' THEN

        RAISE EXCEPTION

            'SKIPPED lifecycle publication cannot be failed';

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
$function$;


-------------------------------------------------------------------------------
-- INGEST:
-- ticket-required findings must carry explicit target_providers.
-------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION compliance.ingest_compliance_run(p_compliance_run jsonb, p_workflow_job_id bigint DEFAULT NULL::bigint, p_compliance_job_id bigint DEFAULT NULL::bigint, p_aggregator_job_id bigint DEFAULT NULL::bigint, p_source text DEFAULT 'awx'::text, p_actor text DEFAULT 'automation'::text)
 RETURNS TABLE(result_run_id text, result_status text, run_inserted boolean, device_results_inserted integer, findings_processed integer, detected_count integer, seen_again_count integer, reopened_count integer, duplicate_finding_count integer)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'compliance'
AS $function$
DECLARE
    v_target_providers JSONB;
    v_run_id               TEXT;
    v_schema_version       TEXT;
    v_generated_at         TIMESTAMPTZ;

    v_summary              JSONB;
    v_device_results       JSONB;
    v_findings             JSONB;
    v_critical_findings    JSONB;

    v_devices_checked      INTEGER;
    v_devices_compliant    INTEGER;
    v_devices_noncompliant INTEGER;

    v_total_findings       INTEGER;
    v_critical_count       INTEGER;
    v_high_count           INTEGER;
    v_medium_count         INTEGER;
    v_low_count            INTEGER;
    v_info_count           INTEGER;

    v_existing_raw         JSONB;

    v_device               JSONB;
    v_finding              JSONB;
    v_ingest_result        RECORD;

    v_violations_count     INTEGER;

    v_device_inserted      INTEGER := 0;
    v_findings_processed   INTEGER := 0;

    v_detected             INTEGER := 0;
    v_seen_again           INTEGER := 0;
    v_reopened             INTEGER := 0;
    v_duplicate            INTEGER := 0;

BEGIN

    -- ========================================================
    -- Validate top-level contract
    -- ========================================================

    IF p_compliance_run IS NULL
       OR jsonb_typeof(p_compliance_run) <> 'object'
    THEN
        RAISE EXCEPTION
            'compliance_run must be a JSON object';
    END IF;


    v_run_id :=
        btrim(
            COALESCE(
                p_compliance_run->>'run_id',
                ''
            )
        );

    IF v_run_id = '' THEN
        RAISE EXCEPTION
            'compliance_run.run_id is required';
    END IF;


    v_schema_version :=
        btrim(
            COALESCE(
                p_compliance_run->>'schema_version',
                ''
            )
        );

    IF v_schema_version = '' THEN
        RAISE EXCEPTION
            'compliance_run.schema_version is required';
    END IF;


    IF btrim(
        COALESCE(
            p_compliance_run->>'generated_at',
            ''
        )
    ) = ''
    THEN
        RAISE EXCEPTION
            'compliance_run.generated_at is required';
    END IF;


    v_generated_at :=
        (p_compliance_run->>'generated_at')::TIMESTAMPTZ;


    v_summary :=
        p_compliance_run->'summary';

    v_device_results :=
        p_compliance_run->'device_results';

    v_findings :=
        p_compliance_run->'findings';

    v_critical_findings :=
        p_compliance_run->'critical_findings';


    IF jsonb_typeof(v_summary) <> 'object' THEN
        RAISE EXCEPTION
            'compliance_run.summary must be an object';
    END IF;

    IF jsonb_typeof(v_device_results) <> 'array' THEN
        RAISE EXCEPTION
            'compliance_run.device_results must be an array';
    END IF;

    IF jsonb_typeof(v_findings) <> 'array' THEN
        RAISE EXCEPTION
            'compliance_run.findings must be an array';
    END IF;

    IF jsonb_typeof(v_critical_findings) <> 'array' THEN
        RAISE EXCEPTION
            'compliance_run.critical_findings must be an array';
    END IF;


    -- ========================================================
    -- Parse summary
    -- ========================================================

    v_devices_checked :=
        (v_summary->>'devices_checked')::INTEGER;

    v_devices_compliant :=
        (v_summary->>'devices_compliant')::INTEGER;

    v_devices_noncompliant :=
        (v_summary->>'devices_noncompliant')::INTEGER;

    v_total_findings :=
        (v_summary->>'total_findings')::INTEGER;

    v_critical_count :=
        (v_summary->>'critical_findings')::INTEGER;

    v_high_count :=
        (v_summary->>'high_findings')::INTEGER;

    v_medium_count :=
        (v_summary->>'medium_findings')::INTEGER;

    v_low_count :=
        (v_summary->>'low_findings')::INTEGER;

    v_info_count :=
        (v_summary->>'info_findings')::INTEGER;


    -- ========================================================
    -- Cross-check JSON arrays against summary
    -- ========================================================

    IF jsonb_array_length(v_device_results)
       <> v_devices_checked
    THEN
        RAISE EXCEPTION
            'device_results count mismatch: array=%, summary=%',
            jsonb_array_length(v_device_results),
            v_devices_checked;
    END IF;


    IF jsonb_array_length(v_findings)
       <> v_total_findings
    THEN
        RAISE EXCEPTION
            'findings count mismatch: array=%, summary=%',
            jsonb_array_length(v_findings),
            v_total_findings;
    END IF;


    -- ========================================================
    -- Serialize the same run_id
    -- ========================================================

    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            v_run_id,
            0
        )
    );


    -- ========================================================
    -- Whole-run idempotency
    --
    -- Same run + same payload:
    --   safe retry
    --
    -- Same run + different payload:
    --   identity collision / reject
    -- ========================================================

    SELECT
        raw_result
    INTO
        v_existing_raw
    FROM compliance.compliance_runs
    WHERE run_id = v_run_id
    FOR UPDATE;


    IF FOUND THEN

        IF v_existing_raw IS DISTINCT FROM
           p_compliance_run
        THEN
            RAISE EXCEPTION
                'Compliance run identity collision: run_id % already exists with different content',
                v_run_id;
        END IF;


        RETURN QUERY
        SELECT
            v_run_id,
            'DUPLICATE'::TEXT,
            false,
            0,
            0,
            0,
            0,
            0,
            0;

        RETURN;

    END IF;


    -- ========================================================
    -- Persist run
    -- ========================================================

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
        v_run_id,
        v_schema_version,
        v_generated_at,

        p_source,

        p_workflow_job_id,
        p_compliance_job_id,
        p_aggregator_job_id,

        v_devices_checked,
        v_devices_compliant,
        v_devices_noncompliant,

        v_total_findings,
        v_critical_count,
        v_high_count,
        v_medium_count,
        v_low_count,
        v_info_count,

        p_compliance_run
    );


    -- ========================================================
    -- Persist device results
    --
    -- JT38 currently emits count values as strings:
    --
    --   "total_checks": "11"
    --   "passed":       "10"
    --   "failed":       "1"
    --
    -- Cast explicitly to INTEGER here.
    -- ========================================================

    FOR v_device IN
        SELECT value
        FROM jsonb_array_elements(
            v_device_results
        )
    LOOP

        IF jsonb_typeof(v_device) <> 'object' THEN
            RAISE EXCEPTION
                'device_results entry must be an object';
        END IF;


        IF jsonb_typeof(
            v_device->'violations'
        ) = 'array'
        THEN
            v_violations_count :=
                jsonb_array_length(
                    v_device->'violations'
                );
        ELSE
            v_violations_count := 0;
        END IF;


        INSERT INTO compliance.compliance_run_devices (
            run_id,
            device,
            status,

            total_checks,
            passed_checks,
            failed_checks,
            violations_count,

            raw_result
        )
        VALUES (
            v_run_id,
            v_device->>'device',
            v_device->>'status',

            (v_device->>'total_checks')::INTEGER,
            (v_device->>'passed')::INTEGER,
            (v_device->>'failed')::INTEGER,
            v_violations_count,

            v_device
        );


        v_device_inserted :=
            v_device_inserted + 1;

    END LOOP;


    -- ========================================================
    -- Persist findings through the already-tested lifecycle API
    -- ========================================================

    FOR v_finding IN
        SELECT value
        FROM jsonb_array_elements(
            v_findings
        )
    LOOP

        IF jsonb_typeof(v_finding) <> 'object' THEN
            RAISE EXCEPTION
                'finding entry must be an object';
        END IF;


        IF jsonb_typeof(
            v_finding->'remediation'
        ) <> 'object'
        THEN
            RAISE EXCEPTION
                'finding remediation must be an object';
        END IF;
        v_target_providers := NULL;

        IF (
            v_finding->>'ticket_required'
        )::BOOLEAN
        THEN
            IF NOT (
                v_finding
                ? 'target_providers'
            )
            THEN
                RAISE EXCEPTION
                    'ticket-required finding requires target_providers';
            END IF;

            IF jsonb_typeof(
                v_finding
                ->'target_providers'
            ) <> 'array'
               OR jsonb_array_length(
                    v_finding
                    ->'target_providers'
               ) < 1
            THEN
                RAISE EXCEPTION
                    'target_providers must be a non-empty array';
            END IF;

            IF EXISTS (
                SELECT 1
                FROM jsonb_array_elements(
                    v_finding
                    ->'target_providers'
                ) AS item(value)
                WHERE
                    jsonb_typeof(
                        item.value
                    ) <> 'string'
                    OR lower(
                        btrim(
                            item.value
                            #>> '{}'
                        )
                    ) NOT IN (
                        'servicenow',
                        'zammad'
                    )
            )
            THEN
                RAISE EXCEPTION
                    'target_providers contains an unsupported provider';
            END IF;

            IF (
                SELECT count(*)
                FROM jsonb_array_elements_text(
                    v_finding
                    ->'target_providers'
                )
            ) <> (
                SELECT count(
                    DISTINCT lower(
                        btrim(value)
                    )
                )
                FROM jsonb_array_elements_text(
                    v_finding
                    ->'target_providers'
                ) AS target(value)
            )
            THEN
                RAISE EXCEPTION
                    'target_providers must not contain duplicates';
            END IF;

            SELECT jsonb_agg(
                provider
                ORDER BY provider
            )
            INTO v_target_providers
            FROM (
                SELECT
                    lower(
                        btrim(value)
                    ) AS provider
                FROM jsonb_array_elements_text(
                    v_finding
                    ->'target_providers'
                ) AS target(value)
            ) AS normalized_target;
        END IF;




        SELECT *
        INTO v_ingest_result
        FROM compliance.ingest_finding(
            p_run_id =>
                v_run_id,

            p_finding_id =>
                v_finding->>'finding_id',

            p_finding_fingerprint =>
                v_finding->>'finding_fingerprint',

            p_device =>
                v_finding->>'device',

            p_policy_id =>
                v_finding->>'policy_id',

            p_control =>
                v_finding->>'control',

            p_finding_scope =>
                v_finding->>'finding_scope',

            p_category =>
                v_finding->>'category',

            p_severity =>
                v_finding->>'severity',

            p_ticket_required =>
                (v_finding->>'ticket_required')::BOOLEAN,

            p_owner =>
                v_finding->>'owner',

            p_remediation_supported =>
                (
                    v_finding
                    ->'remediation'
                    ->>'supported'
                )::BOOLEAN,

            p_remediation_mode =>
                v_finding
                ->'remediation'
                ->>'mode',

            p_remediation_risk =>
                v_finding
                ->'remediation'
                ->>'risk',

            p_expected =>
                v_finding->'expected',

            p_actual =>
                v_finding->'actual',

            p_remediation =>
                v_finding->'remediation',

            p_raw_finding =>
                v_finding,

            p_observed_at =>
                v_generated_at,

            p_actor =>
                p_actor,

            p_event_details =>
                jsonb_build_object(
                    'source',
                    'ingest_compliance_run',

                    'run_id',
                    v_run_id,

                    'policy_name',
                    v_finding->>'policy_name',
                    'target_providers',
                    v_target_providers
                )
        );


        v_findings_processed :=
            v_findings_processed + 1;


        CASE v_ingest_result.result_event_type

            WHEN 'DETECTED' THEN
                v_detected :=
                    v_detected + 1;

            WHEN 'SEEN_AGAIN' THEN
                v_seen_again :=
                    v_seen_again + 1;

            WHEN 'REOPENED' THEN
                v_reopened :=
                    v_reopened + 1;

            WHEN 'DUPLICATE' THEN
                v_duplicate :=
                    v_duplicate + 1;

            ELSE
                RAISE EXCEPTION
                    'Unexpected ingest_finding result: %',
                    v_ingest_result.result_event_type;

        END CASE;

    END LOOP;


    -- ========================================================
    -- Return persistence summary
    -- ========================================================

    RETURN QUERY
    SELECT
        v_run_id,
        'INSERTED'::TEXT,
        true,
        v_device_inserted,
        v_findings_processed,
        v_detected,
        v_seen_again,
        v_reopened,
        v_duplicate;

END;
$function$;


-------------------------------------------------------------------------------
-- RESOLVED:
-- derive target providers from existing provider ticket records.
-- zero-ticket resolutions are terminally SKIPPED.
-------------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION compliance.resolve_absent_findings_after_run()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'compliance'
AS $function$
BEGIN

    WITH candidates AS MATERIALIZED
    (
        SELECT
            f.finding_id,
            f.device,
            f.status AS old_status

        FROM compliance.compliance_findings AS f

        WHERE
            -- Only operational lifecycle states are automatically closed.
            f.status IN (
                'OPEN',
                'REMEDIATING'
            )

            -- Never allow an older/backfilled clean run to resolve
            -- a finding observed by a newer run.
            AND f.last_seen <= NEW.generated_at

            -- Resolution is permitted only when this device actually
            -- completed compliance evaluation in the current run.
            AND EXISTS
            (
                SELECT 1

                FROM compliance.compliance_run_devices AS rd

                WHERE
                    rd.run_id = NEW.run_id
                    AND rd.device = f.device
                    AND rd.status IN (
                        'COMPLIANT',
                        'NON-COMPLIANT'
                    )
            )

            -- The canonical finding was not observed in this run.
            AND NOT EXISTS
            (
                SELECT 1

                FROM compliance.finding_occurrences AS fo

                WHERE
                    fo.run_id = NEW.run_id
                    AND fo.finding_id = f.finding_id
            )
    ),

    resolved AS
    (
        UPDATE compliance.compliance_findings AS f

        SET
            status = 'RESOLVED',

            resolved_at =
                NEW.generated_at,

            updated_at =
                GREATEST(
                    f.updated_at,
                    NEW.generated_at
                )

        FROM candidates AS c

        WHERE
            f.finding_id = c.finding_id

            -- Re-check mutable lifecycle state in case another transaction
            -- changed the row after candidate selection.
            AND f.status = c.old_status

            -- Re-check temporal guard at UPDATE time.
            AND f.last_seen <= NEW.generated_at

        RETURNING
            f.finding_id,
            f.device,
            c.old_status
    )

    INSERT INTO compliance.finding_events
    (
        finding_id,
        run_id,
        event_type,
        event_time,
        old_status,
        new_status,
        actor,
        details
    )

    SELECT
        r.finding_id,
        NEW.run_id,
        'RESOLVED',
        NEW.generated_at,
        r.old_status,
        'RESOLVED',

        CASE
            WHEN NEW.workflow_job_id IS NOT NULL
            THEN
                'awx-workflow-' ||
                NEW.workflow_job_id::TEXT
            ELSE
                'compliance-resolution-engine'
        END,

        jsonb_build_object(
            'source',
            'resolve_absent_findings_after_run',

            'reason',
            'finding_absent_from_completed_device_scan',

            'device',
            r.device,

            'run_id',
            NEW.run_id
        )

    FROM resolved AS r;
    -- Provider-routing enrichment for newly generated
    -- RESOLVED lifecycle events.
    WITH resolved_targets AS (
        SELECT
            fe.event_id,

            COALESCE(
                (
                    SELECT jsonb_agg(
                        provider
                        ORDER BY provider
                    )
                    FROM (
                        SELECT DISTINCT
                            lower(
                                btrim(
                                    tr.provider
                                )
                            ) AS provider

                        FROM compliance.ticket_records
                            AS tr

                        WHERE
                            tr.finding_id
                            = fe.finding_id

                            AND lower(
                                btrim(
                                    tr.provider
                                )
                            ) IN (
                                'servicenow',
                                'zammad'
                            )
                    ) AS provider_rows
                ),
                '[]'::jsonb
            ) AS target_providers

        FROM compliance.finding_events AS fe

        WHERE
            fe.run_id = NEW.run_id
            AND fe.event_type = 'RESOLVED'
            AND NOT (
                COALESCE(
                    fe.details,
                    '{}'::jsonb
                )
                ? 'target_providers'
            )
    )

    UPDATE compliance.finding_events AS fe
    SET
        details =
            COALESCE(
                fe.details,
                '{}'::jsonb
            )
            ||
            jsonb_build_object(
                'target_providers',
                rt.target_providers
            )

    FROM resolved_targets AS rt

    WHERE
        fe.event_id = rt.event_id;


    -- A RESOLVED finding with no existing provider
    -- ticket has no remote close action to perform.
    -- Retire that transport event explicitly.
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
        completed_at,
        failed_at,
        skipped_at,
        last_error,
        details
    )
    SELECT
        'network.compliance.lifecycle.events',
        fe.event_id,
        fe.finding_id,
        fe.event_type,
        'SKIPPED',
        'migration019-provider-routing-cutover',
        0,
        0,
        NULL,
        NULL,
        NULL,
        NULL,
        clock_timestamp(),
        NULL,
        jsonb_build_object(
            'skip_reason',
            'NO_EXISTING_PROVIDER_TICKET_ON_RESOLUTION',
            'skip_actor',
            'migration019-provider-routing-cutover'
        )

    FROM compliance.finding_events AS fe

    WHERE
        fe.run_id = NEW.run_id
        AND fe.event_type = 'RESOLVED'
        AND fe.details
            ->'target_providers'
            = '[]'::jsonb

    ON CONFLICT (
        topic,
        source_event_id
    )
    DO NOTHING;




    RETURN NEW;

END;
$function$;


-------------------------------------------------------------------------------
-- LEGACY EVENT 21:
-- retire without publishing and without backfilling target_providers.
-------------------------------------------------------------------------------

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
    completed_at,
    failed_at,
    skipped_at,
    last_error,
    details
)
SELECT
    'network.compliance.lifecycle.events',
    fe.event_id,
    fe.finding_id,
    fe.event_type,
    'SKIPPED',
    'migration019-provider-routing-cutover',
    0,
    0,
    NULL,
    NULL,
    NULL,
    NULL,
    clock_timestamp(),
    NULL,
    jsonb_build_object(
        'skip_reason',
        'PRE_ROUTING_CONTRACT_ZAMMAD_E2E_LINEAGE_FROZEN',
        'skip_actor',
        'migration019-provider-routing-cutover'
    )
FROM compliance.finding_events AS fe
WHERE
    fe.event_id = 21
    AND fe.finding_id = 'ft-zammad-e2e-16be64f033'
    AND fe.run_id = 'ft-zammad-e2e-16be64f033-detected'
    AND fe.event_type = 'DETECTED'
    AND NOT (
        COALESCE(
            fe.details,
            '{}'::jsonb
        )
        ? 'target_providers'
    );


DO $migration019_postcheck$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT count(*)
    INTO v_count
    FROM compliance.lifecycle_event_publications
    WHERE
        topic = 'network.compliance.lifecycle.events'
        AND source_event_id = 21
        AND source_finding_id = 'ft-zammad-e2e-16be64f033'
        AND lifecycle_event_type = 'DETECTED'
        AND state = 'SKIPPED'
        AND attempt_count = 0
        AND duplicate_count = 0
        AND claimed_at IS NULL
        AND lease_expires_at IS NULL
        AND completed_at IS NULL
        AND failed_at IS NULL
        AND skipped_at IS NOT NULL
        AND last_error IS NULL
        AND details->>'skip_reason'
            = 'PRE_ROUTING_CONTRACT_ZAMMAD_E2E_LINEAGE_FROZEN';

    IF v_count <> 1 THEN
        RAISE EXCEPTION
            'migration019 legacy event retirement postcondition failed';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM compliance.finding_events
        WHERE
            event_id = 21
            AND details
                ? 'target_providers'
    ) THEN
        RAISE EXCEPTION
            'migration019 must not backfill target_providers on legacy event 21';
    END IF;
END;
$migration019_postcheck$;


COMMIT;
