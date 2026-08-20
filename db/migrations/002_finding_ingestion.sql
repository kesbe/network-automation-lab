BEGIN;


CREATE OR REPLACE FUNCTION compliance.ingest_finding(
    p_run_id                  TEXT,
    p_finding_id              TEXT,
    p_finding_fingerprint     TEXT,

    p_device                  TEXT,
    p_policy_id               TEXT,
    p_control                 TEXT,
    p_finding_scope           TEXT,

    p_category                TEXT,
    p_severity                TEXT,
    p_ticket_required         BOOLEAN,
    p_owner                   TEXT,

    p_remediation_supported   BOOLEAN,
    p_remediation_mode        TEXT,
    p_remediation_risk        TEXT,

    p_expected                JSONB,
    p_actual                  JSONB,
    p_remediation             JSONB,
    p_raw_finding             JSONB,

    p_observed_at             TIMESTAMPTZ DEFAULT now(),
    p_actor                   TEXT DEFAULT 'automation',
    p_event_details           JSONB DEFAULT '{}'::jsonb
)
RETURNS TABLE (
    result_finding_id         TEXT,
    result_event_type         TEXT,
    result_old_status         TEXT,
    result_new_status         TEXT,
    occurrence_inserted       BOOLEAN
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_inserted_finding_id     TEXT;
    v_canonical_finding_id    TEXT;

    v_existing_status         TEXT;
    v_existing_first_seen     TIMESTAMPTZ;
    v_existing_last_seen      TIMESTAMPTZ;
    v_existing_resolved_at    TIMESTAMPTZ;

    v_historical_observation  BOOLEAN := false;

    v_occurrence_finding_id   TEXT;

    v_event_type              TEXT;
    v_old_status              TEXT;
    v_new_status              TEXT;

BEGIN

    -- --------------------------------------------------------
    -- Validate the semantic fingerprint contract.
    --
    -- Current contract:
    --
    --   device|policy_id|scope
    --
    -- Example:
    --
    --   leaf01|NET-BGP-002|device
    -- --------------------------------------------------------

    IF p_finding_fingerprint <>
       (
           p_device
           || '|'
           || p_policy_id
           || '|'
           || p_finding_scope
       )
    THEN
        RAISE EXCEPTION
            'Finding fingerprint contract violation: supplied=%, expected=%',
            p_finding_fingerprint,
            (
                p_device
                || '|'
                || p_policy_id
                || '|'
                || p_finding_scope
            );
    END IF;


    -- --------------------------------------------------------
    -- Serialize operations for the same semantic finding.
    --
    -- This protects lifecycle classification when concurrent
    -- workers observe the same fingerprint.
    -- --------------------------------------------------------

    PERFORM pg_advisory_xact_lock(
        hashtextextended(
            p_finding_fingerprint,
            0
        )
    );


    -- --------------------------------------------------------
    -- Attempt to create a new canonical finding.
    --
    -- If the fingerprint already exists, the canonical row is
    -- reused instead.
    -- --------------------------------------------------------

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

        remediation_supported,
        remediation_mode,
        remediation_risk,

        expected,
        current_actual
    )
    VALUES (
        p_finding_id,
        p_finding_fingerprint,

        p_device,
        p_policy_id,
        p_control,
        p_finding_scope,

        p_category,
        p_severity,
        p_ticket_required,
        p_owner,

        'OPEN',
        p_observed_at,
        p_observed_at,

        p_remediation_supported,
        p_remediation_mode,
        p_remediation_risk,

        p_expected,
        p_actual
    )
    ON CONFLICT (
        finding_fingerprint
    )
    DO NOTHING

    RETURNING finding_id
    INTO v_inserted_finding_id;


    IF v_inserted_finding_id IS NOT NULL THEN

        v_canonical_finding_id :=
            v_inserted_finding_id;

        v_existing_status := NULL;

        v_old_status := NULL;
        v_new_status := 'OPEN';
        v_event_type := 'DETECTED';

    ELSE

        -- ----------------------------------------------------
        -- Existing semantic finding.
        --
        -- Lock the canonical row before deciding whether this
        -- observation is SEEN_AGAIN or REOPENED.
        -- ----------------------------------------------------

        SELECT
            finding_id,
            status,
            first_seen,
            last_seen,
            resolved_at
        INTO
            v_canonical_finding_id,
            v_existing_status,
            v_existing_first_seen,
            v_existing_last_seen,
            v_existing_resolved_at
        FROM compliance.compliance_findings
        WHERE finding_fingerprint =
              p_finding_fingerprint
        FOR UPDATE;


        IF NOT FOUND THEN
            RAISE EXCEPTION
                'Canonical finding unexpectedly missing for fingerprint %',
                p_finding_fingerprint;
        END IF;


        -- ----------------------------------------------------
        -- The application-generated finding ID must remain
        -- deterministic for the same fingerprint.
        -- ----------------------------------------------------

        IF v_canonical_finding_id <>
           p_finding_id
        THEN
            RAISE EXCEPTION
                'Finding identity contract violation: stored=%, supplied=%',
                v_canonical_finding_id,
                p_finding_id;
        END IF;


        v_old_status := v_existing_status;


        -- ----------------------------------------------------
        -- Historical / out-of-order observation handling.
        --
        -- An older observation must not move last_seen
        -- backwards or reopen a finding that was resolved
        -- after that observation actually occurred.
        -- ----------------------------------------------------

        v_historical_observation :=
            p_observed_at < v_existing_last_seen
            OR
            (
                v_existing_status = 'RESOLVED'
                AND v_existing_resolved_at IS NOT NULL
                AND p_observed_at <= v_existing_resolved_at
            );


        IF v_historical_observation THEN

            v_event_type := 'SEEN_AGAIN';
            v_new_status := v_existing_status;

        ELSIF v_existing_status = 'RESOLVED' THEN

            v_event_type := 'REOPENED';
            v_new_status := 'OPEN';

        ELSE

            v_event_type := 'SEEN_AGAIN';
            v_new_status := v_existing_status;

        END IF;

    END IF;


    -- --------------------------------------------------------
    -- Store this observation.
    --
    -- (run_id, finding_id) is the idempotency key.
    --
    -- If AWX retries persistence for the same run, no duplicate
    -- occurrence is created.
    -- --------------------------------------------------------

    INSERT INTO compliance.finding_occurrences (
        run_id,
        finding_id,
        observed_at,

        device_status,
        severity,
        ticket_required,

        expected,
        actual,
        remediation,
        raw_finding
    )
    VALUES (
        p_run_id,
        v_canonical_finding_id,
        p_observed_at,

        'NON-COMPLIANT',
        p_severity,
        p_ticket_required,

        p_expected,
        p_actual,
        p_remediation,
        p_raw_finding
    )
    ON CONFLICT (
        run_id,
        finding_id
    )
    DO NOTHING

    RETURNING finding_id
    INTO v_occurrence_finding_id;


    -- --------------------------------------------------------
    -- Retry / duplicate persistence attempt.
    --
    -- Do not modify lifecycle state and do not create another
    -- event.
    -- --------------------------------------------------------

    IF v_occurrence_finding_id IS NULL THEN

        RETURN QUERY
        SELECT
            v_canonical_finding_id,
            'DUPLICATE'::TEXT,
            v_existing_status,
            v_existing_status,
            false;

        RETURN;

    END IF;


    -- --------------------------------------------------------
    -- Existing finding: update current observation state.
    --
    -- first_seen is intentionally never modified.
    -- --------------------------------------------------------

    IF v_inserted_finding_id IS NULL THEN

        UPDATE compliance.compliance_findings
        SET
            category =
                CASE
                    WHEN v_historical_observation
                    THEN category
                    ELSE p_category
                END,

            severity =
                CASE
                    WHEN v_historical_observation
                    THEN severity
                    ELSE p_severity
                END,

            ticket_required =
                CASE
                    WHEN v_historical_observation
                    THEN ticket_required
                    ELSE p_ticket_required
                END,

            owner =
                CASE
                    WHEN v_historical_observation
                    THEN owner
                    ELSE p_owner
                END,

            status = v_new_status,

            first_seen =
                LEAST(
                    first_seen,
                    p_observed_at
                ),

            last_seen =
                GREATEST(
                    last_seen,
                    p_observed_at
                ),

            resolved_at =
                CASE
                    WHEN
                        NOT v_historical_observation
                        AND v_existing_status = 'RESOLVED'
                    THEN NULL
                    ELSE resolved_at
                END,

            remediation_supported =
                CASE
                    WHEN v_historical_observation
                    THEN remediation_supported
                    ELSE p_remediation_supported
                END,

            remediation_mode =
                CASE
                    WHEN v_historical_observation
                    THEN remediation_mode
                    ELSE p_remediation_mode
                END,

            remediation_risk =
                CASE
                    WHEN v_historical_observation
                    THEN remediation_risk
                    ELSE p_remediation_risk
                END,

            expected =
                CASE
                    WHEN v_historical_observation
                    THEN expected
                    ELSE p_expected
                END,

            current_actual =
                CASE
                    WHEN v_historical_observation
                    THEN current_actual
                    ELSE p_actual
                END,

            updated_at =
                CASE
                    WHEN v_historical_observation
                    THEN updated_at
                    ELSE now()
                END

        WHERE finding_id =
              v_canonical_finding_id;

    END IF;


    -- --------------------------------------------------------
    -- Append lifecycle audit event.
    -- --------------------------------------------------------

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
        v_canonical_finding_id,
        p_run_id,

        v_event_type,
        v_old_status,
        v_new_status,

        p_actor,

        COALESCE(
            p_event_details,
            '{}'::jsonb
        )
        ||
        jsonb_build_object(
            'device',
            p_device,

            'policy_id',
            p_policy_id,

            'fingerprint',
            p_finding_fingerprint,

            'observed_at',
            p_observed_at,

            'historical_observation',
            v_historical_observation
        )
    );


    RETURN QUERY
    SELECT
        v_canonical_finding_id,
        v_event_type,
        v_old_status,
        v_new_status,
        true;

END;
$$;


COMMENT ON FUNCTION compliance.ingest_finding(
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    BOOLEAN,
    TEXT,
    BOOLEAN,
    TEXT,
    TEXT,
    JSONB,
    JSONB,
    JSONB,
    JSONB,
    TIMESTAMPTZ,
    TEXT,
    JSONB
)
IS
'Atomically persists a compliance finding occurrence and classifies its lifecycle as DETECTED, SEEN_AGAIN, REOPENED, or DUPLICATE.';


COMMIT;
