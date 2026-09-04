BEGIN;


-- ============================================================================
-- V3 activation-source run reader
--
-- Outbound V3 publishing is run-oriented:
--
--   persisted V3 run
--       |
--       v
--   zero or more DETECTED / REOPENED activation sources
--
-- A persisted V3 run with zero activation sources is valid and returns an
-- empty result set.
--
-- An unknown run fails closed. The V3 persistence-context table provides the
-- durable run-existence identity even when the run emitted no activations.
--
-- Runtime callers receive no direct SELECT privilege on either underlying
-- table.
-- ============================================================================

CREATE FUNCTION compliance.read_v3_activation_sources_for_run(
    p_run_id TEXT
)
RETURNS TABLE (
    finding_event_id      BIGINT,
    run_id                TEXT,
    finding_id            TEXT,
    lifecycle_event_type  TEXT,
    activated_at          TIMESTAMPTZ,
    finding_snapshot      JSONB,
    resolved_target       JSONB
)
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v_run_id TEXT;
BEGIN

    v_run_id :=
        btrim(
            COALESCE(
                p_run_id,
                ''
            )
        );


    IF v_run_id = '' THEN
        RAISE EXCEPTION
            'run_id must not be empty'
            USING ERRCODE = '22023';
    END IF;


    -- A V3 run context exists for every successfully persisted V3 run,
    -- including runs that produced zero activation events.

    IF NOT EXISTS (
        SELECT 1
        FROM compliance.v3_run_persistence_contexts AS run_context
        WHERE run_context.run_id = v_run_id
    )
    THEN
        RAISE EXCEPTION
            'V3 persistence context not found for run_id %',
            v_run_id
            USING ERRCODE = 'P0002';
    END IF;


    -- Zero matching activation rows is valid.
    --
    -- finding_event_id is the durable lifecycle-event identity and therefore
    -- provides deterministic fan-out order for the publisher workflow.

    RETURN QUERY
    SELECT
        source.finding_event_id,
        source.run_id,
        source.finding_id,
        source.lifecycle_event_type,
        source.activated_at,
        source.finding_snapshot,
        source.resolved_target
    FROM compliance.v3_activation_sources AS source
    WHERE source.run_id = v_run_id
    ORDER BY source.finding_event_id ASC;

END;
$$;


-- ============================================================================
-- Function security
-- ============================================================================

REVOKE EXECUTE ON FUNCTION
    compliance.read_v3_activation_sources_for_run(
        TEXT
    )
FROM PUBLIC;


-- Temporarily permit ownership transfer, matching the established controlled
-- PostgreSQL API security pattern.

GRANT CREATE ON SCHEMA compliance
    TO compliance_api_owner;


ALTER FUNCTION compliance.read_v3_activation_sources_for_run(
    TEXT
)
OWNER TO compliance_api_owner;


REVOKE CREATE ON SCHEMA compliance
    FROM compliance_api_owner;


ALTER FUNCTION compliance.read_v3_activation_sources_for_run(
    TEXT
)
SECURITY DEFINER;


ALTER FUNCTION compliance.read_v3_activation_sources_for_run(
    TEXT
)
SET search_path = pg_catalog, compliance;


GRANT EXECUTE ON FUNCTION
    compliance.read_v3_activation_sources_for_run(
        TEXT
    )
TO compliance_ingest;


COMMENT ON FUNCTION compliance.read_v3_activation_sources_for_run(
    TEXT
) IS
    'Returns zero or more immutable V3 activation sources for one persisted '
    'V3 compliance run in deterministic finding_event_id order through a '
    'least-privilege SECURITY DEFINER read boundary.';


COMMIT;
