BEGIN;


-- ============================================================================
-- V3 activation-source read boundary
--
-- A single V3 compliance run may activate a given finding at most once.
-- Migration 012 already enforces this during transactional ingestion.
-- Formalize that invariant in the storage schema so (run_id, finding_id)
-- becomes a schema-backed lookup identity.
-- ============================================================================

ALTER TABLE compliance.v3_activation_sources
    ADD CONSTRAINT v3_activation_sources_run_finding_unique
    UNIQUE (
        run_id,
        finding_id
    );


-- ============================================================================
-- read_v3_activation_source()
--
-- Controlled read-only API for the immutable source material associated with
-- one V3 DETECTED / REOPENED activation.
--
-- Runtime callers receive no direct SELECT privilege on the underlying table.
-- ============================================================================

CREATE FUNCTION compliance.read_v3_activation_source(
    p_run_id TEXT,
    p_finding_id TEXT
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
    v_run_id       TEXT;
    v_finding_id   TEXT;
    v_source       compliance.v3_activation_sources%ROWTYPE;
BEGIN

    v_run_id :=
        btrim(
            COALESCE(
                p_run_id,
                ''
            )
        );

    v_finding_id :=
        btrim(
            COALESCE(
                p_finding_id,
                ''
            )
        );


    IF v_run_id = '' THEN
        RAISE EXCEPTION
            'run_id must not be empty'
            USING ERRCODE = '22023';
    END IF;


    IF v_finding_id = '' THEN
        RAISE EXCEPTION
            'finding_id must not be empty'
            USING ERRCODE = '22023';
    END IF;


    SELECT
        source.*
    INTO
        v_source
    FROM compliance.v3_activation_sources AS source
    WHERE
        source.run_id = v_run_id
        AND source.finding_id = v_finding_id;


    IF NOT FOUND THEN
        RAISE EXCEPTION
            'V3 activation source not found for run_id %, finding_id %',
            v_run_id,
            v_finding_id
            USING ERRCODE = 'P0002';
    END IF;


    RETURN QUERY
    SELECT
        v_source.finding_event_id,
        v_source.run_id,
        v_source.finding_id,
        v_source.lifecycle_event_type,
        v_source.activated_at,
        v_source.finding_snapshot,
        v_source.resolved_target;

END;
$$;


-- ============================================================================
-- Function security
-- ============================================================================

REVOKE EXECUTE ON FUNCTION
    compliance.read_v3_activation_source(
        TEXT,
        TEXT
    )
FROM PUBLIC;


-- Temporarily permit ownership transfer, matching the existing controlled
-- API security pattern.

GRANT CREATE ON SCHEMA compliance
    TO compliance_api_owner;


ALTER FUNCTION compliance.read_v3_activation_source(
    TEXT,
    TEXT
)
OWNER TO compliance_api_owner;


REVOKE CREATE ON SCHEMA compliance
    FROM compliance_api_owner;


ALTER FUNCTION compliance.read_v3_activation_source(
    TEXT,
    TEXT
)
SECURITY DEFINER;


ALTER FUNCTION compliance.read_v3_activation_source(
    TEXT,
    TEXT
)
SET search_path = pg_catalog, compliance;


GRANT EXECUTE ON FUNCTION
    compliance.read_v3_activation_source(
        TEXT,
        TEXT
    )
TO compliance_ingest;


COMMENT ON FUNCTION compliance.read_v3_activation_source(
    TEXT,
    TEXT
) IS
    'Returns the immutable V3 activation source identified by run_id and '
    'finding_id through a least-privilege SECURITY DEFINER read boundary.';


COMMIT;
