-- ============================================================================
-- 007_stale_reconciliation_security.sql
--
-- Least-privilege stale transport reconciliation boundary.
--
-- This migration deliberately keeps reconciliation separate from the normal
-- compliance_ingest / compliance_writer transport path.
-- ============================================================================

BEGIN;

-- ============================================================================
-- Reconciliation roles
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_roles
        WHERE rolname = 'compliance_reconciler'
    ) THEN
        CREATE ROLE compliance_reconciler
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
        WHERE rolname = 'compliance_reconciler_runtime'
    ) THEN
        CREATE ROLE compliance_reconciler_runtime
            LOGIN
            PASSWORD NULL
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS;
    END IF;
END
$$;

ALTER ROLE compliance_reconciler
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;

ALTER ROLE compliance_reconciler_runtime
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;

GRANT compliance_reconciler
    TO compliance_reconciler_runtime;

GRANT USAGE ON SCHEMA compliance
    TO compliance_reconciler;

-- Explicitly deny raw ledger access.
REVOKE ALL PRIVILEGES
    ON TABLE compliance.transport_events
    FROM compliance_reconciler;

REVOKE ALL PRIVILEGES
    ON TABLE compliance.transport_events
    FROM compliance_reconciler_runtime;

-- ============================================================================
-- inspect_stale_transport_event()
--
-- Controlled read API.
--
-- Only returns ownership metadata when the event is currently CLAIMED and its
-- lease has expired. It does not expose the unrestricted transport ledger.
-- ============================================================================

CREATE FUNCTION compliance.inspect_stale_transport_event(
    p_event_id text
)
RETURNS jsonb
LANGUAGE plpgsql
AS $$
DECLARE
    v_now timestamp with time zone;
    v_row compliance.transport_events%ROWTYPE;
BEGIN
    IF p_event_id IS NULL
       OR btrim(p_event_id) = '' THEN
        RAISE EXCEPTION
            'event_id must not be empty'
            USING ERRCODE = '22023';
    END IF;

    v_now := clock_timestamp();

    SELECT *
    INTO v_row
    FROM compliance.transport_events
    WHERE event_id = p_event_id;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'decision',
            'NOT_FOUND',
            'event_id',
            p_event_id
        );
    END IF;

    IF v_row.state <> 'CLAIMED'
       OR v_row.lease_expires_at IS NULL
       OR v_row.lease_expires_at > v_now THEN
        RETURN jsonb_build_object(
            'decision',
            'NOT_STALE_CANDIDATE',
            'event_id',
            v_row.event_id
        );
    END IF;

    RETURN jsonb_build_object(
        'decision',
        'STALE_CANDIDATE',
        'event_id',
        v_row.event_id,
        'event_type',
        v_row.event_type,
        'compliance_run_id',
        v_row.compliance_run_id,
        'state',
        v_row.state,
        'attempt_count',
        v_row.attempt_count,
        'duplicate_count',
        v_row.duplicate_count,
        'claim_workflow_job_id',
        v_row.claim_workflow_job_id,
        'claimed_at',
        v_row.claimed_at,
        'lease_expires_at',
        v_row.lease_expires_at
    );
END;
$$;

REVOKE EXECUTE ON FUNCTION
    compliance.inspect_stale_transport_event(text)
FROM PUBLIC;

-- Match the existing transport API ownership model.
GRANT CREATE ON SCHEMA compliance
    TO compliance_api_owner;

ALTER FUNCTION compliance.inspect_stale_transport_event(text)
    OWNER TO compliance_api_owner;

REVOKE CREATE ON SCHEMA compliance
    FROM compliance_api_owner;

ALTER FUNCTION compliance.inspect_stale_transport_event(text)
    SECURITY DEFINER;

ALTER FUNCTION compliance.inspect_stale_transport_event(text)
    SET search_path = pg_catalog, compliance;

GRANT EXECUTE ON FUNCTION
    compliance.inspect_stale_transport_event(text)
TO compliance_reconciler;

-- Only the reconciliation capability receives stale ownership transfer.
GRANT EXECUTE ON FUNCTION
    compliance.reclaim_stale_transport_event(
        text,
        bigint,
        bigint,
        integer,
        text
    )
TO compliance_reconciler;

-- Normal transport roles remain unable to reconcile.
REVOKE EXECUTE ON FUNCTION
    compliance.inspect_stale_transport_event(text)
FROM compliance_ingest;

REVOKE EXECUTE ON FUNCTION
    compliance.inspect_stale_transport_event(text)
FROM compliance_writer;

REVOKE EXECUTE ON FUNCTION
    compliance.reclaim_stale_transport_event(
        text,
        bigint,
        bigint,
        integer,
        text
    )
FROM compliance_ingest;

REVOKE EXECUTE ON FUNCTION
    compliance.reclaim_stale_transport_event(
        text,
        bigint,
        bigint,
        integer,
        text
    )
FROM compliance_writer;

COMMENT ON ROLE compliance_reconciler IS
    'Least-privilege capability role for stale transport reconciliation';

COMMENT ON ROLE compliance_reconciler_runtime IS
    'Runtime login role for stale transport reconciliation; password managed outside migrations';

COMMENT ON FUNCTION compliance.inspect_stale_transport_event(text) IS
    'Returns limited metadata only for an expired CLAIMED transport event';

COMMIT;
