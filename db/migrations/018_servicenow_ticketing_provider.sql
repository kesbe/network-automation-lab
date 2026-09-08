BEGIN;


-- ============================================================================
-- ServiceNow ticketing provider runtime boundary
--
-- This migration adds provider-restricted wrappers only.
--
-- It intentionally does not:
-- * modify lifecycle publication semantics
-- * modify ticket_event_receipts storage
-- * modify ticket_records storage
-- * contact ServiceNow
-- * store ServiceNow credentials
-- * grant direct table DML
-- * grant remediation or approval privileges
-- ============================================================================


-- ============================================================================
-- 1. LEAST-PRIVILEGE RUNTIME API ROLE
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles
        WHERE rolname =
              'compliance_servicenow_runtime_api'
    ) THEN
        CREATE ROLE compliance_servicenow_runtime_api
            NOLOGIN
            NOINHERIT;
    END IF;
END;
$$;


GRANT USAGE
ON SCHEMA compliance
TO compliance_servicenow_runtime_api;


-- Start from no explicitly granted function privileges for this role.
REVOKE EXECUTE
ON ALL FUNCTIONS IN SCHEMA compliance
FROM compliance_servicenow_runtime_api;


-- ============================================================================
-- 2. PROVIDER-RESTRICTED RECEIPT WRAPPERS
-- ============================================================================

CREATE FUNCTION compliance.claim_servicenow_ticket_event_receipt(
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
        'servicenow',
        p_source_event_id,
        p_consumer_instance_id,
        p_lease_seconds,
        p_details
    );
$$;


CREATE FUNCTION compliance.complete_servicenow_ticket_event_receipt(
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
        'servicenow',
        p_source_event_id,
        p_consumer_instance_id,
        p_ticket_record_id,
        p_details
    );
$$;


CREATE FUNCTION compliance.fail_servicenow_ticket_event_receipt(
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
        'servicenow',
        p_source_event_id,
        p_consumer_instance_id,
        p_error,
        p_details
    );
$$;


-- ============================================================================
-- 3. SERVICENOW INCIDENT RECORD READER
-- ============================================================================

CREATE FUNCTION compliance.read_servicenow_ticket_record(
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
      AND provider = 'servicenow'
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
            'servicenow',
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
-- 4. SERVICENOW INCIDENT UPSERT WRAPPER
-- ============================================================================

CREATE FUNCTION compliance.upsert_servicenow_ticket_record(
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
        'servicenow',
        'INCIDENT',
        p_external_ticket_id,
        p_external_ticket_number,
        p_ticket_state,
        'NOT_REQUIRED',
        false,
        p_details
    );
$$;


-- ============================================================================
-- 5. SERVICENOW INCIDENT UPDATE WRAPPER
-- ============================================================================

CREATE FUNCTION compliance.update_servicenow_ticket_record(
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
    WHERE ticket_record_id =
          p_ticket_record_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION
            'ticket record does not exist: %',
            p_ticket_record_id;
    END IF;

    IF v_provider <> 'servicenow'
       OR v_type <> 'INCIDENT'
    THEN
        RAISE EXCEPTION
            'ticket record is not a ServiceNow incident';
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
-- 6. FUNCTION OWNERSHIP
-- ============================================================================

ALTER FUNCTION compliance.claim_servicenow_ticket_event_receipt(
    BIGINT,
    TEXT,
    INTEGER,
    JSONB
)
OWNER TO compliance_api_owner;


ALTER FUNCTION compliance.complete_servicenow_ticket_event_receipt(
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
OWNER TO compliance_api_owner;


ALTER FUNCTION compliance.fail_servicenow_ticket_event_receipt(
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
OWNER TO compliance_api_owner;


ALTER FUNCTION compliance.read_servicenow_ticket_record(
    TEXT
)
OWNER TO compliance_api_owner;


ALTER FUNCTION compliance.upsert_servicenow_ticket_record(
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    JSONB
)
OWNER TO compliance_api_owner;


ALTER FUNCTION compliance.update_servicenow_ticket_record(
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
-- 7. PUBLIC EXECUTE MUST REMAIN CLOSED
-- ============================================================================

REVOKE EXECUTE
ON FUNCTION compliance.claim_servicenow_ticket_event_receipt(
    BIGINT,
    TEXT,
    INTEGER,
    JSONB
)
FROM PUBLIC;


REVOKE EXECUTE
ON FUNCTION compliance.complete_servicenow_ticket_event_receipt(
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
FROM PUBLIC;


REVOKE EXECUTE
ON FUNCTION compliance.fail_servicenow_ticket_event_receipt(
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
FROM PUBLIC;


REVOKE EXECUTE
ON FUNCTION compliance.read_servicenow_ticket_record(
    TEXT
)
FROM PUBLIC;


REVOKE EXECUTE
ON FUNCTION compliance.upsert_servicenow_ticket_record(
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    JSONB
)
FROM PUBLIC;


REVOKE EXECUTE
ON FUNCTION compliance.update_servicenow_ticket_record(
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    JSONB
)
FROM PUBLIC;


-- ============================================================================
-- 8. GRANT ONLY PROVIDER-RESTRICTED WRAPPERS
-- ============================================================================

GRANT EXECUTE
ON FUNCTION compliance.claim_servicenow_ticket_event_receipt(
    BIGINT,
    TEXT,
    INTEGER,
    JSONB
)
TO compliance_servicenow_runtime_api;


GRANT EXECUTE
ON FUNCTION compliance.complete_servicenow_ticket_event_receipt(
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
TO compliance_servicenow_runtime_api;


GRANT EXECUTE
ON FUNCTION compliance.fail_servicenow_ticket_event_receipt(
    BIGINT,
    TEXT,
    TEXT,
    JSONB
)
TO compliance_servicenow_runtime_api;


GRANT EXECUTE
ON FUNCTION compliance.read_servicenow_ticket_record(
    TEXT
)
TO compliance_servicenow_runtime_api;


GRANT EXECUTE
ON FUNCTION compliance.upsert_servicenow_ticket_record(
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    JSONB
)
TO compliance_servicenow_runtime_api;


GRANT EXECUTE
ON FUNCTION compliance.update_servicenow_ticket_record(
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    TEXT,
    JSONB
)
TO compliance_servicenow_runtime_api;


COMMIT;
