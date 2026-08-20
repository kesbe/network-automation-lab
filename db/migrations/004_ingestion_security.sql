BEGIN;

-- ---------------------------------------------------------------------------
-- Dedicated non-login roles
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_roles
        WHERE rolname = 'compliance_api_owner'
    ) THEN
        CREATE ROLE compliance_api_owner
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
        WHERE rolname = 'compliance_ingest'
    ) THEN
        CREATE ROLE compliance_ingest
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS;
    END IF;
END
$$;

-- Reassert safe attributes if roles already existed.
ALTER ROLE compliance_api_owner
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;

ALTER ROLE compliance_ingest
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;

-- ---------------------------------------------------------------------------
-- Schema boundary
-- ---------------------------------------------------------------------------

REVOKE ALL ON SCHEMA compliance FROM PUBLIC;

GRANT USAGE ON SCHEMA compliance
    TO compliance_api_owner;

GRANT USAGE ON SCHEMA compliance
    TO compliance_ingest;

-- ---------------------------------------------------------------------------
-- Internal API owner permissions
--
-- This role can perform the DML required by the ingestion functions but
-- cannot log in and does not own the compliance tables.
-- ---------------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE
    ON ALL TABLES IN SCHEMA compliance
    TO compliance_api_owner;

GRANT USAGE, SELECT, UPDATE
    ON ALL SEQUENCES IN SCHEMA compliance
    TO compliance_api_owner;

-- Application-facing role receives no direct table access.
REVOKE ALL PRIVILEGES
    ON ALL TABLES IN SCHEMA compliance
    FROM compliance_ingest;

REVOKE ALL PRIVILEGES
    ON ALL SEQUENCES IN SCHEMA compliance
    FROM compliance_ingest;

-- ---------------------------------------------------------------------------
-- Remove default PUBLIC function access before enabling SECURITY DEFINER.
-- ---------------------------------------------------------------------------

REVOKE EXECUTE ON FUNCTION compliance.ingest_compliance_run(
    jsonb,
    bigint,
    bigint,
    bigint,
    text,
    text
) FROM PUBLIC;

REVOKE EXECUTE ON FUNCTION compliance.ingest_finding(
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    boolean,
    text,
    boolean,
    text,
    text,
    jsonb,
    jsonb,
    jsonb,
    jsonb,
    timestamp with time zone,
    text,
    jsonb
) FROM PUBLIC;

-- ---------------------------------------------------------------------------
-- Transfer controlled ingestion API ownership.
--
-- CREATE is granted only long enough to permit function ownership transfer.
-- ---------------------------------------------------------------------------

GRANT CREATE ON SCHEMA compliance
    TO compliance_api_owner;

ALTER FUNCTION compliance.ingest_compliance_run(
    jsonb,
    bigint,
    bigint,
    bigint,
    text,
    text
)
OWNER TO compliance_api_owner;

ALTER FUNCTION compliance.ingest_finding(
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    boolean,
    text,
    boolean,
    text,
    text,
    jsonb,
    jsonb,
    jsonb,
    jsonb,
    timestamp with time zone,
    text,
    jsonb
)
OWNER TO compliance_api_owner;

REVOKE CREATE ON SCHEMA compliance
    FROM compliance_api_owner;

-- ---------------------------------------------------------------------------
-- SECURITY DEFINER with controlled search_path.
--
-- This prevents caller-controlled schemas from changing object resolution.
-- ---------------------------------------------------------------------------

ALTER FUNCTION compliance.ingest_compliance_run(
    jsonb,
    bigint,
    bigint,
    bigint,
    text,
    text
)
SECURITY DEFINER;

ALTER FUNCTION compliance.ingest_compliance_run(
    jsonb,
    bigint,
    bigint,
    bigint,
    text,
    text
)
SET search_path = pg_catalog, compliance;

ALTER FUNCTION compliance.ingest_finding(
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    boolean,
    text,
    boolean,
    text,
    text,
    jsonb,
    jsonb,
    jsonb,
    jsonb,
    timestamp with time zone,
    text,
    jsonb
)
SECURITY DEFINER;

ALTER FUNCTION compliance.ingest_finding(
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    boolean,
    text,
    boolean,
    text,
    text,
    jsonb,
    jsonb,
    jsonb,
    jsonb,
    timestamp with time zone,
    text,
    jsonb
)
SET search_path = pg_catalog, compliance;

-- ---------------------------------------------------------------------------
-- Public application API
--
-- AWX may call the run-level API only. ingest_finding() remains internal.
-- ---------------------------------------------------------------------------

GRANT EXECUTE ON FUNCTION compliance.ingest_compliance_run(
    jsonb,
    bigint,
    bigint,
    bigint,
    text,
    text
) TO compliance_ingest;

REVOKE EXECUTE ON FUNCTION compliance.ingest_finding(
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    text,
    boolean,
    text,
    boolean,
    text,
    text,
    jsonb,
    jsonb,
    jsonb,
    jsonb,
    timestamp with time zone,
    text,
    jsonb
) FROM compliance_ingest;

-- ---------------------------------------------------------------------------
-- Defensive defaults for future migrations created by netauto_admin.
-- ---------------------------------------------------------------------------

ALTER DEFAULT PRIVILEGES
    FOR ROLE netauto_admin
    IN SCHEMA compliance
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

ALTER DEFAULT PRIVILEGES
    FOR ROLE netauto_admin
    IN SCHEMA compliance
    REVOKE ALL ON TABLES FROM PUBLIC;

ALTER DEFAULT PRIVILEGES
    FOR ROLE netauto_admin
    IN SCHEMA compliance
    REVOKE ALL ON SEQUENCES FROM PUBLIC;

COMMENT ON ROLE compliance_api_owner IS
    'Non-login owner for network compliance ingestion functions';

COMMENT ON ROLE compliance_ingest IS
    'Non-login privilege role allowed to execute the compliance run ingestion API';

COMMIT;
