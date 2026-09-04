-- V3 dedicated read-only privilege boundary.
--
-- This migration creates only the NOLOGIN privilege role used by the
-- production V3 activation-source preparation path.
--
-- The password-bearing runtime LOGIN role is intentionally created by a
-- separate operational phase and is not part of this migration.
--
-- Security model:
--
--   compliance_v3_reader
--       NOLOGIN
--       no elevated role attributes
--       no membership in compliance_ingest or any other privilege role
--       USAGE on schema compliance
--       EXECUTE only:
--         compliance.read_v3_activation_source(text,text)
--         compliance.read_v3_activation_sources_for_run(text)
--       no direct table/sequence privileges
--       no execute privilege on ingest_v3_compliance_run()
--
-- Existing compliance_ingest and compliance_writer behavior is preserved.

BEGIN;


-------------------------------------------------------------------------------
-- 1. CREATE THE DEDICATED NOLOGIN PRIVILEGE ROLE IF ABSENT
-------------------------------------------------------------------------------

DO $v3_reader_role$
BEGIN

    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles
        WHERE rolname = 'compliance_v3_reader'
    )
    THEN

        CREATE ROLE compliance_v3_reader
            NOLOGIN
            NOSUPERUSER
            NOINHERIT
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS;

    END IF;

END
$v3_reader_role$;


-------------------------------------------------------------------------------
-- 2. FAIL-CLOSED ROLE ATTRIBUTE NORMALIZATION
-------------------------------------------------------------------------------

ALTER ROLE compliance_v3_reader
    WITH
        NOLOGIN
        NOSUPERUSER
        NOINHERIT
        NOCREATEDB
        NOCREATEROLE
        NOREPLICATION
        NOBYPASSRLS;


-------------------------------------------------------------------------------
-- 3. REMOVE ANY PRE-EXISTING DIRECT PRIVILEGES
-------------------------------------------------------------------------------

REVOKE ALL PRIVILEGES
    ON SCHEMA compliance
    FROM compliance_v3_reader;

REVOKE ALL PRIVILEGES
    ON ALL TABLES IN SCHEMA compliance
    FROM compliance_v3_reader;

REVOKE ALL PRIVILEGES
    ON ALL SEQUENCES IN SCHEMA compliance
    FROM compliance_v3_reader;

REVOKE EXECUTE
    ON ALL FUNCTIONS IN SCHEMA compliance
    FROM compliance_v3_reader;


-------------------------------------------------------------------------------
-- 4. THE READER ROLE MUST NEVER INHERIT THE INGEST ROLE
-------------------------------------------------------------------------------

REVOKE compliance_ingest
    FROM compliance_v3_reader;


-------------------------------------------------------------------------------
-- 5. GRANT ONLY THE REQUIRED READ BOUNDARY
-------------------------------------------------------------------------------

GRANT USAGE
    ON SCHEMA compliance
    TO compliance_v3_reader;


GRANT EXECUTE
    ON FUNCTION compliance.read_v3_activation_source(
        TEXT,
        TEXT
    )
    TO compliance_v3_reader;


GRANT EXECUTE
    ON FUNCTION compliance.read_v3_activation_sources_for_run(
        TEXT
    )
    TO compliance_v3_reader;


-------------------------------------------------------------------------------
-- 6. EXPLICITLY DENY THE V3 INGESTION ENTRY POINT
-------------------------------------------------------------------------------

REVOKE EXECUTE
    ON FUNCTION compliance.ingest_v3_compliance_run(
        JSONB,
        JSONB,
        BIGINT,
        BIGINT,
        BIGINT,
        TEXT,
        TEXT
    )
    FROM compliance_v3_reader;


-------------------------------------------------------------------------------
-- 7. FAIL CLOSED IF THIS PRIVILEGE ROLE INHERITS ANY OTHER ROLE
-------------------------------------------------------------------------------

DO $v3_reader_membership$
BEGIN

    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members m
        JOIN pg_catalog.pg_roles member_role
          ON member_role.oid = m.member
        WHERE member_role.rolname = 'compliance_v3_reader'
    )
    THEN

        RAISE EXCEPTION
            'compliance_v3_reader must not inherit any role membership';

    END IF;

END
$v3_reader_membership$;


-------------------------------------------------------------------------------
-- 8. DOCUMENT THE SECURITY BOUNDARY
-------------------------------------------------------------------------------

COMMENT ON ROLE compliance_v3_reader IS
    'NOLOGIN least-privilege role for V3 activation-source readers; grants only schema USAGE and EXECUTE on the two SECURITY DEFINER reader functions.';


COMMIT;
