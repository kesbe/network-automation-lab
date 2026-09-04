BEGIN;


-- ============================================================================
-- V3 COMPLIANCE EXPORTER READ MODEL
--
-- PostgreSQL remains the durable source of truth.
--
-- This migration exposes only low-cardinality aggregate read models for
-- Prometheus consumption.
--
-- The exporter has no capability to:
--
--   * create/update findings
--   * transition remediation
--   * approve remediation
--   * mutate tickets
--   * publish Kafka events
--   * call AWX
--
-- Runtime login identity is provisioned externally.
-- ============================================================================


-- ============================================================================
-- 1. EXPORTER SECURITY ROLES
-- ============================================================================

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_roles
        WHERE rolname = 'compliance_exporter_owner'
    ) THEN
        CREATE ROLE compliance_exporter_owner
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
        WHERE rolname = 'compliance_exporter'
    ) THEN
        CREATE ROLE compliance_exporter
            NOLOGIN
            NOSUPERUSER
            NOCREATEDB
            NOCREATEROLE
            NOREPLICATION
            NOBYPASSRLS;
    END IF;
END
$$;


ALTER ROLE compliance_exporter_owner
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;


ALTER ROLE compliance_exporter
    NOLOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS;


GRANT USAGE ON SCHEMA compliance
    TO compliance_exporter_owner;


GRANT USAGE ON SCHEMA compliance
    TO compliance_exporter;


-- The view owner receives the minimum underlying table access needed
-- to evaluate the approved exporter views.

GRANT SELECT ON
    compliance.compliance_findings,
    compliance.remediation_attempts,
    compliance.ticket_records
TO compliance_exporter_owner;


-- The application/exporter capability must never read the underlying
-- lifecycle tables directly.

REVOKE ALL PRIVILEGES ON
    compliance.compliance_findings,
    compliance.remediation_attempts,
    compliance.ticket_records
FROM compliance_exporter;


-- ============================================================================
-- 2. FINDING METRIC READ MODEL
-- ============================================================================

CREATE VIEW compliance.exporter_findings_summary AS
SELECT
    status,
    severity,
    remediation_mode,
    count(*)::BIGINT AS finding_count
FROM compliance.compliance_findings
GROUP BY
    status,
    severity,
    remediation_mode;


ALTER VIEW compliance.exporter_findings_summary
    OWNER TO compliance_exporter_owner;


REVOKE ALL PRIVILEGES ON
    compliance.exporter_findings_summary
FROM PUBLIC;


GRANT SELECT ON
    compliance.exporter_findings_summary
TO compliance_exporter;


-- ============================================================================
-- 3. REMEDIATION METRIC READ MODEL
-- ============================================================================

CREATE VIEW compliance.exporter_remediation_summary AS
SELECT
    remediation_state,
    remediation_policy,
    COALESCE(
        failure_class,
        'none'
    ) AS failure_class,
    count(*)::BIGINT AS attempt_count
FROM compliance.remediation_attempts
GROUP BY
    remediation_state,
    remediation_policy,
    COALESCE(
        failure_class,
        'none'
    );


ALTER VIEW compliance.exporter_remediation_summary
    OWNER TO compliance_exporter_owner;


REVOKE ALL PRIVILEGES ON
    compliance.exporter_remediation_summary
FROM PUBLIC;


GRANT SELECT ON
    compliance.exporter_remediation_summary
TO compliance_exporter;


-- ============================================================================
-- 4. ACTIVE TICKET METRIC READ MODEL
--
-- RESOLVED and CLOSED tickets are deliberately excluded.
-- ============================================================================

CREATE VIEW compliance.exporter_active_ticket_summary AS
SELECT
    provider,
    ticket_type,
    ticket_state,
    approval_state,
    count(*)::BIGINT AS ticket_count
FROM compliance.ticket_records
WHERE ticket_state NOT IN (
    'RESOLVED',
    'CLOSED'
)
GROUP BY
    provider,
    ticket_type,
    ticket_state,
    approval_state;


ALTER VIEW compliance.exporter_active_ticket_summary
    OWNER TO compliance_exporter_owner;


REVOKE ALL PRIVILEGES ON
    compliance.exporter_active_ticket_summary
FROM PUBLIC;


GRANT SELECT ON
    compliance.exporter_active_ticket_summary
TO compliance_exporter;


-- ============================================================================
-- 5. LOW-CARDINALITY OVERVIEW
-- ============================================================================

CREATE VIEW compliance.exporter_overview AS
SELECT

    (
        SELECT count(DISTINCT device)::BIGINT
        FROM compliance.compliance_findings
        WHERE status IN (
            'OPEN',
            'REMEDIATING'
        )
    ) AS devices_noncompliant,

    (
        SELECT count(*)::BIGINT
        FROM compliance.remediation_attempts
        WHERE remediation_state =
              'WAITING_FOR_APPROVAL'
    ) AS remediation_waiting_approval,

    (
        SELECT count(*)::BIGINT
        FROM compliance.ticket_records
        WHERE ticket_state NOT IN (
            'RESOLVED',
            'CLOSED'
        )
    ) AS active_tickets,

    (
        SELECT COALESCE(
            EXTRACT(
                EPOCH FROM (
                    now() - min(first_seen)
                )
            ),
            0
        )::DOUBLE PRECISION
        FROM compliance.compliance_findings
        WHERE status IN (
            'OPEN',
            'REMEDIATING'
        )
    ) AS oldest_open_seconds;


ALTER VIEW compliance.exporter_overview
    OWNER TO compliance_exporter_owner;


REVOKE ALL PRIVILEGES ON
    compliance.exporter_overview
FROM PUBLIC;


GRANT SELECT ON
    compliance.exporter_overview
TO compliance_exporter;


-- ============================================================================
-- 6. DOCUMENT SECURITY BOUNDARY
-- ============================================================================

COMMENT ON ROLE compliance_exporter_owner IS
    'NOLOGIN owner for V3 compliance exporter read-only views; has SELECT only on approved source tables';


COMMENT ON ROLE compliance_exporter IS
    'NOLOGIN runtime capability for V3 compliance exporter; may SELECT approved aggregate views only';


COMMENT ON VIEW compliance.exporter_findings_summary IS
    'Low-cardinality current compliance finding counts for Prometheus export';


COMMENT ON VIEW compliance.exporter_remediation_summary IS
    'Low-cardinality remediation lifecycle counts for Prometheus export';


COMMENT ON VIEW compliance.exporter_active_ticket_summary IS
    'Low-cardinality active operational ticket counts for Prometheus export';


COMMENT ON VIEW compliance.exporter_overview IS
    'Scalar V3 compliance operational metrics for Prometheus export';


COMMIT;
