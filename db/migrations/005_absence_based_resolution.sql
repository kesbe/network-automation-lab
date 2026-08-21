BEGIN;

-- =====================================================================
-- Migration 005
--
-- Resolve canonical findings that are absent from a later completed
-- compliance scan for the same device.
--
-- Design properties:
--
--   * Does not change ingest_compliance_run() signature or return shape.
--   * Runs only for a genuinely inserted compliance_runs row.
--   * Deferred until transaction end so run_devices and occurrences
--     created by ingest_compliance_run() are already present.
--   * Does not resolve findings for devices absent from the run.
--   * Does not resolve findings from incomplete/error device results.
--   * Historical clean scans cannot resolve newer findings.
--   * SUPPRESSED findings remain under governance control.
--   * Duplicate run retries cannot generate duplicate resolution events
--     because duplicate ingestion does not INSERT compliance_runs.
--
-- =====================================================================


CREATE OR REPLACE FUNCTION
    compliance.resolve_absent_findings_after_run()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, compliance
AS $$
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


    RETURN NEW;

END;
$$;


-- The trigger function is an internal persistence primitive.
-- Callers do not need direct EXECUTE privilege.
ALTER FUNCTION
    compliance.resolve_absent_findings_after_run()
OWNER TO compliance_api_owner;

REVOKE ALL
ON FUNCTION compliance.resolve_absent_findings_after_run()
FROM PUBLIC;

REVOKE ALL
ON FUNCTION compliance.resolve_absent_findings_after_run()
FROM compliance_ingest;


DROP TRIGGER IF EXISTS
    trg_resolve_absent_findings_after_run
ON compliance.compliance_runs;


-- A constraint trigger gives us DEFERRABLE / INITIALLY DEFERRED
-- semantics. It executes after ingest_compliance_run() has inserted
-- run_devices and finding_occurrences.
CREATE CONSTRAINT TRIGGER
    trg_resolve_absent_findings_after_run

AFTER INSERT
ON compliance.compliance_runs

DEFERRABLE
INITIALLY DEFERRED

FOR EACH ROW

EXECUTE FUNCTION
    compliance.resolve_absent_findings_after_run();


COMMENT ON FUNCTION
    compliance.resolve_absent_findings_after_run()
IS
    'Deferred internal lifecycle handler that resolves OPEN or REMEDIATING findings absent from a later completed compliance scan for the same device.';


COMMIT;
