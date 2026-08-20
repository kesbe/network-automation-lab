BEGIN;


CREATE OR REPLACE FUNCTION compliance.ingest_compliance_run(
    p_compliance_run      JSONB,
    p_workflow_job_id     BIGINT DEFAULT NULL,
    p_compliance_job_id   BIGINT DEFAULT NULL,
    p_aggregator_job_id   BIGINT DEFAULT NULL,
    p_source              TEXT DEFAULT 'awx',
    p_actor               TEXT DEFAULT 'automation'
)
RETURNS TABLE (
    result_run_id              TEXT,
    result_status              TEXT,
    run_inserted               BOOLEAN,
    device_results_inserted    INTEGER,
    findings_processed         INTEGER,
    detected_count             INTEGER,
    seen_again_count           INTEGER,
    reopened_count             INTEGER,
    duplicate_finding_count    INTEGER
)
LANGUAGE plpgsql
AS $$
DECLARE
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
                    v_finding->>'policy_name'
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
$$;


COMMENT ON FUNCTION compliance.ingest_compliance_run(
    JSONB,
    BIGINT,
    BIGINT,
    BIGINT,
    TEXT,
    TEXT
)
IS
'Atomically persists one JT38 compliance_run, its per-device results, and canonical finding occurrences. Same run_id and payload is idempotent; run_id reuse with different content is rejected.';


COMMIT;
