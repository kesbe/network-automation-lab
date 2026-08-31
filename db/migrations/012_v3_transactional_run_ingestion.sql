BEGIN;


-- ============================================================================
-- V3 durable run-level persistence context
--
-- Stores the complete canonical V3 persistence context supplied alongside
-- the legacy compliance_run.
--
-- This is required even when a run produces zero activation events so that
-- an exact retry can prove that the immutable V3 context has not changed.
-- ============================================================================

CREATE TABLE compliance.v3_run_persistence_contexts (
    run_id                  TEXT PRIMARY KEY,

    persistence_context     JSONB NOT NULL,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT fk_v3_run_persistence_context_run
        FOREIGN KEY (run_id)
        REFERENCES compliance.compliance_runs(run_id)
        ON DELETE CASCADE,

    CONSTRAINT v3_run_persistence_context_object
        CHECK (
            jsonb_typeof(persistence_context) = 'object'
        ),

    CONSTRAINT v3_run_persistence_context_schema
        CHECK (
            persistence_context->>'schema_version' = '3.0'
        ),

    CONSTRAINT v3_run_persistence_context_identity
        CHECK (
            btrim(
                COALESCE(
                    persistence_context->>'compliance_run_id',
                    ''
                )
            ) = run_id
        ),

    CONSTRAINT v3_run_persistence_context_target
        CHECK (
            jsonb_typeof(
                persistence_context->'resolved_target'
            ) = 'object'
        ),

    CONSTRAINT v3_run_persistence_context_findings
        CHECK (
            jsonb_typeof(
                persistence_context->'findings'
            ) = 'array'
        )
);


CREATE INDEX idx_v3_run_persistence_context_created
    ON compliance.v3_run_persistence_contexts (
        created_at DESC
    );


COMMENT ON TABLE compliance.v3_run_persistence_contexts IS
'Immutable canonical V3 persistence context bound to one compliance run. Used to prove exact retry identity even when no activation event was emitted.';


-- ============================================================================
-- Transactional V3 run-level ingestion wrapper
--
-- External callers use this run-level boundary.
--
-- The existing ingest_compliance_run() remains authoritative for legacy run
-- persistence and lifecycle classification.
--
-- This function:
--
--   1. validates V3 persistence-context identity,
--   2. proves exact finding-ID equality with the legacy run,
--   3. calls ingest_compliance_run(),
--   4. persists the complete immutable V3 context for new runs,
--   5. selects only DETECTED / REOPENED lifecycle events,
--   6. stores canonical activation sources,
--   7. verifies exact immutable state on retry.
--
-- No legacy-to-V3 canonicalization occurs here.
-- ============================================================================

CREATE OR REPLACE FUNCTION compliance.ingest_v3_compliance_run(
    p_compliance_run       JSONB,
    p_persistence_context  JSONB,

    p_workflow_job_id      BIGINT DEFAULT NULL,
    p_compliance_job_id    BIGINT DEFAULT NULL,
    p_aggregator_job_id    BIGINT DEFAULT NULL,

    p_source               TEXT DEFAULT 'awx',
    p_actor                TEXT DEFAULT 'automation'
)
RETURNS TABLE (
    result_run_id               TEXT,
    result_status               TEXT,
    run_inserted                BOOLEAN,
    device_results_inserted     INTEGER,
    findings_processed          INTEGER,
    detected_count              INTEGER,
    seen_again_count            INTEGER,
    reopened_count              INTEGER,
    duplicate_finding_count     INTEGER,
    activation_sources_inserted INTEGER
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_run_id                    TEXT;
    v_context_run_id            TEXT;

    v_legacy_finding_count      INTEGER;
    v_context_finding_count     INTEGER;

    v_legacy_distinct_count     INTEGER;
    v_context_distinct_count    INTEGER;

    v_ingest_result             RECORD;

    v_existing_context          JSONB;

    v_detected_actual           INTEGER;
    v_reopened_actual           INTEGER;
    v_activation_actual         INTEGER;

    v_activation_sources_count  INTEGER;
    v_activation_inserted       INTEGER := 0;

BEGIN

    -- ========================================================================
    -- Validate top-level inputs.
    -- ========================================================================

    IF p_compliance_run IS NULL
       OR jsonb_typeof(p_compliance_run) <> 'object'
    THEN
        RAISE EXCEPTION
            'compliance_run must be a JSON object';
    END IF;


    IF p_persistence_context IS NULL
       OR jsonb_typeof(p_persistence_context) <> 'object'
    THEN
        RAISE EXCEPTION
            'persistence_context must be a JSON object';
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


    v_context_run_id :=
        btrim(
            COALESCE(
                p_persistence_context
                ->>'compliance_run_id',
                ''
            )
        );


    IF p_persistence_context->>'schema_version'
       IS DISTINCT FROM '3.0'
    THEN
        RAISE EXCEPTION
            'persistence_context.schema_version must be 3.0';
    END IF;


    IF v_context_run_id = '' THEN
        RAISE EXCEPTION
            'persistence_context.compliance_run_id is required';
    END IF;


    IF v_context_run_id <> v_run_id THEN
        RAISE EXCEPTION
            'V3 persistence context run identity mismatch: compliance_run %, persistence_context %',
            v_run_id,
            v_context_run_id;
    END IF;


    IF jsonb_typeof(
        p_compliance_run->'findings'
    ) <> 'array'
    THEN
        RAISE EXCEPTION
            'compliance_run.findings must be an array';
    END IF;


    IF jsonb_typeof(
        p_persistence_context->'findings'
    ) <> 'array'
    THEN
        RAISE EXCEPTION
            'persistence_context.findings must be an array';
    END IF;


    IF jsonb_typeof(
        p_persistence_context->'resolved_target'
    ) <> 'object'
    THEN
        RAISE EXCEPTION
            'persistence_context.resolved_target must be an object';
    END IF;


    -- ========================================================================
    -- Validate the resolved-target storage shape.
    --
    -- Full canonicalization remains owned by the accepted Python V3 contract.
    -- This SQL boundary validates only the durable structure required here.
    -- ========================================================================

    IF NOT (
        p_persistence_context
        ->'resolved_target'
        ?& ARRAY[
            'target_id',
            'selector',
            'devices',
            'device_count'
        ]
    )
    THEN
        RAISE EXCEPTION
            'persistence_context.resolved_target is missing required fields';
    END IF;


    IF btrim(
        COALESCE(
            p_persistence_context
            ->'resolved_target'
            ->>'target_id',
            ''
        )
    ) NOT LIKE 'target-%'
    THEN
        RAISE EXCEPTION
            'persistence_context resolved target_id is invalid';
    END IF;


    IF jsonb_typeof(
        p_persistence_context
        ->'resolved_target'
        ->'selector'
    ) <> 'object'
    THEN
        RAISE EXCEPTION
            'persistence_context resolved target selector must be an object';
    END IF;


    IF jsonb_typeof(
        p_persistence_context
        ->'resolved_target'
        ->'devices'
    ) <> 'array'
    THEN
        RAISE EXCEPTION
            'persistence_context resolved target devices must be an array';
    END IF;


    IF jsonb_typeof(
        p_persistence_context
        ->'resolved_target'
        ->'device_count'
    ) <> 'number'
    THEN
        RAISE EXCEPTION
            'persistence_context resolved target device_count must be numeric';
    END IF;


    IF (
        p_persistence_context
        ->'resolved_target'
        ->>'device_count'
    )::INTEGER
       <>
       jsonb_array_length(
           p_persistence_context
           ->'resolved_target'
           ->'devices'
       )
    THEN
        RAISE EXCEPTION
            'persistence_context resolved target device_count mismatch';
    END IF;


    IF jsonb_array_length(
        p_persistence_context
        ->'resolved_target'
        ->'devices'
    ) = 0
    THEN
        RAISE EXCEPTION
            'persistence_context resolved target must contain at least one device';
    END IF;


    -- ========================================================================
    -- Validate legacy finding identities.
    -- ========================================================================

    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(
            p_compliance_run->'findings'
        ) AS legacy_finding(value)
        WHERE
            jsonb_typeof(value) <> 'object'
            OR btrim(
                COALESCE(
                    value->>'finding_id',
                    ''
                )
            ) = ''
    )
    THEN
        RAISE EXCEPTION
            'compliance_run findings require non-empty finding_id';
    END IF;


    -- ========================================================================
    -- Validate canonical persistence finding storage shape.
    -- ========================================================================

    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(
            p_persistence_context->'findings'
        ) AS context_finding(value)
        WHERE
            jsonb_typeof(value) <> 'object'

            OR NOT (
                value
                ?& ARRAY[
                    'finding_id',
                    'device',
                    'vendor',
                    'platform',
                    'control',
                    'severity',
                    'status',
                    'remediable',
                    'remediation_policy',
                    'ticket_required'
                ]
            )

            OR btrim(
                COALESCE(
                    value->>'finding_id',
                    ''
                )
            ) = ''

            OR btrim(
                COALESCE(
                    value->>'device',
                    ''
                )
            ) = ''

            OR btrim(
                COALESCE(
                    value->>'vendor',
                    ''
                )
            ) = ''

            OR btrim(
                COALESCE(
                    value->>'platform',
                    ''
                )
            ) = ''

            OR btrim(
                COALESCE(
                    value->>'control',
                    ''
                )
            ) = ''

            OR btrim(
                COALESCE(
                    value->>'severity',
                    ''
                )
            ) = ''

            OR value->>'status'
               IS DISTINCT FROM 'NON_COMPLIANT'

            OR jsonb_typeof(
                value->'remediable'
            ) <> 'boolean'

            OR btrim(
                COALESCE(
                    value->>'remediation_policy',
                    ''
                )
            ) NOT IN (
                'auto',
                'approval_required',
                'manual',
                'observe_only',
                'blocked'
            )

            OR jsonb_typeof(
                value->'ticket_required'
            ) <> 'boolean'
    )
    THEN
        RAISE EXCEPTION
            'persistence_context finding storage contract is invalid';
    END IF;


    -- Approval-required findings must require a ticket.

    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(
            p_persistence_context->'findings'
        ) AS context_finding(value)
        WHERE
            value->>'remediation_policy'
                = 'approval_required'
            AND (
                value->>'ticket_required'
            )::BOOLEAN IS NOT TRUE
    )
    THEN
        RAISE EXCEPTION
            'approval_required persistence finding requires ticket_required=true';
    END IF;


    -- Non-remediable findings cannot carry executable policies.

    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(
            p_persistence_context->'findings'
        ) AS context_finding(value)
        WHERE
            (
                value->>'remediable'
            )::BOOLEAN IS FALSE
            AND value->>'remediation_policy'
                IN (
                    'auto',
                    'approval_required'
                )
    )
    THEN
        RAISE EXCEPTION
            'non-remediable persistence finding cannot use executable remediation policy';
    END IF;


    -- ========================================================================
    -- Finding -> resolved-target binding.
    --
    -- Every persistence finding must identify exactly one resolved target
    -- device and must carry the same vendor/platform identity.
    -- ========================================================================

    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(
            p_persistence_context->'findings'
        ) AS context_finding(finding)
        WHERE
            (
                SELECT count(*)
                FROM jsonb_array_elements(
                    p_persistence_context
                    ->'resolved_target'
                    ->'devices'
                ) AS target_device(device)
                WHERE
                    target_device.device->>'name'
                    =
                    context_finding.finding->>'device'
            ) <> 1
    )
    THEN
        RAISE EXCEPTION
            'persistence finding device must identify exactly one resolved target device';
    END IF;


    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(
            p_persistence_context->'findings'
        ) AS context_finding(finding)
        WHERE NOT EXISTS (
            SELECT 1
            FROM jsonb_array_elements(
                p_persistence_context
                ->'resolved_target'
                ->'devices'
            ) AS target_device(device)
            WHERE
                target_device.device->>'name'
                =
                context_finding.finding->>'device'

                AND target_device.device->>'vendor'
                =
                context_finding.finding->>'vendor'

                AND target_device.device->>'platform'
                =
                context_finding.finding->>'platform'
        )
    )
    THEN
        RAISE EXCEPTION
            'persistence finding vendor/platform conflicts with resolved target';
    END IF;


    -- ========================================================================
    -- Exact finding-ID equality.
    --
    -- The V3 persistence context contains every finding from the legacy run,
    -- including findings that will later classify as SEEN_AGAIN.
    -- ========================================================================

    SELECT
        count(*),
        count(
            DISTINCT btrim(
                value->>'finding_id'
            )
        )
    INTO
        v_legacy_finding_count,
        v_legacy_distinct_count
    FROM jsonb_array_elements(
        p_compliance_run->'findings'
    ) AS legacy_finding(value);


    SELECT
        count(*),
        count(
            DISTINCT btrim(
                value->>'finding_id'
            )
        )
    INTO
        v_context_finding_count,
        v_context_distinct_count
    FROM jsonb_array_elements(
        p_persistence_context->'findings'
    ) AS context_finding(value);


    IF v_legacy_finding_count
       <> v_legacy_distinct_count
    THEN
        RAISE EXCEPTION
            'compliance_run contains duplicate finding_id';
    END IF;


    IF v_context_finding_count
       <> v_context_distinct_count
    THEN
        RAISE EXCEPTION
            'persistence_context contains duplicate finding_id';
    END IF;


    IF v_legacy_finding_count
       <> v_context_finding_count
    THEN
        RAISE EXCEPTION
            'legacy/V3 persistence finding count mismatch';
    END IF;


    IF EXISTS (
        SELECT
            btrim(
                value->>'finding_id'
            )
        FROM jsonb_array_elements(
            p_compliance_run->'findings'
        ) AS legacy_finding(value)

        EXCEPT

        SELECT
            btrim(
                value->>'finding_id'
            )
        FROM jsonb_array_elements(
            p_persistence_context->'findings'
        ) AS context_finding(value)
    )
    OR EXISTS (
        SELECT
            btrim(
                value->>'finding_id'
            )
        FROM jsonb_array_elements(
            p_persistence_context->'findings'
        ) AS context_finding(value)

        EXCEPT

        SELECT
            btrim(
                value->>'finding_id'
            )
        FROM jsonb_array_elements(
            p_compliance_run->'findings'
        ) AS legacy_finding(value)
    )
    THEN
        RAISE EXCEPTION
            'legacy/V3 persistence finding identity set mismatch';
    END IF;


    -- ========================================================================
    -- Existing run-level lifecycle ingestion.
    --
    -- This nested call executes within the same PostgreSQL transaction.
    -- Any later exception in this wrapper rolls the entire operation back.
    -- ========================================================================

    SELECT *
    INTO v_ingest_result
    FROM compliance.ingest_compliance_run(
        p_compliance_run,
        p_workflow_job_id,
        p_compliance_job_id,
        p_aggregator_job_id,
        p_source,
        p_actor
    );


    IF v_ingest_result.result_status
       NOT IN (
           'INSERTED',
           'DUPLICATE'
       )
    THEN
        RAISE EXCEPTION
            'unexpected ingest_compliance_run result_status: %',
            v_ingest_result.result_status;
    END IF;


    -- ========================================================================
    -- Fresh V3 run.
    -- ========================================================================

    IF v_ingest_result.result_status = 'INSERTED'
    THEN

        INSERT INTO compliance.v3_run_persistence_contexts (
            run_id,
            persistence_context
        )
        VALUES (
            v_run_id,
            p_persistence_context
        );


        -- --------------------------------------------------------------------
        -- Discover the exact activation lifecycle set created by this run.
        -- --------------------------------------------------------------------

        SELECT
            count(*) FILTER (
                WHERE event_type = 'DETECTED'
            ),
            count(*) FILTER (
                WHERE event_type = 'REOPENED'
            ),
            count(*)
        INTO
            v_detected_actual,
            v_reopened_actual,
            v_activation_actual
        FROM compliance.finding_events
        WHERE
            run_id = v_run_id
            AND event_type IN (
                'DETECTED',
                'REOPENED'
            );


        -- --------------------------------------------------------------------
        -- The lifecycle summary returned by ingest_compliance_run() must agree
        -- with the durable event rows.
        -- --------------------------------------------------------------------

        IF v_detected_actual
           <> v_ingest_result.detected_count
        THEN
            RAISE EXCEPTION
                'DETECTED lifecycle count mismatch: result %, durable %',
                v_ingest_result.detected_count,
                v_detected_actual;
        END IF;


        IF v_reopened_actual
           <> v_ingest_result.reopened_count
        THEN
            RAISE EXCEPTION
                'REOPENED lifecycle count mismatch: result %, durable %',
                v_ingest_result.reopened_count,
                v_reopened_actual;
        END IF;


        IF v_activation_actual
           <>
           (
               v_ingest_result.detected_count
               +
               v_ingest_result.reopened_count
           )
        THEN
            RAISE EXCEPTION
                'activation lifecycle count mismatch';
        END IF;


        -- --------------------------------------------------------------------
        -- Defensive cardinality proof.
        --
        -- Normal ingest_finding() semantics already enforce this through the
        -- finding_occurrences (run_id, finding_id) primary key.
        --
        -- Do not alter finding_events; fail closed if the invariant is ever
        -- violated.
        -- --------------------------------------------------------------------

        IF EXISTS (
            SELECT
                finding_id
            FROM compliance.finding_events
            WHERE
                run_id = v_run_id
                AND event_type IN (
                    'DETECTED',
                    'REOPENED'
                )
            GROUP BY
                finding_id
            HAVING
                count(*) <> 1
        )
        THEN
            RAISE EXCEPTION
                'multiple activation lifecycle events exist for one run/finding';
        END IF;


        -- --------------------------------------------------------------------
        -- Every actual activation must have exactly one canonical V3 finding.
        -- --------------------------------------------------------------------

        IF EXISTS (
            SELECT 1
            FROM compliance.finding_events AS lifecycle_event
            WHERE
                lifecycle_event.run_id = v_run_id
                AND lifecycle_event.event_type IN (
                    'DETECTED',
                    'REOPENED'
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM jsonb_array_elements(
                        p_persistence_context->'findings'
                    ) AS context_finding(finding)
                    WHERE
                        btrim(
                            context_finding.finding
                            ->>'finding_id'
                        )
                        =
                        lifecycle_event.finding_id
                )
        )
        THEN
            RAISE EXCEPTION
                'activation lifecycle finding is absent from persistence context';
        END IF;


        -- --------------------------------------------------------------------
        -- Persist immutable activation sources.
        --
        -- SEEN_AGAIN is intentionally excluded.
        -- --------------------------------------------------------------------

        INSERT INTO compliance.v3_activation_sources (
            finding_event_id,
            run_id,
            finding_id,
            lifecycle_event_type,
            activated_at,
            finding_snapshot,
            resolved_target
        )
        SELECT
            lifecycle_event.event_id,
            lifecycle_event.run_id,
            lifecycle_event.finding_id,
            lifecycle_event.event_type,
            lifecycle_event.event_time,
            context_finding.finding,
            p_persistence_context->'resolved_target'
        FROM compliance.finding_events AS lifecycle_event
        JOIN LATERAL (
            SELECT
                value AS finding
            FROM jsonb_array_elements(
                p_persistence_context->'findings'
            ) AS context_element(value)
            WHERE
                btrim(
                    context_element.value
                    ->>'finding_id'
                )
                =
                lifecycle_event.finding_id
        ) AS context_finding
            ON TRUE
        WHERE
            lifecycle_event.run_id = v_run_id
            AND lifecycle_event.event_type IN (
                'DETECTED',
                'REOPENED'
            );


        GET DIAGNOSTICS
            v_activation_inserted = ROW_COUNT;


        IF v_activation_inserted
           <> v_activation_actual
        THEN
            RAISE EXCEPTION
                'activation-source insertion count mismatch: expected %, inserted %',
                v_activation_actual,
                v_activation_inserted;
        END IF;


        RETURN QUERY
        SELECT
            v_ingest_result.result_run_id,
            v_ingest_result.result_status,
            v_ingest_result.run_inserted,
            v_ingest_result.device_results_inserted,
            v_ingest_result.findings_processed,
            v_ingest_result.detected_count,
            v_ingest_result.seen_again_count,
            v_ingest_result.reopened_count,
            v_ingest_result.duplicate_finding_count,
            v_activation_inserted;


        RETURN;

    END IF;


    -- ========================================================================
    -- Exact retry.
    --
    -- A DUPLICATE legacy run is accepted as a V3 retry only when the complete
    -- V3 persistence context already exists and is byte-equivalent as JSONB.
    --
    -- This intentionally refuses retroactive V3 backfill of a run previously
    -- written only through the legacy API. That preserves the guarantee that
    -- V3 lifecycle classification and activation-source persistence were part
    -- of the same original transaction.
    -- ========================================================================

    SELECT
        persistence_context
    INTO
        v_existing_context
    FROM compliance.v3_run_persistence_contexts
    WHERE
        run_id = v_run_id;


    IF NOT FOUND THEN
        RAISE EXCEPTION
            'existing compliance run % has no transactional V3 persistence context',
            v_run_id;
    END IF;


    IF v_existing_context IS DISTINCT FROM
       p_persistence_context
    THEN
        RAISE EXCEPTION
            'V3 persistence context identity collision for run_id %',
            v_run_id;
    END IF;


    -- ------------------------------------------------------------------------
    -- Reconstruct expected activation set from durable lifecycle history.
    -- ------------------------------------------------------------------------

    SELECT
        count(*)
    INTO
        v_activation_actual
    FROM compliance.finding_events
    WHERE
        run_id = v_run_id
        AND event_type IN (
            'DETECTED',
            'REOPENED'
        );


    IF EXISTS (
        SELECT
            finding_id
        FROM compliance.finding_events
        WHERE
            run_id = v_run_id
            AND event_type IN (
                'DETECTED',
                'REOPENED'
            )
        GROUP BY
            finding_id
        HAVING
            count(*) <> 1
    )
    THEN
        RAISE EXCEPTION
            'multiple activation lifecycle events exist for one run/finding';
    END IF;


    SELECT
        count(*)
    INTO
        v_activation_sources_count
    FROM compliance.v3_activation_sources
    WHERE
        run_id = v_run_id;


    IF v_activation_sources_count
       <> v_activation_actual
    THEN
        RAISE EXCEPTION
            'stored V3 activation-source count mismatch: expected %, stored %',
            v_activation_actual,
            v_activation_sources_count;
    END IF;


    -- ------------------------------------------------------------------------
    -- Every expected activation row must still exactly match:
    --
    --   lifecycle identity
    --   canonical finding snapshot
    --   immutable resolved target
    --
    -- The 7F.5F composite FK additionally binds the copied lifecycle metadata
    -- back to the exact finding_events row.
    -- ------------------------------------------------------------------------

    IF EXISTS (
        SELECT 1
        FROM compliance.finding_events AS lifecycle_event

        LEFT JOIN LATERAL (
            SELECT
                value AS finding
            FROM jsonb_array_elements(
                p_persistence_context->'findings'
            ) AS context_element(value)
            WHERE
                btrim(
                    context_element.value
                    ->>'finding_id'
                )
                =
                lifecycle_event.finding_id
        ) AS context_finding
            ON TRUE

        LEFT JOIN compliance.v3_activation_sources AS source
            ON source.finding_event_id =
               lifecycle_event.event_id

        WHERE
            lifecycle_event.run_id = v_run_id
            AND lifecycle_event.event_type IN (
                'DETECTED',
                'REOPENED'
            )
            AND (
                context_finding.finding IS NULL

                OR source.finding_event_id IS NULL

                OR source.run_id IS DISTINCT FROM
                   lifecycle_event.run_id

                OR source.finding_id IS DISTINCT FROM
                   lifecycle_event.finding_id

                OR source.lifecycle_event_type
                   IS DISTINCT FROM
                   lifecycle_event.event_type

                OR source.activated_at IS DISTINCT FROM
                   lifecycle_event.event_time

                OR source.finding_snapshot IS DISTINCT FROM
                   context_finding.finding

                OR source.resolved_target IS DISTINCT FROM
                   p_persistence_context->'resolved_target'
            )
    )
    THEN
        RAISE EXCEPTION
            'stored V3 activation source does not match immutable retry context';
    END IF;


    RETURN QUERY
    SELECT
        v_ingest_result.result_run_id,
        v_ingest_result.result_status,
        v_ingest_result.run_inserted,
        v_ingest_result.device_results_inserted,
        v_ingest_result.findings_processed,
        v_ingest_result.detected_count,
        v_ingest_result.seen_again_count,
        v_ingest_result.reopened_count,
        v_ingest_result.duplicate_finding_count,
        0;


    RETURN;

END;
$$;


COMMENT ON FUNCTION compliance.ingest_v3_compliance_run(
    JSONB,
    JSONB,
    BIGINT,
    BIGINT,
    BIGINT,
    TEXT,
    TEXT
)
IS
'Atomically composes legacy compliance-run lifecycle ingestion with immutable canonical V3 run context and DETECTED/REOPENED activation-source persistence. Exact retries verify both V3 context and durable activation sources.';


-- ============================================================================
-- Security boundary
-- ============================================================================

REVOKE ALL PRIVILEGES
    ON TABLE compliance.v3_run_persistence_contexts
    FROM PUBLIC;

REVOKE ALL PRIVILEGES
    ON TABLE compliance.v3_run_persistence_contexts
    FROM compliance_ingest;


REVOKE ALL PRIVILEGES
    ON TABLE compliance.v3_activation_sources
    FROM PUBLIC;

REVOKE ALL PRIVILEGES
    ON TABLE compliance.v3_activation_sources
    FROM compliance_ingest;


GRANT SELECT, INSERT
    ON TABLE compliance.v3_run_persistence_contexts
    TO compliance_api_owner;

GRANT SELECT, INSERT
    ON TABLE compliance.v3_activation_sources
    TO compliance_api_owner;


REVOKE EXECUTE ON FUNCTION compliance.ingest_v3_compliance_run(
    JSONB,
    JSONB,
    BIGINT,
    BIGINT,
    BIGINT,
    TEXT,
    TEXT
) FROM PUBLIC;


-- Temporarily permit ownership transfer, matching the established
-- ingestion-security migration pattern.

GRANT CREATE ON SCHEMA compliance
    TO compliance_api_owner;


ALTER FUNCTION compliance.ingest_v3_compliance_run(
    JSONB,
    JSONB,
    BIGINT,
    BIGINT,
    BIGINT,
    TEXT,
    TEXT
)
OWNER TO compliance_api_owner;


REVOKE CREATE ON SCHEMA compliance
    FROM compliance_api_owner;


ALTER FUNCTION compliance.ingest_v3_compliance_run(
    JSONB,
    JSONB,
    BIGINT,
    BIGINT,
    BIGINT,
    TEXT,
    TEXT
)
SECURITY DEFINER;


ALTER FUNCTION compliance.ingest_v3_compliance_run(
    JSONB,
    JSONB,
    BIGINT,
    BIGINT,
    BIGINT,
    TEXT,
    TEXT
)
SET search_path = pg_catalog, compliance;


GRANT EXECUTE ON FUNCTION compliance.ingest_v3_compliance_run(
    JSONB,
    JSONB,
    BIGINT,
    BIGINT,
    BIGINT,
    TEXT,
    TEXT
) TO compliance_ingest;


COMMIT;
