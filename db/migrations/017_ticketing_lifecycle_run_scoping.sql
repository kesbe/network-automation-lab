BEGIN;


-- ============================================================================
-- RUN-SCOPED TICKETING LIFECYCLE READER
--
-- The existing production reader remains unchanged.
--
-- This reader is intentionally scoped inside the SECURITY DEFINER SQL
-- boundary so filtering occurs before ORDER BY / LIMIT.  This prevents an
-- unrelated unpublished lifecycle event from entering a controlled publisher
-- batch.
-- ============================================================================

CREATE FUNCTION compliance.read_unpublished_ticket_lifecycle_events_for_run(
    p_topic TEXT,
    p_run_id TEXT,
    p_limit INTEGER DEFAULT 100
)
RETURNS TABLE (
    source_event_id        BIGINT,
    source_finding_id      TEXT,
    run_id                 TEXT,
    lifecycle_event_type   TEXT,
    event_time             TIMESTAMPTZ,
    old_status             TEXT,
    new_status             TEXT,
    event_details          JSONB,
    finding_snapshot       JSONB
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, compliance
AS $$
BEGIN
    IF p_topic IS NULL
       OR btrim(p_topic) = ''
    THEN
        RAISE EXCEPTION
            'topic must not be empty';
    END IF;

    IF p_run_id IS NULL
       OR btrim(p_run_id) = ''
    THEN
        RAISE EXCEPTION
            'run_id must not be empty';
    END IF;

    IF p_limit IS NULL
       OR p_limit < 1
       OR p_limit > 1000
    THEN
        RAISE EXCEPTION
            'limit must be between 1 and 1000';
    END IF;

    RETURN QUERY
    SELECT
        fe.event_id,
        fe.finding_id,
        fe.run_id,
        fe.event_type,
        fe.event_time,
        fe.old_status,
        fe.new_status,
        fe.details,

        jsonb_build_object(
            'finding_id',
            cf.finding_id,
            'finding_fingerprint',
            cf.finding_fingerprint,
            'device',
            cf.device,
            'policy_id',
            cf.policy_id,
            'control',
            cf.control,
            'finding_scope',
            cf.finding_scope,
            'category',
            cf.category,
            'severity',
            cf.severity,
            'ticket_required',
            cf.ticket_required,
            'owner',
            cf.owner,
            'status',
            cf.status,
            'first_seen',
            cf.first_seen,
            'last_seen',
            cf.last_seen,
            'resolved_at',
            cf.resolved_at,
            'remediation_supported',
            cf.remediation_supported,
            'remediation_mode',
            cf.remediation_mode,
            'remediation_risk',
            cf.remediation_risk,
            'expected',
            cf.expected,
            'current_actual',
            cf.current_actual
        )

    FROM compliance.finding_events AS fe

    JOIN compliance.compliance_findings AS cf
      ON cf.finding_id = fe.finding_id

    LEFT JOIN compliance.lifecycle_event_publications AS pub
      ON pub.topic = p_topic
     AND pub.source_event_id = fe.event_id

    WHERE fe.event_type IN (
        'DETECTED',
        'SEEN_AGAIN',
        'REOPENED',
        'RESOLVED'
    )

      AND fe.run_id = p_run_id

      AND cf.ticket_required

      AND (
          pub.source_event_id IS NULL
          OR pub.state <> 'COMPLETED'
      )

    ORDER BY fe.event_id

    LIMIT p_limit;
END;
$$;


ALTER FUNCTION compliance.read_unpublished_ticket_lifecycle_events_for_run(
    TEXT,
    TEXT,
    INTEGER
)
OWNER TO compliance_api_owner;


REVOKE ALL
ON FUNCTION compliance.read_unpublished_ticket_lifecycle_events_for_run(
    TEXT,
    TEXT,
    INTEGER
)
FROM PUBLIC;


GRANT EXECUTE
ON FUNCTION compliance.read_unpublished_ticket_lifecycle_events_for_run(
    TEXT,
    TEXT,
    INTEGER
)
TO compliance_lifecycle_publisher;


COMMENT ON FUNCTION compliance.read_unpublished_ticket_lifecycle_events_for_run(
    TEXT,
    TEXT,
    INTEGER
) IS
'Reads unpublished ticket-required lifecycle events for one exact run_id, filtering before ordering and limiting.';


COMMIT;
