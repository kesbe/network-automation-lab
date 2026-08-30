-- ============================================================================
-- V3 transport-event identity
--
-- V2 drift events have one logical transport event per
-- (event_type, compliance_run_id).
--
-- V3 finding activation events are per-finding events. Multiple distinct
-- event_id values may therefore legitimately share the same event_type and
-- compliance_run_id.
--
-- event_id remains the durable transport idempotency identity.
-- ============================================================================

BEGIN;

-- Remove the global logical-event uniqueness boundary introduced by
-- migration 006. It is too broad for V3 per-finding activation events.
ALTER TABLE compliance.transport_events
    DROP CONSTRAINT transport_events_logical_event_unique;


-- Preserve the accepted V2 invariant:
--
--     one NETWORK_COMPLIANCE_DRIFT_DETECTED event per compliance run.
--
-- V3 NETWORK_COMPLIANCE_FINDING_ACTIVATED events are intentionally outside
-- this partial uniqueness boundary and remain idempotent by event_id.
CREATE UNIQUE INDEX
    idx_transport_events_v2_logical_event_unique
    ON compliance.transport_events (
        event_type,
        compliance_run_id
    )
    WHERE event_type =
        'NETWORK_COMPLIANCE_DRIFT_DETECTED';


COMMENT ON INDEX
    compliance.idx_transport_events_v2_logical_event_unique
IS
    'Preserves V2 one-drift-event-per-run identity while V3 finding '
    'activation events use event_id as transport identity.';


COMMIT;
