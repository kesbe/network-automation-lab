-- ============================================================================
-- V3 activation-source durability
--
-- A V3 compliance activation event requires information that is not fully
-- reconstructable from the legacy compliance finding tables alone:
--
--   - canonical V3 finding
--   - immutable resolved target
--
-- This table preserves that source material durably for activation lifecycle
-- transitions.
--
-- Important identity boundary:
--
--   finding_event_id
--       PostgreSQL lifecycle-event identity.
--
--   V3 event_id
--       Deterministically generated later by v3_compliance_event.py.
--
-- This migration defines storage only. The transactional V3 ingestion wrapper
-- that populates this table is intentionally introduced separately.
-- ============================================================================

BEGIN;


-- Provide a composite lifecycle identity that activation-source rows can
-- reference atomically. event_id remains the primary lifecycle identity;
-- this redundant unique key exists only to bind the copied lifecycle
-- metadata to that exact event row.
ALTER TABLE compliance.finding_events
    ADD CONSTRAINT finding_events_v3_activation_identity_unique
    UNIQUE (
        event_id,
        run_id,
        finding_id,
        event_type,
        event_time
    );


CREATE TABLE compliance.v3_activation_sources (
    finding_event_id       BIGINT PRIMARY KEY,

    run_id                 TEXT NOT NULL,
    finding_id             TEXT NOT NULL,

    lifecycle_event_type   TEXT NOT NULL,
    activated_at           TIMESTAMPTZ NOT NULL,

    finding_snapshot       JSONB NOT NULL,
    resolved_target        JSONB NOT NULL,

    created_at             TIMESTAMPTZ NOT NULL
                           DEFAULT now(),

    CONSTRAINT fk_v3_activation_lifecycle_event
        FOREIGN KEY (
            finding_event_id,
            run_id,
            finding_id,
            lifecycle_event_type,
            activated_at
        )
        REFERENCES compliance.finding_events (
            event_id,
            run_id,
            finding_id,
            event_type,
            event_time
        ),

    CONSTRAINT v3_activation_run_id_nonempty
        CHECK (
            btrim(run_id) <> ''
        ),

    CONSTRAINT v3_activation_finding_id_nonempty
        CHECK (
            btrim(finding_id) <> ''
        ),

    CONSTRAINT v3_activation_lifecycle
        CHECK (
            lifecycle_event_type IN (
                'DETECTED',
                'REOPENED'
            )
        ),

    CONSTRAINT v3_activation_finding_object
        CHECK (
            jsonb_typeof(finding_snapshot)
            = 'object'
        ),

    CONSTRAINT v3_activation_target_object
        CHECK (
            jsonb_typeof(resolved_target)
            = 'object'
        ),

    CONSTRAINT v3_activation_finding_required_fields
        CHECK (
            finding_snapshot ?& ARRAY[
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
        ),

    CONSTRAINT v3_activation_finding_identity
        CHECK (
            finding_snapshot->>'finding_id'
            = finding_id
        ),

    CONSTRAINT v3_activation_finding_status
        CHECK (
            finding_snapshot->>'status'
            = 'NON_COMPLIANT'
        ),

    CONSTRAINT v3_activation_target_required_fields
        CHECK (
            resolved_target ?& ARRAY[
                'target_id',
                'selector',
                'devices',
                'device_count'
            ]
        ),

    CONSTRAINT v3_activation_target_id_nonempty
        CHECK (
            btrim(
                COALESCE(
                    resolved_target->>'target_id',
                    ''
                )
            ) <> ''
        ),

    CONSTRAINT v3_activation_target_id_format
        CHECK (
            resolved_target->>'target_id'
            LIKE 'target-%'
        ),

    CONSTRAINT v3_activation_target_selector_object
        CHECK (
            jsonb_typeof(
                resolved_target->'selector'
            ) = 'object'
        ),

    CONSTRAINT v3_activation_target_devices_array
        CHECK (
            jsonb_typeof(
                resolved_target->'devices'
            ) = 'array'
        )
);


CREATE INDEX
    idx_v3_activation_sources_run
    ON compliance.v3_activation_sources (
        run_id
    );


CREATE INDEX
    idx_v3_activation_sources_finding
    ON compliance.v3_activation_sources (
        finding_id,
        activated_at DESC
    );


CREATE INDEX
    idx_v3_activation_sources_lifecycle_time
    ON compliance.v3_activation_sources (
        lifecycle_event_type,
        activated_at DESC
    );


COMMENT ON TABLE
    compliance.v3_activation_sources
IS
    'Durable canonical source snapshots for V3 DETECTED and REOPENED '
    'activation events. finding_event_id is the PostgreSQL lifecycle identity; '
    'the V3 transport event_id is derived later from the canonical event '
    'contract.';


COMMIT;
