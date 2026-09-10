# ServiceNow Ticketing Adapter — Phase 5A Offline Readiness

## Status

This document defines offline deployment-readiness artifacts only.

Current constraints:

- ServiceNow PDI is available but has not yet been contacted or validated.
- No real ServiceNow credential exists in this phase.
- Migration 018 must not be applied in this phase.
- The runtime image must not be built or pushed in this phase.
- Kubernetes resources must not be applied in this phase.
- Kafka consumption must not be started in this phase.
- Git push is outside this phase.

## Runtime architecture

The ServiceNow adapter uses the existing shared ticketing runtime image.

The shared image must contain:

- `scripts/ticketing_runtime_common.py`
- `scripts/ticketing_provider.py`
- `scripts/ticketing_lifecycle_publisher.py`
- `scripts/zammad_ticketing_adapter.py`
- `scripts/servicenow_ticketing_adapter.py`

The existing Zammad runtime remains preserved.

No additional Python dependency is required for the ServiceNow HTTP client because
the provider uses Python standard-library `urllib`.

The existing runtime dependencies remain:

- `confluent-kafka==2.15.0`
- `psycopg2-binary==2.9.12`

## Database runtime configuration

Non-secret configuration:

- `TICKETING_DB_HOST`
- `TICKETING_DB_PORT`
- `TICKETING_DB_NAME`

Secret configuration:

- `TICKETING_DB_USER`
- `TICKETING_DB_PASSWORD`

## Kafka runtime configuration

- `TICKETING_KAFKA_BOOTSTRAP_SERVERS`
- `TICKETING_LIFECYCLE_TOPIC=network.compliance.lifecycle.events`
- `TICKETING_SERVICENOW_CONSUMER_GROUP=servicenow-network-compliance-production-v1`
- `TICKETING_RECEIPT_LEASE_SECONDS=300`
- `TICKETING_CONSUMER_POLL_SECONDS=5`

`TICKETING_ADAPTER_INSTANCE_ID` is intentionally omitted from the Phase 5A
manifest so the runtime's hostname default remains effective.

## ServiceNow configuration

Required before runtime activation:

- `TICKETING_SERVICENOW_BASE_URL`
- `TICKETING_SERVICENOW_ACTIVE_STATE`
- `TICKETING_SERVICENOW_RESOLVED_STATE`
- `TICKETING_SERVICENOW_AUTHORIZATION`

Optional values are intentionally omitted until the PDI contract is known:

- `TICKETING_SERVICENOW_ASSIGNMENT_GROUP`
- `TICKETING_SERVICENOW_RESOLUTION_CODE`

## PDI prerequisites

Before any live API validation, determine and verify:

1. PDI instance URL.
2. Supported authorization mechanism.
3. Incident table read access.
4. Incident table create access.
5. Incident table update access.
6. Access to `correlation_id`.
7. Access to `sys_id`.
8. Access to `number`.
9. Access to `state`.
10. Actual active-state value.
11. Actual resolved-state value.
12. Optional assignment-group value if used.
13. Optional resolution/close-code value if required.

The identity contract remains:

- local `external_ticket_id` = ServiceNow `sys_id`
- local `external_ticket_number` = ServiceNow incident number
- local finding ID = ServiceNow `correlation_id`

## Phase 5A Kubernetes safeguards

The Deployment is deliberately non-activated:

- `replicas: 0`
- image points to `example.invalid`
- the real Secret does not exist
- `secret-template.yaml` is excluded from `kustomization.yaml`

These safeguards are intentional and must not be removed during Phase 5A.

The pod does not need Kubernetes API access, therefore:

- no dedicated Kubernetes API permissions are required;
- service-account token automount is disabled.

The container runs as UID/GID 1000 with:

- non-root execution;
- no privilege escalation;
- all Linux capabilities dropped;
- RuntimeDefault seccomp;
- read-only root filesystem;
- writable `/tmp` supplied through `emptyDir`.

## Health strategy

No synthetic HTTP or exec health probe is added during Phase 5A.

The adapter currently exposes no dedicated health endpoint. A probe that merely
checks Python would not prove Kafka, database, or ServiceNow readiness and could
provide a false signal.

Health/readiness behavior must therefore be designed and validated in a later
runtime activation phase.

## Migration 018 pre-apply boundary

Migration 018 must remain unapplied during Phase 5A.

Before a future apply phase:

1. Explicitly authorize database access and migration application.
2. Confirm the intended target database.
3. Confirm the migration source hash is still the reconciled version.
4. Confirm the runtime role and wrapper contract expected by the committed
   ServiceNow adapter.
5. Establish a database rollback/recovery procedure.
6. Run the existing migration contract tests.
7. Apply migration 018 once under a dedicated authorization.
8. Reconcile the resulting database objects before any adapter activation.

## PDI validation sequence

Because a PDI is now available, live validation still requires a separately authorized phase:

1. Determine the PDI URL and state values.
2. Create the least-privilege integration credential.
3. Perform a read-only connectivity test.
4. Validate exact `correlation_id` lookup.
5. Validate incident field permissions.
6. Perform one controlled create test.
7. Verify returned `sys_id` and incident number.
8. Perform controlled resolve/reopen tests on that same `sys_id`.
9. Only after successful reconciliation proceed toward runtime activation.

## Runtime activation boundary

Runtime activation is not part of Phase 5A.

A later activation phase must independently reconcile:

- built image digest;
- runtime Secret;
- ConfigMap;
- migration 018 database state;
- Kafka topic/group;
- PDI access;
- Deployment manifest;
- initial replica transition from `0` to an authorized value.

## Rollback principle

Before activation, rollback is simply preservation of `replicas: 0`.

After a future activation, the first containment action for adapter-specific
failure should be to return the ServiceNow adapter to zero replicas without
altering the existing Zammad runtime.

Database rollback must use the procedure approved for the migration phase and
must never be improvised by the runtime deployment phase.
