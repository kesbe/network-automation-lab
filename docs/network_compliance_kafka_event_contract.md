# Network Compliance Kafka Event Contract

## Event type

`NETWORK_COMPLIANCE_DRIFT_DETECTED`

## Purpose

Signals that one completed network compliance detection run found
one or more actionable compliance findings.

## Publication invariant

Exactly one drift event is published for each completed
`compliance_run_id` when `findings_total > 0`.

The event is run-scoped, not finding-scoped.

Multiple findings from the same compliance run MUST NOT result in
multiple workflow-trigger events.

## Correlation

`event_id`
- Unique transport event identifier.

`correlation.compliance_run_id`
- Stable compliance-run correlation identifier.

`correlation.compliance_job_id`
- AWX compliance detector job.

`correlation.aggregator_job_id`
- AWX aggregation job producing the run-level result.

`finding_id`
- Stable canonical finding identity.

`fingerprint`
- Stable issue fingerprint.

## Consumer independence

The producer event MUST NOT contain:

- AWX credentials
- AWX tokens
- workflow template IDs
- WF40
- run_workflow_template
- EDA activation IDs

Consumer routing belongs to EDA, not to the producer.

## Safety

Publishing this event alone does not authorize remediation.

EDA applies the automation policy and determines whether an AWX
workflow may be invoked.

## Versioning

`schema_version` is currently `1.0`.

Breaking contract changes require a new schema version.
