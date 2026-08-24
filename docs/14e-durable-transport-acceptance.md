# Durable Kafka-to-AWX Transport — Acceptance Evidence

## Status

**PASS**

`PHASE_4A_5O_14E=DURABLE_TRANSPORT_IDEMPOTENCY_ACCEPTANCE_PASS`

## Scope

Validated durable and idempotent transport across:

```text
Kafka -> Event-Driven Ansible -> AWX WF56 -> PostgreSQL transport ledger -> AWX WF40
```

The objective was to allow at-least-once Kafka delivery while preventing duplicate remediation for the same logical compliance event.

## Production Components

- AWX durable wrapper: WF56
- AWX remediation workflow: WF40
- Claim template: JT52
- Claim classifier: JT53
- Complete template: JT54
- Fail template: JT55
- Kafka topic: `network.compliance.events`
- Consumer group: `eda-network-compliance-production-v1`
- Ledger: `compliance.transport_events`
- Production rulebook commit: `f54c4a2569196f82fe90f65021fd5c31b213892b`

## Acceptance Matrix

| Scenario | Result | Status |
|---|---|---|
| First delivery | `CLAIMED_NEW`, remediation executed | PASS |
| Completed duplicate | `DUPLICATE_COMPLETED`, remediation suppressed | PASS |
| Live duplicate | `DUPLICATE_INFLIGHT`, original owner preserved | PASS |
| Expired lease | `STALE_CLAIM`, fail closed | PASS |
| Explicit reconciliation | `CLAIMED_RECONCILED`, ownership transferred | PASS |
| Previous-owner fencing | old owner rejected after transfer | PASS |
| Consumer lag | zero on every partition | PASS |
| Temporary workflow cleanup | WF57/WF58 removed | PASS |
| Acceptance pod cleanup | completed publisher pods removed | PASS |

## Event Evidence

### First delivery / completed duplicate

```text
event_id=network-compliance-drift-ef4fa595a087c954874eb4a69fbabce0
run_id=wf56-production-acceptance-20260824T075145Z-43f1573a-62f8-4726-904b-c95a69a047b7
owner=597
final_state=COMPLETED
attempt_count=1
duplicate_count=1
```

### Live duplicate

```text
event_id=network-compliance-drift-5e584ed4f23b094b00b1ddac73141165
run_id=wf56-inflight-acceptance-20260824T092752Z-71aa015c-b06c-4513-b9ad-bb0d6dada842
owner=618
duplicate_decision=DUPLICATE_INFLIGHT
final_state=COMPLETED
attempt_count=1
duplicate_count=1
```

### Stale claim and reconciliation

```text
event_id=network-compliance-drift-6e3b7c970cb023d461de1b472e2333a2
run_id=wf57-stale-claim-20260824T094937Z-bc8e1a2d-7ed8-4a23-9c7c-cf2d63afecb4
initial_owner=637
stale_decision=STALE_CLAIM
reconciled_owner=645
reconciliation_decision=CLAIMED_RECONCILED
old_owner_completion=REJECTED
new_owner_completion=COMPLETED
final_state=COMPLETED
attempt_count=2
duplicate_count=1
```

## Final Runtime Evidence

```text
WF56_count=3
WF40_count=10
Kafka_partition_0=4
Kafka_partition_1=0
Kafka_partition_2=3
EDA_consumer_lag=0
WF57=REMOVED
WF58=REMOVED
acceptance_test_pods=REMOVED
```

## Reliability Properties

```text
NEW EVENT
  -> CLAIMED_NEW
  -> remediation
  -> COMPLETED

COMPLETED DUPLICATE
  -> DUPLICATE_COMPLETED
  -> suppress remediation

LIVE DUPLICATE
  -> DUPLICATE_INFLIGHT
  -> preserve original owner
  -> suppress remediation

EXPIRED CLAIM
  -> STALE_CLAIM
  -> fail closed
  -> no automatic takeover

EXPLICIT RECONCILIATION
  -> CLAIMED_RECONCILED
  -> transfer ownership
  -> fence previous owner
  -> controlled completion
```

## Engineering Conclusion

Kafka at-least-once delivery is compatible with effectively once-per-logical-event remediation through durable idempotency, duplicate suppression, lease-based ownership, stale-claim fail-closed behavior, explicit privileged reconciliation, and previous-owner fencing.

## Final Freeze

```text
first_delivery=PASS
duplicate_completed=PASS
duplicate_inflight=PASS
stale_claim_fail_closed=PASS
explicit_stale_reconciliation=PASS
old_owner_fencing=PASS
wf56_count=3
wf40_count=10
kafka_offsets=4,0,3
consumer_lag=0
temporary_workflows_removed=PASS
transport_ledger_preserved=PASS
acceptance_test_pods_removed=PASS
PHASE_4A_5O_14E=DURABLE_TRANSPORT_IDEMPOTENCY_ACCEPTANCE_PASS
PHASE_4A_5O_14F_B=ACCEPTANCE_RUNTIME_CLEANUP_PASS
```
