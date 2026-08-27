# Network Compliance Production V2 — Operational Handoff

## Status

PRODUCTION V2 ACCEPTED

Acceptance date: 28 August 2026, Sydney.

## Production Entry Point

- AWX Project: 69 — Network Automation Lab - Production V2
- Source tag: v2.0.0-rc1-real-drift-accepted
- Accepted revision:
  940d75787f7d73f206c097f7ea3e2a3552f26583
- Project SCM update on launch: disabled
- Production workflow: WF74
- Production schedule: schedule 8 / SCH03
- Production schedule state: enabled
- Previous V1 schedule 7: disabled

## Production V2 Workflow

WF74:

1. JT70 — compliance detector
2. JT71 — compliance aggregator
3. JT72 — PostgreSQL persistence
4. JT73 — Kafka publisher

The aggregator is intentionally scoped to leaf01 for this accepted
production-v2 deployment.

The publisher uses the production Kafka bootstrap service.

## Accepted Clean Behaviour

Clean compliance:

- detector: COMPLIANT
- aggregator: one device checked
- findings: zero
- persistence: run inserted
- publisher: NO_EVENT
- Kafka contact: no
- Kafka publish: no
- WF56 launch: no
- WF40 launch: no

Accepted manual clean canary:

- WF74 job 848

Accepted first natural scheduled run:

- WF74 job 890
- launch_type: scheduled
- detector job 891
- aggregator job 892
- persistence job 893
- publisher job 894

## Accepted Drift Behaviour

Controlled drift:

maximum-paths 2 -> maximum-paths 1 on leaf01.

Evidence:

- mutation ad-hoc 854
- independent drift read 855
- WF74 drift job 856
- detector 857
- aggregator 858
- persistence 859
- publisher 860

Published event:

network-compliance-drift-b61a84d08b875e3068582cd44cd376ae

Compliance run:

compliance-285c122b-2c44-40ad-b385-6a0e82ed5881

Natural downstream:

- WF56 job 861
- WF40 job 864
- JT36 remediation job 875
- JT37 recheck job 877
- final independent device read 889

Transport ledger acceptance:

- state: COMPLETED
- attempt_count: 1
- duplicate_count: 0
- claim_workflow_job_id: 861

Final independent device state:

- leaf01 named host confirmed
- maximum-paths 1 absent
- maximum-paths 2 present

## Normal Operations

The expected daily clean path is:

schedule8
  -> WF74
  -> JT70
  -> JT71
  -> JT72
  -> JT73
  -> NO_EVENT

A clean run must not create WF56 or WF40 activity.

The expected drift path is:

schedule8
  -> WF74
  -> detector finds drift
  -> persistence
  -> Kafka publisher
  -> Kafka
  -> EDA
  -> WF56 durable wrapper
  -> WF40 remediation
  -> JT36 remediation
  -> JT37 recheck

## Operational Guardrails

Do not:

- manually launch JT70, JT71, JT72 or JT73 as a workaround
- manually publish an already attempted Kafka event
- manually launch WF56 or WF40 for an already published event
- run Project69 SCM update
- repoint Project69 away from the accepted tag
- enable schedule7 while schedule8 remains enabled
- mutate an accepted transport ledger record
- use write memory during controlled FRR testing
- trust Ansible rc=0 without named-host verification
- retry a consumed AWX POST merely because local parsing failed

## Schedule Rollback Procedure

Rollback is only for an explicitly approved production rollback.

Before rollback:

1. Confirm AWX is quiescent.
2. Confirm no WF74/WF56/WF40 remediation is active.
3. Read both schedules.
4. Confirm schedule8 is enabled and schedule7 disabled.

Rollback order:

1. Disable schedule8.
2. Read back and confirm both schedules are disabled.
3. Enable schedule7.
4. Read back and confirm:
   - schedule8 disabled
   - schedule7 enabled
5. Confirm AWX remains quiescent.

Never enable schedule7 first because that creates overlapping production
schedules.

## Runtime Failure Triage

If WF74 fails:

1. Do not relaunch automatically.
2. Inspect the exact failed workflow job.
3. Inspect runtime workflow nodes.
4. Identify detector/aggregator/persistence/publisher child.
5. Inspect child stdout/artifacts.
6. Determine whether Kafka contact or publication was attempted.
7. If publication was attempted, do not republish manually.
8. Correlate event_id and compliance_run_id in PostgreSQL.

If WF56/WF40 begins:

- allow the natural chain to reach terminal state
- do not restore the device while remediation is active
- perform independent device read only after the workflow is terminal

## Acceptance Jobs — Frozen Evidence

- 848 — corrected clean canary
- 856 — accepted real-drift canary
- 890 — first natural scheduled production-v2 execution

These jobs must not be replaced by manually created acceptance runs.
