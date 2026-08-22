#!/usr/bin/env python3

import json
import sys
from pathlib import Path


EXPECTED_EVENT_TYPE = "NETWORK_COMPLIANCE_DRIFT_DETECTED"

FORBIDDEN_TERMS = (
    "run_workflow_template",
    "workflow_template_id",
    "wf40",
    "awx_token",
    "awx_password",
    "credential_id",
)


def fail(message):
    print(f"FAIL: {message}")
    sys.exit(1)


def main():
    path = Path(
        sys.argv[1]
        if len(sys.argv) > 1
        else "examples/events/network_compliance_drift_event_v1.json"
    )

    data = json.loads(path.read_text())

    required = {
        "schema_version",
        "event_id",
        "event_type",
        "occurred_at",
        "producer",
        "correlation",
        "summary",
        "findings",
    }

    missing = required - set(data)

    if missing:
        fail(
            "missing top-level fields: "
            + ",".join(sorted(missing))
        )

    if data["schema_version"] != "1.0":
        fail("schema_version must be 1.0")

    if data["event_type"] != EXPECTED_EVENT_TYPE:
        fail("unexpected event_type")

    producer = data["producer"]

    if producer.get("system") != "awx":
        fail("producer.system must be awx")

    if (
        producer.get("component")
        != "network-compliance-detector"
    ):
        fail("unexpected producer.component")

    correlation = data["correlation"]

    for key in (
        "compliance_run_id",
        "compliance_job_id",
        "aggregator_job_id",
    ):
        if key not in correlation:
            fail(f"missing correlation.{key}")

    summary = data["summary"]
    findings = data["findings"]

    if not isinstance(findings, list) or not findings:
        fail("findings must contain at least one finding")

    if summary.get("findings_total") != len(findings):
        fail(
            "summary.findings_total does not match findings length"
        )

    if summary.get("devices_noncompliant", 0) < 1:
        fail("drift event requires noncompliant device")

    finding_ids = []

    for finding in findings:
        for key in (
            "finding_id",
            "fingerprint",
            "device",
            "policy_id",
            "severity",
            "ticket_required",
            "remediation_mode",
        ):
            if key not in finding:
                fail(
                    f"finding missing required field {key}"
                )

        finding_ids.append(
            finding["finding_id"]
        )

    if len(finding_ids) != len(set(finding_ids)):
        fail("duplicate finding_id in event")

    serialized = json.dumps(
        data,
        sort_keys=True
    ).lower()

    violations = [
        term
        for term in FORBIDDEN_TERMS
        if term in serialized
    ]

    if violations:
        fail(
            "consumer-routing/security fields found: "
            + ",".join(violations)
        )

    print("schema_version=PASS")
    print("event_type=PASS")
    print("producer_contract=PASS")
    print("correlation_contract=PASS")
    print("summary_contract=PASS")
    print("finding_contract=PASS")
    print("finding_uniqueness=PASS")
    print("consumer_routing_fields_absent=PASS")
    print("network_compliance_event_contract=PASS")


if __name__ == "__main__":
    main()
