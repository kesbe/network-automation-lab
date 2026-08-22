#!/usr/bin/env python3

import argparse
import hashlib
import json
import sys
from pathlib import Path


EVENT_TYPE = "NETWORK_COMPLIANCE_DRIFT_DETECTED"
SCHEMA_VERSION = "1.0"


def fail(message):
    raise ValueError(message)


def positive_int(value, field):
    try:
        result=int(value)
    except (TypeError, ValueError):
        fail(f"{field} must be an integer-compatible value")

    if result < 1:
        fail(f"{field} must be greater than zero")

    return result


def deterministic_event_id(run_id):
    material=f"{EVENT_TYPE}|{run_id}"

    digest=hashlib.sha256(
        material.encode("utf-8")
    ).hexdigest()[:32]

    return (
        "network-compliance-drift-"
        + digest
    )


def map_finding(finding):
    required=(
        "finding_id",
        "finding_fingerprint",
        "device",
        "policy_id",
        "severity",
        "ticket_required",
        "actual",
        "expected",
        "remediation",
    )

    for field in required:
        if field not in finding:
            fail(
                f"finding missing required field {field}"
            )

    remediation=finding["remediation"]

    if not isinstance(remediation, dict):
        fail("finding.remediation must be an object")

    mode=remediation.get("mode")

    if not isinstance(mode, str) or not mode:
        fail(
            "finding.remediation.mode must be non-empty"
        )

    if not isinstance(
        finding["ticket_required"],
        bool,
    ):
        fail(
            "finding.ticket_required must be boolean"
        )

    return {
        "finding_id":
            finding["finding_id"],

        "fingerprint":
            finding["finding_fingerprint"],

        "device":
            finding["device"],

        "policy_id":
            finding["policy_id"],

        "severity":
            finding["severity"],

        "ticket_required":
            finding["ticket_required"],

        "remediation_mode":
            mode,

        "observed":
            finding["actual"],

        "expected":
            finding["expected"],
    }


def build_event(job):
    artifacts=job.get("artifacts") or {}
    run=artifacts.get("compliance_run") or {}

    findings=run.get("findings") or []

    # Production invariant:
    # a clean run publishes no drift event.
    if len(findings) == 0:
        return None

    run_id=run.get("run_id")

    if not isinstance(run_id, str) or not run_id:
        fail("compliance_run.run_id is required")

    generated_at=run.get("generated_at")

    if not isinstance(generated_at, str) or not generated_at:
        fail("compliance_run.generated_at is required")

    compliance_job_id=positive_int(
        artifacts.get("compliance_job_id"),
        "artifacts.compliance_job_id",
    )

    aggregator_job_id=positive_int(
        artifacts.get("aggregator_job_id"),
        "artifacts.aggregator_job_id",
    )

    awx_job_id=positive_int(
        job.get("id"),
        "job.id",
    )

    if aggregator_job_id != awx_job_id:
        fail(
            "aggregator_job_id does not match AWX job id"
        )

    summary=run.get("summary") or {}

    required_summary=(
        "devices_checked",
        "devices_noncompliant",
        "total_findings",
        "critical_findings",
    )

    for field in required_summary:
        if field not in summary:
            fail(
                f"compliance_run.summary.{field} missing"
            )

    total_findings=int(
        summary["total_findings"]
    )

    if total_findings != len(findings):
        fail(
            "summary.total_findings does not match "
            "finding count"
        )

    devices_noncompliant=int(
        summary["devices_noncompliant"]
    )

    if devices_noncompliant < 1:
        fail(
            "drift event requires at least one "
            "noncompliant device"
        )

    mapped_findings=[
        map_finding(finding)
        for finding in findings
    ]

    return {
        "schema_version":
            SCHEMA_VERSION,

        "event_id":
            deterministic_event_id(run_id),

        "event_type":
            EVENT_TYPE,

        "occurred_at":
            generated_at,

        "producer": {
            "system":
                "awx",

            "component":
                "network-compliance-detector",

            "job_id":
                compliance_job_id,
        },

        "correlation": {
            "compliance_run_id":
                run_id,

            "compliance_job_id":
                compliance_job_id,

            "aggregator_job_id":
                aggregator_job_id,
        },

        "summary": {
            "devices_evaluated":
                int(summary["devices_checked"]),

            "devices_noncompliant":
                devices_noncompliant,

            "findings_total":
                total_findings,

            "findings_critical":
                int(summary["critical_findings"]),
        },

        "findings":
            mapped_findings,
    }


def main():
    parser=argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        required=True,
    )

    parser.add_argument(
        "--output",
        required=True,
    )

    args=parser.parse_args()

    source=Path(args.input)
    output=Path(args.output)

    try:
        job=json.loads(
            source.read_text()
        )

        event=build_event(job)

    except Exception as exc:
        print(
            "event_transform=FAIL "
            + str(exc)
        )
        return 1

    if event is None:
        if output.exists():
            output.unlink()

        print("finding_count=0")
        print("publish_event=NO")
        print("event_transform=NO_EVENT")
        return 0

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    )

    print(
        "event_id="
        + event["event_id"]
    )

    print(
        "compliance_run_id="
        + event["correlation"]
               ["compliance_run_id"]
    )

    print(
        "finding_count="
        + str(len(event["findings"]))
    )

    print("publish_event=YES")
    print("event_transform=PASS")

    return 0


if __name__ == "__main__":
    sys.exit(main())
