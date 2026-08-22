#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

BUILDER = (
    ROOT
    / "scripts"
    / "build_network_compliance_drift_event.py"
)

VALIDATOR = (
    ROOT
    / "scripts"
    / "validate_network_compliance_event.py"
)


def run_command(command):
    result = subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
    )

    if result.stdout:
        print(
            result.stdout,
            end=""
            if result.stdout.endswith("\n")
            else "\n",
        )

    if result.stderr:
        print(
            result.stderr,
            end=""
            if result.stderr.endswith("\n")
            else "\n",
            file=sys.stderr,
        )

    return result.returncode


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Build and validate a network compliance "
            "event without contacting Kafka."
        )
    )

    parser.add_argument(
        "--input",
        required=True,
        help="AWX aggregator API JSON input",
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Generated event JSON path",
    )

    parser.add_argument(
        "--transport",
        default="disabled",
        choices=(
            "disabled",
            "kafka",
        ),
    )

    args = parser.parse_args()

    output = Path(args.output)

    if output.exists():
        output.unlink()

    if args.transport != "disabled":
        print("transport_enablement=REFUSED")
        print("transport=KAFKA")
        print("publish_attempted=NO")
        print("kafka_contact_attempted=NO")
        print("publisher_offline_result=REFUSED")
        return 2

    build_rc = run_command(
        [
            sys.executable,
            str(BUILDER),
            "--input",
            args.input,
            "--output",
            str(output),
        ]
    )

    print(
        "publisher_transform_rc="
        + str(build_rc)
    )

    if build_rc != 0:
        print("publisher_decision=ERROR")
        print("publish_attempted=NO")
        print("kafka_contact_attempted=NO")
        print("publisher_offline_result=FAIL")
        return build_rc

    if not output.exists():
        print("publisher_decision=NO_EVENT")
        print("transport=DISABLED")
        print("publish_attempted=NO")
        print("kafka_contact_attempted=NO")
        print("publisher_offline_result=PASS")
        return 0

    validate_rc = run_command(
        [
            sys.executable,
            str(VALIDATOR),
            str(output),
        ]
    )

    print(
        "publisher_validation_rc="
        + str(validate_rc)
    )

    if validate_rc != 0:
        print("publisher_decision=INVALID_EVENT")
        print("publish_attempted=NO")
        print("kafka_contact_attempted=NO")
        print("publisher_offline_result=FAIL")
        return validate_rc

    event = json.loads(
        output.read_text()
    )

    findings = event.get("findings") or []

    print(
        "publisher_event_id="
        + str(event.get("event_id"))
    )

    print(
        "publisher_event_type="
        + str(event.get("event_type"))
    )

    print(
        "publisher_finding_count="
        + str(len(findings))
    )

    print("publisher_decision=EVENT_READY")
    print("transport=DISABLED")
    print("publish_attempted=NO")
    print("kafka_contact_attempted=NO")
    print("publisher_offline_result=PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
