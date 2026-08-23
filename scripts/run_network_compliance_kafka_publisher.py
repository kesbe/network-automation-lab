#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

OFFLINE_PUBLISHER = (
    ROOT
    / "scripts"
    / "run_network_compliance_publisher.py"
)

PRODUCTION_TOPIC = "network.compliance.events"


try:
    from scripts.kafka_event_transport import publish_event
except ModuleNotFoundError:
    from kafka_event_transport import publish_event


def validate_bootstrap_servers(
    bootstrap_servers,
):
    if (
        not isinstance(bootstrap_servers, str)
        or not bootstrap_servers.strip()
    ):
        raise ValueError(
            "bootstrap_servers must be non-empty"
        )


def build_event_offline(
    input_path,
    output_path,
):
    result = subprocess.run(
        [
            sys.executable,
            str(OFFLINE_PUBLISHER),
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--transport",
            "disabled",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    if result.stdout:
        print(
            result.stdout,
            end="",
        )

    if result.stderr:
        print(
            result.stderr,
            end="",
            file=sys.stderr,
        )

    if result.returncode != 0:
        raise RuntimeError(
            "offline event preparation failed"
        )


def execute(
    input_path,
    output_path,
    bootstrap_servers,
    client_id,
    *,
    publisher=publish_event,
):
    validate_bootstrap_servers(
        bootstrap_servers
    )

    output = Path(output_path)

    if output.exists():
        output.unlink()

    build_event_offline(
        input_path,
        output,
    )

    if not output.exists():
        print(
            "production_publisher_decision="
            "NO_EVENT"
        )

        print(
            "producer_instantiated=NO"
        )

        print(
            "kafka_publish_attempted=NO"
        )

        return {
            "decision": "NO_EVENT",
            "receipt": None,
        }

    event = json.loads(
        output.read_text()
    )

    receipt = publisher(
        event,
        bootstrap_servers,
        PRODUCTION_TOPIC,
        client_id,
    )

    if (
        receipt.get("event_id")
        != event.get("event_id")
    ):
        raise RuntimeError(
            "delivery receipt event_id mismatch"
        )

    if (
        receipt.get("topic")
        != PRODUCTION_TOPIC
    ):
        raise RuntimeError(
            "delivery receipt topic mismatch"
        )

    print(
        "production_publisher_decision="
        "EVENT_PUBLISHED"
    )

    print(
        "published_event_id="
        + str(receipt["event_id"])
    )

    print(
        "published_topic="
        + str(receipt["topic"])
    )

    print(
        "published_partition="
        + str(receipt["partition"])
    )

    print(
        "published_offset="
        + str(receipt["offset"])
    )

    return {
        "decision":
            "EVENT_PUBLISHED",

        "receipt":
            receipt,
    }


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        required=True,
    )

    parser.add_argument(
        "--output",
        required=True,
    )

    parser.add_argument(
        "--bootstrap-servers",
        required=True,
    )

    parser.add_argument(
        "--client-id",
        default=(
            "network-compliance-publisher"
        ),
    )

    args = parser.parse_args()

    try:
        result = execute(
            args.input,
            args.output,
            args.bootstrap_servers,
            args.client_id,
        )

    except Exception as exc:
        print(
            "production_publisher_result=FAIL "
            + str(exc),
            file=sys.stderr,
        )

        return 1

    print(
        "production_publisher_result=PASS"
    )

    if result["decision"] == "NO_EVENT":
        print(
            "kafka_record_published=NO"
        )
    else:
        print(
            "kafka_record_published=YES"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
