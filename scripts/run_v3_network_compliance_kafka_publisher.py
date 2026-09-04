#!/usr/bin/env python3

"""
Production Kafka publisher for canonical V3 compliance events.

This adapter does not construct V3 events.

Responsibilities:
- load canonical V3 event JSON
- validate the V3 event contract
- enforce the production Kafka topic
- publish through the V3 Kafka transport
- verify the delivery receipt
"""

import argparse
import json
import sys
from pathlib import Path


PRODUCTION_TOPIC = (
    "network.compliance.events"
)


try:
    from scripts.v3_compliance_event import (
        validate_event,
    )

    from scripts.v3_kafka_event_transport import (
        publish_event,
    )

except ModuleNotFoundError:
    from v3_compliance_event import (
        validate_event,
    )

    from v3_kafka_event_transport import (
        publish_event,
    )


def validate_bootstrap_servers(
    bootstrap_servers,
):
    if (
        not isinstance(
            bootstrap_servers,
            str,
        )
        or not bootstrap_servers.strip()
    ):
        raise ValueError(
            "bootstrap_servers must be non-empty"
        )


def load_event(
    input_path,
):
    path = Path(
        input_path
    )

    event = json.loads(
        path.read_text()
    )

    validate_event(
        event
    )

    return event


def execute(
    input_path,
    bootstrap_servers,
    client_id,
    *,
    publisher=publish_event,
):
    validate_bootstrap_servers(
        bootstrap_servers
    )

    event = load_event(
        input_path
    )

    receipt = publisher(
        event,
        bootstrap_servers,
        PRODUCTION_TOPIC,
        client_id,
    )

    if not isinstance(
        receipt,
        dict,
    ):
        raise RuntimeError(
            "delivery receipt must be an object"
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
        "v3_production_publisher_decision="
        "EVENT_PUBLISHED"
    )

    print(
        "published_event_id="
        + str(
            receipt["event_id"]
        )
    )

    print(
        "published_topic="
        + str(
            receipt["topic"]
        )
    )

    print(
        "published_partition="
        + str(
            receipt["partition"]
        )
    )

    print(
        "published_offset="
        + str(
            receipt["offset"]
        )
    )

    return {
        "decision":
            "EVENT_PUBLISHED",

        "event":
            event,

        "receipt":
            receipt,
    }


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Publish a canonical V3 network "
            "compliance event to Kafka."
        )
    )

    parser.add_argument(
        "--input",
        required=True,
        help=(
            "Canonical V3 compliance "
            "event JSON"
        ),
    )

    parser.add_argument(
        "--bootstrap-servers",
        required=True,
    )

    parser.add_argument(
        "--client-id",
        default=(
            "network-compliance-v3-publisher"
        ),
    )

    args = parser.parse_args()

    try:
        execute(
            args.input,
            args.bootstrap_servers,
            args.client_id,
        )

    except Exception as exc:
        print(
            "v3_production_publisher_result="
            "FAIL "
            + str(exc),
            file=sys.stderr,
        )

        print(
            "kafka_record_published=NO",
            file=sys.stderr,
        )

        return 1

    print(
        "v3_production_publisher_result=PASS"
    )

    print(
        "kafka_record_published=YES"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
