#!/usr/bin/env python3

import json


EVENT_TYPE = "NETWORK_COMPLIANCE_DRIFT_DETECTED"


def build_producer_config(
    bootstrap_servers,
    client_id,
):
    if (
        not isinstance(bootstrap_servers, str)
        or not bootstrap_servers.strip()
    ):
        raise ValueError(
            "bootstrap_servers must be non-empty"
        )

    if (
        not isinstance(client_id, str)
        or not client_id.strip()
    ):
        raise ValueError(
            "client_id must be non-empty"
        )

    return {
        "bootstrap.servers":
            bootstrap_servers,

        "client.id":
            client_id,

        "enable.idempotence":
            True,

        "acks":
            "all",

        "retries":
            2147483647,

        "max.in.flight.requests.per.connection":
            5,

        "delivery.timeout.ms":
            120000,

        "request.timeout.ms":
            30000,

        "socket.keepalive.enable":
            True,
    }


def validate_transport_event(event):
    if not isinstance(event, dict):
        raise ValueError(
            "event must be an object"
        )

    event_id=event.get("event_id")

    if (
        not isinstance(event_id, str)
        or not event_id
    ):
        raise ValueError(
            "event.event_id must be non-empty"
        )

    if event.get("event_type") != EVENT_TYPE:
        raise ValueError(
            "unsupported event_type"
        )

    correlation=event.get("correlation")

    if not isinstance(correlation, dict):
        raise ValueError(
            "event.correlation must be an object"
        )

    run_id=correlation.get(
        "compliance_run_id"
    )

    if (
        not isinstance(run_id, str)
        or not run_id
    ):
        raise ValueError(
            "event correlation compliance_run_id "
            "must be non-empty"
        )

    return event_id


def serialize_event(event):
    validate_transport_event(event)

    return json.dumps(
        event,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _default_producer_factory(config):
    from confluent_kafka import Producer

    return Producer(config)


def publish_event(
    event,
    bootstrap_servers,
    topic,
    client_id,
    *,
    producer_factory=None,
    flush_timeout=10.0,
):
    event_id=validate_transport_event(event)

    if (
        not isinstance(topic, str)
        or not topic.strip()
    ):
        raise ValueError(
            "topic must be non-empty"
        )

    if flush_timeout <= 0:
        raise ValueError(
            "flush_timeout must be greater than zero"
        )

    config=build_producer_config(
        bootstrap_servers,
        client_id,
    )

    factory=(
        producer_factory
        or _default_producer_factory
    )

    producer=factory(config)

    delivery={
        "completed": False,
        "error": None,
        "topic": None,
        "partition": None,
        "offset": None,
    }

    def on_delivery(error, message):
        delivery["completed"]=True

        if error is not None:
            delivery["error"]=str(error)
            return

        delivery["topic"]=message.topic()
        delivery["partition"]=message.partition()
        delivery["offset"]=message.offset()

    producer.produce(
        topic=topic,
        key=event_id.encode("utf-8"),
        value=serialize_event(event),
        on_delivery=on_delivery,
    )

    remaining=producer.flush(
        flush_timeout
    )

    if remaining:
        raise RuntimeError(
            "Kafka delivery timed out with "
            f"{remaining} undelivered message(s)"
        )

    if not delivery["completed"]:
        raise RuntimeError(
            "Kafka delivery callback was not invoked"
        )

    if delivery["error"] is not None:
        raise RuntimeError(
            "Kafka delivery failed: "
            + delivery["error"]
        )

    return {
        "event_id":
            event_id,

        "topic":
            delivery["topic"],

        "partition":
            delivery["partition"],

        "offset":
            delivery["offset"],
    }
