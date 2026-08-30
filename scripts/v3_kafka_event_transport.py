#!/usr/bin/env python3

"""
Kafka transport adapter for V3 finding activation events.

The V3 event contract remains owned by v3_compliance_event.
Kafka delivery mechanics remain owned by kafka_event_transport.
"""

try:
    from scripts.kafka_event_transport import (
        publish_validated_event,
    )

    from scripts.v3_compliance_event import (
        validate_event,
    )

except ModuleNotFoundError:
    from kafka_event_transport import (
        publish_validated_event,
    )

    from v3_compliance_event import (
        validate_event,
    )


def publish_event(
    event,
    bootstrap_servers,
    topic,
    client_id,
    *,
    producer_factory=None,
    flush_timeout=10.0,
):
    return publish_validated_event(
        event,
        bootstrap_servers,
        topic,
        client_id,
        validator=validate_event,
        producer_factory=producer_factory,
        flush_timeout=flush_timeout,
    )
