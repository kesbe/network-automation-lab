import json
import unittest

from scripts.v3_kafka_event_transport import (
    publish_event,
)

from scripts.v3_compliance_event import (
    build_event,
)

from tests.test_v3_compliance_event import (
    make_finding,
    make_target,
)


class FakeMessage:

    def __init__(
        self,
        topic,
        partition=2,
        offset=84,
    ):
        self._topic = topic
        self._partition = partition
        self._offset = offset

    def topic(self):
        return self._topic

    def partition(self):
        return self._partition

    def offset(self):
        return self._offset


class FakeProducer:

    def __init__(
        self,
        config,
        *,
        delivery_error=None,
        flush_remaining=0,
        invoke_callback=True,
    ):
        self.config = config
        self.delivery_error = delivery_error
        self.flush_remaining = flush_remaining
        self.invoke_callback = invoke_callback
        self.produced = []

    def produce(
        self,
        *,
        topic,
        key,
        value,
        on_delivery,
    ):
        self.produced.append(
            {
                "topic":
                    topic,

                "key":
                    key,

                "value":
                    value,
            }
        )

        if self.invoke_callback:
            on_delivery(
                self.delivery_error,
                FakeMessage(topic),
            )

    def flush(
        self,
        timeout,
    ):
        self.flush_timeout = timeout

        return self.flush_remaining


def sample_event():
    return build_event(
        finding=make_finding(),
        resolved_target=make_target(),
        lifecycle_event_type="DETECTED",
        compliance_run_id=
            "phase7f5d-v3-kafka-test",
        activated_at=
            "2026-08-31T01:30:00+10:00",
    )


class V3KafkaEventTransportTests(
    unittest.TestCase
):

    def test_valid_v3_event_publishes(self):
        holder = {}

        def factory(config):
            producer = FakeProducer(
                config
            )

            holder["producer"] = (
                producer
            )

            return producer

        event = sample_event()

        receipt = publish_event(
            event,
            "kafka.example:9092",
            "network.compliance.events",
            "v3-publisher-test",
            producer_factory=factory,
        )

        self.assertEqual(
            receipt["event_id"],
            event["event_id"],
        )

        self.assertEqual(
            receipt["topic"],
            "network.compliance.events",
        )

        self.assertEqual(
            receipt["partition"],
            2,
        )

        self.assertEqual(
            receipt["offset"],
            84,
        )

    def test_event_id_is_message_key(self):
        holder = {}

        def factory(config):
            producer = FakeProducer(
                config
            )

            holder["producer"] = (
                producer
            )

            return producer

        event = sample_event()

        publish_event(
            event,
            "kafka.example:9092",
            "network.compliance.events",
            "v3-publisher-test",
            producer_factory=factory,
        )

        produced = (
            holder["producer"]
            .produced[0]
        )

        self.assertEqual(
            produced["key"],
            event["event_id"].encode(
                "utf-8"
            ),
        )

    def test_payload_is_deterministic_json(self):
        holder = {}

        def factory(config):
            producer = FakeProducer(
                config
            )

            holder["producer"] = (
                producer
            )

            return producer

        event = sample_event()

        publish_event(
            event,
            "kafka.example:9092",
            "network.compliance.events",
            "v3-publisher-test",
            producer_factory=factory,
        )

        produced = (
            holder["producer"]
            .produced[0]
        )

        expected = json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        self.assertEqual(
            produced["value"],
            expected,
        )

        self.assertEqual(
            json.loads(
                produced["value"]
            ),
            event,
        )

    def test_tampered_v3_event_fails_before_producer(
        self,
    ):
        factory_called = False

        def factory(config):
            nonlocal factory_called

            factory_called = True

            return FakeProducer(
                config
            )

        event = sample_event()

        event["event_id"] = (
            "v3-compliance-event-"
            "00000000000000000000000000000000"
        )

        with self.assertRaises(
            ValueError
        ):
            publish_event(
                event,
                "kafka.example:9092",
                "network.compliance.events",
                "v3-publisher-test",
                producer_factory=factory,
            )

        self.assertFalse(
            factory_called
        )

    def test_delivery_error_fails_closed(self):
        def factory(config):
            return FakeProducer(
                config,
                delivery_error=
                    "synthetic failure",
            )

        with self.assertRaises(
            RuntimeError
        ):
            publish_event(
                sample_event(),
                "kafka.example:9092",
                "network.compliance.events",
                "v3-publisher-test",
                producer_factory=factory,
            )

    def test_flush_timeout_fails_closed(self):
        def factory(config):
            return FakeProducer(
                config,
                flush_remaining=1,
            )

        with self.assertRaises(
            RuntimeError
        ):
            publish_event(
                sample_event(),
                "kafka.example:9092",
                "network.compliance.events",
                "v3-publisher-test",
                producer_factory=factory,
            )


if __name__ == "__main__":
    unittest.main()
