import json
import unittest

from scripts.kafka_event_transport import (
    EVENT_TYPE,
    build_producer_config,
    publish_event,
    serialize_event,
)


class FakeMessage:

    def __init__(
        self,
        topic,
        partition=1,
        offset=42,
    ):
        self._topic=topic
        self._partition=partition
        self._offset=offset

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
        self.config=config
        self.delivery_error=delivery_error
        self.flush_remaining=flush_remaining
        self.invoke_callback=invoke_callback
        self.produced=[]

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
                "topic": topic,
                "key": key,
                "value": value,
            }
        )

        if self.invoke_callback:
            on_delivery(
                self.delivery_error,
                FakeMessage(topic),
            )

    def flush(self, timeout):
        self.flush_timeout=timeout
        return self.flush_remaining


def sample_event():
    return {
        "schema_version": "1.0",
        "event_id":
            "network-compliance-drift-test1234",
        "event_type":
            EVENT_TYPE,
        "occurred_at":
            "2026-08-23T00:00:00Z",
        "producer": {
            "system": "awx",
            "component":
                "network-compliance-detector",
            "job_id": 555,
        },
        "correlation": {
            "compliance_run_id":
                "compliance-test-run",
            "compliance_job_id": 555,
            "aggregator_job_id": 566,
        },
        "summary": {
            "devices_evaluated": 4,
            "devices_noncompliant": 1,
            "findings_total": 1,
            "findings_critical": 0,
        },
        "findings": [
            {
                "finding_id":
                    "finding-test",
                "fingerprint":
                    "leaf01|NET-BGP-002|device",
                "device":
                    "leaf01",
                "policy_id":
                    "NET-BGP-002",
                "severity":
                    "high",
                "ticket_required":
                    False,
                "remediation_mode":
                    "auto",
                "observed":
                    "missing or different",
                "expected":
                    2,
            }
        ],
    }


class KafkaEventTransportTests(
    unittest.TestCase
):

    def test_producer_config_is_idempotent(self):
        config=build_producer_config(
            "kafka.example:9092",
            "publisher-test",
        )

        self.assertTrue(
            config["enable.idempotence"]
        )

        self.assertEqual(
            config["acks"],
            "all",
        )

        self.assertEqual(
            config["retries"],
            2147483647,
        )

        self.assertLessEqual(
            config[
                "max.in.flight.requests."
                "per.connection"
            ],
            5,
        )

    def test_serialization_is_deterministic(self):
        event=sample_event()

        first=serialize_event(event)
        second=serialize_event(event)

        self.assertEqual(
            first,
            second,
        )

        self.assertEqual(
            json.loads(first),
            event,
        )

    def test_event_id_is_message_key(self):
        holder={}

        def factory(config):
            producer=FakeProducer(config)
            holder["producer"]=producer
            return producer

        event=sample_event()

        publish_event(
            event,
            "kafka.example:9092",
            "test.topic",
            "publisher-test",
            producer_factory=factory,
        )

        produced=(
            holder["producer"]
            .produced[0]
        )

        self.assertEqual(
            produced["key"],
            event["event_id"].encode(
                "utf-8"
            ),
        )

    def test_successful_delivery_receipt(self):
        def factory(config):
            return FakeProducer(config)

        receipt=publish_event(
            sample_event(),
            "kafka.example:9092",
            "test.topic",
            "publisher-test",
            producer_factory=factory,
        )

        self.assertEqual(
            receipt["topic"],
            "test.topic",
        )

        self.assertEqual(
            receipt["partition"],
            1,
        )

        self.assertEqual(
            receipt["offset"],
            42,
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
                "test.topic",
                "publisher-test",
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
                "test.topic",
                "publisher-test",
                producer_factory=factory,
            )

    def test_missing_delivery_callback_fails_closed(
        self
    ):
        def factory(config):
            return FakeProducer(
                config,
                invoke_callback=False,
            )

        with self.assertRaises(
            RuntimeError
        ):
            publish_event(
                sample_event(),
                "kafka.example:9092",
                "test.topic",
                "publisher-test",
                producer_factory=factory,
            )

    def test_invalid_event_type_fails_closed(self):
        event=sample_event()
        event["event_type"]="BAD_EVENT"

        with self.assertRaises(
            ValueError
        ):
            serialize_event(event)


if __name__ == "__main__":
    unittest.main()
