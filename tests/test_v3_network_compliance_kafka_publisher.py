import json
import tempfile
import unittest
from pathlib import Path


import scripts.run_v3_network_compliance_kafka_publisher as publisher

from scripts.v3_compliance_event import (
    build_event,
)

from tests.test_v3_compliance_event import (
    make_finding,
    make_target,
)


class FakePublisher:

    def __init__(
        self,
        *,
        receipt_event_id=None,
        receipt_topic=None,
    ):
        self.calls = []

        self.receipt_event_id = (
            receipt_event_id
        )

        self.receipt_topic = (
            receipt_topic
        )

    def __call__(
        self,
        event,
        bootstrap_servers,
        topic,
        client_id,
    ):
        self.calls.append(
            {
                "event":
                    event,

                "bootstrap_servers":
                    bootstrap_servers,

                "topic":
                    topic,

                "client_id":
                    client_id,
            }
        )

        return {
            "event_id":
                (
                    self.receipt_event_id
                    if self.receipt_event_id
                    is not None
                    else event["event_id"]
                ),

            "topic":
                (
                    self.receipt_topic
                    if self.receipt_topic
                    is not None
                    else topic
                ),

            "partition":
                0,

            "offset":
                0,
        }


def sample_event():
    return build_event(
        finding=make_finding(),
        resolved_target=make_target(),
        lifecycle_event_type="DETECTED",
        compliance_run_id=
            "phase7f5e-production-publisher",
        activated_at=
            "2026-08-31T01:30:00+10:00",
    )


class V3ProductionKafkaPublisherTests(
    unittest.TestCase
):

    def event_file(
        self,
        event=None,
    ):
        tmp = tempfile.TemporaryDirectory()

        self.addCleanup(
            tmp.cleanup
        )

        path = (
            Path(tmp.name)
            / "v3-event.json"
        )

        if event is None:
            event = sample_event()

        path.write_text(
            json.dumps(
                event,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )

        return path

    def test_production_topic_is_fixed(self):
        self.assertEqual(
            publisher.PRODUCTION_TOPIC,
            "network.compliance.events",
        )

    def test_empty_bootstrap_is_refused(self):
        fake = FakePublisher()

        with self.assertRaises(
            ValueError
        ):
            publisher.execute(
                self.event_file(),
                "",
                "unit-test",
                publisher=fake,
            )

        self.assertEqual(
            len(fake.calls),
            0,
        )

    def test_valid_v3_event_publishes_once(self):
        fake = FakePublisher()

        event_path = self.event_file()

        result = publisher.execute(
            event_path,
            "fake-kafka:9092",
            "unit-test",
            publisher=fake,
        )

        self.assertEqual(
            result["decision"],
            "EVENT_PUBLISHED",
        )

        self.assertEqual(
            len(fake.calls),
            1,
        )

        call = fake.calls[0]

        self.assertEqual(
            call["topic"],
            "network.compliance.events",
        )

        self.assertEqual(
            call["event"]["event_type"],
            "NETWORK_COMPLIANCE_FINDING_ACTIVATED",
        )

        self.assertTrue(
            call["event"]["event_id"].startswith(
                "v3-compliance-event-"
            )
        )

    def test_invalid_v3_event_fails_before_publish(
        self,
    ):
        fake = FakePublisher()

        event = sample_event()

        event["event_id"] = (
            "v3-compliance-event-"
            "00000000000000000000000000000000"
        )

        with self.assertRaises(
            ValueError
        ):
            publisher.execute(
                self.event_file(
                    event
                ),
                "fake-kafka:9092",
                "unit-test",
                publisher=fake,
            )

        self.assertEqual(
            len(fake.calls),
            0,
        )

    def test_receipt_event_id_must_match(self):
        fake = FakePublisher(
            receipt_event_id=
                "wrong-event-id"
        )

        with self.assertRaises(
            RuntimeError
        ):
            publisher.execute(
                self.event_file(),
                "fake-kafka:9092",
                "unit-test",
                publisher=fake,
            )

        self.assertEqual(
            len(fake.calls),
            1,
        )

    def test_receipt_topic_must_match(self):
        fake = FakePublisher(
            receipt_topic=
                "unexpected.topic"
        )

        with self.assertRaises(
            RuntimeError
        ):
            publisher.execute(
                self.event_file(),
                "fake-kafka:9092",
                "unit-test",
                publisher=fake,
            )

        self.assertEqual(
            len(fake.calls),
            1,
        )

    def test_non_object_receipt_fails_closed(
        self,
    ):
        calls = []

        def fake(
            event,
            bootstrap_servers,
            topic,
            client_id,
        ):
            calls.append(
                event
            )

            return None

        with self.assertRaises(
            RuntimeError
        ):
            publisher.execute(
                self.event_file(),
                "fake-kafka:9092",
                "unit-test",
                publisher=fake,
            )

        self.assertEqual(
            len(calls),
            1,
        )

    def test_publisher_does_not_build_event(self):
        source = Path(
            publisher.__file__
        ).read_text()

        self.assertNotIn(
            "build_event(",
            source,
        )

        self.assertIn(
            "validate_event(",
            source,
        )


if __name__ == "__main__":
    unittest.main()
