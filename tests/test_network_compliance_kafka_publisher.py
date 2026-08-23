import tempfile
import unittest
from pathlib import Path

import scripts.run_network_compliance_kafka_publisher as publisher


ROOT = Path(__file__).resolve().parents[1]

CLEAN = (
    ROOT
    / "tests"
    / "fixtures"
    / "awx_aggregator_clean_realshape.json"
)

DRIFT = (
    ROOT
    / "tests"
    / "fixtures"
    / "awx_aggregator_drift_realshape.json"
)


class FakePublisher:

    def __init__(
        self,
        *,
        receipt_topic=None,
    ):
        self.calls = []
        self.receipt_topic = receipt_topic

    def __call__(
        self,
        event,
        bootstrap_servers,
        topic,
        client_id,
    ):
        self.calls.append({
            "event":
                event,

            "bootstrap_servers":
                bootstrap_servers,

            "topic":
                topic,

            "client_id":
                client_id,
        })

        return {
            "event_id":
                event["event_id"],

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


class ProductionKafkaPublisherTests(
    unittest.TestCase
):

    def output_path(self):
        tmp = tempfile.TemporaryDirectory()

        self.addCleanup(
            tmp.cleanup
        )

        return (
            Path(tmp.name)
            / "event.json"
        )

    def test_production_topic_is_fixed(self):
        self.assertEqual(
            publisher.PRODUCTION_TOPIC,
            "network.compliance.events",
        )

    def test_empty_bootstrap_is_refused(self):
        fake = FakePublisher()
        output = self.output_path()

        with self.assertRaises(
            ValueError
        ):
            publisher.execute(
                DRIFT,
                output,
                "",
                "unit-test",
                publisher=fake,
            )

        self.assertEqual(
            len(fake.calls),
            0,
        )

        self.assertFalse(
            output.exists()
        )

    def test_clean_run_does_not_publish(self):
        fake = FakePublisher()
        output = self.output_path()

        result = publisher.execute(
            CLEAN,
            output,
            "fake-kafka:9092",
            "unit-test",
            publisher=fake,
        )

        self.assertEqual(
            result["decision"],
            "NO_EVENT",
        )

        self.assertEqual(
            len(fake.calls),
            0,
        )

        self.assertFalse(
            output.exists()
        )

    def test_drift_run_publishes_once(self):
        fake = FakePublisher()
        output = self.output_path()

        result = publisher.execute(
            DRIFT,
            output,
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
        event = call["event"]

        self.assertEqual(
            call["topic"],
            "network.compliance.events",
        )

        self.assertEqual(
            event["event_type"],
            "NETWORK_COMPLIANCE_DRIFT_DETECTED",
        )

        self.assertEqual(
            len(event["findings"]),
            1,
        )

        self.assertEqual(
            event["findings"][0]["device"],
            "leaf01",
        )

        self.assertEqual(
            event["findings"][0]["policy_id"],
            "NET-BGP-002",
        )

    def test_receipt_event_id_matches(self):
        fake = FakePublisher()
        output = self.output_path()

        result = publisher.execute(
            DRIFT,
            output,
            "fake-kafka:9092",
            "unit-test",
            publisher=fake,
        )

        event = fake.calls[0]["event"]

        self.assertEqual(
            result["receipt"]["event_id"],
            event["event_id"],
        )

    def test_wrong_receipt_topic_fails_closed(
        self
    ):
        fake = FakePublisher(
            receipt_topic=
                "unexpected.topic"
        )

        output = self.output_path()

        with self.assertRaises(
            RuntimeError
        ):
            publisher.execute(
                DRIFT,
                output,
                "fake-kafka:9092",
                "unit-test",
                publisher=fake,
            )

        self.assertEqual(
            len(fake.calls),
            1,
        )


if __name__ == "__main__":
    unittest.main()
