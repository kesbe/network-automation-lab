import tempfile
import unittest
from pathlib import Path

import scripts.run_network_compliance_kafka_test_publisher as test_publisher


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

SAFE_TOPIC = (
    "network.compliance.events."
    "transport-validation-unit-test"
)


class FakePublisher:

    def __init__(self):
        self.calls = []

    def __call__(
        self,
        event,
        bootstrap_servers,
        topic,
        client_id,
    ):
        self.calls.append({
            "event": event,
            "bootstrap_servers":
                bootstrap_servers,
            "topic": topic,
            "client_id": client_id,
        })

        return {
            "event_id":
                event["event_id"],
            "topic":
                topic,
            "partition":
                0,
            "offset":
                0,
        }


class KafkaTestPublisherTests(
    unittest.TestCase
):

    def output_path(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)

        return (
            Path(tmp.name)
            / "event.json"
        )

    def test_production_topic_is_refused(self):
        with self.assertRaises(ValueError):
            test_publisher.validate_test_topic(
                "network.compliance.events"
            )

    def test_unexpected_topic_is_refused(self):
        with self.assertRaises(ValueError):
            test_publisher.validate_test_topic(
                "automation.results"
            )

    def test_validation_topic_is_accepted(self):
        test_publisher.validate_test_topic(
            SAFE_TOPIC
        )

    def test_clean_run_does_not_publish(self):
        fake = FakePublisher()
        output = self.output_path()

        result = test_publisher.execute(
            CLEAN,
            output,
            "fake-kafka:9092",
            SAFE_TOPIC,
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

        result = test_publisher.execute(
            DRIFT,
            output,
            "fake-kafka:9092",
            SAFE_TOPIC,
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

        self.assertTrue(
            output.exists()
        )

        event = fake.calls[0]["event"]

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

        self.assertEqual(
            fake.calls[0]["topic"],
            SAFE_TOPIC,
        )

    def test_receipt_matches_event(self):
        fake = FakePublisher()
        output = self.output_path()

        result = test_publisher.execute(
            DRIFT,
            output,
            "fake-kafka:9092",
            SAFE_TOPIC,
            "unit-test",
            publisher=fake,
        )

        event = fake.calls[0]["event"]
        receipt = result["receipt"]

        self.assertEqual(
            receipt["event_id"],
            event["event_id"],
        )

        self.assertEqual(
            receipt["topic"],
            SAFE_TOPIC,
        )


if __name__ == "__main__":
    unittest.main()
