import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SCRIPT = (
    ROOT
    / "scripts"
    / "run_network_compliance_publisher.py"
)

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


class OfflinePublisherTests(unittest.TestCase):

    def run_publisher(
        self,
        fixture,
        transport="disabled",
    ):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)

        output = (
            Path(tmp.name)
            / "event.json"
        )

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--input",
                str(fixture),
                "--output",
                str(output),
                "--transport",
                transport,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

        return result, output

    def test_clean_run_creates_no_event(self):
        result, output = self.run_publisher(
            CLEAN
        )

        self.assertEqual(
            result.returncode,
            0,
            result.stderr,
        )

        self.assertIn(
            "publisher_decision=NO_EVENT",
            result.stdout,
        )

        self.assertIn(
            "publish_attempted=NO",
            result.stdout,
        )

        self.assertIn(
            "kafka_contact_attempted=NO",
            result.stdout,
        )

        self.assertFalse(
            output.exists()
        )

    def test_drift_run_creates_valid_event_only(self):
        result, output = self.run_publisher(
            DRIFT
        )

        self.assertEqual(
            result.returncode,
            0,
            result.stderr,
        )

        self.assertIn(
            "publisher_decision=EVENT_READY",
            result.stdout,
        )

        self.assertIn(
            "publish_attempted=NO",
            result.stdout,
        )

        self.assertIn(
            "kafka_contact_attempted=NO",
            result.stdout,
        )

        self.assertTrue(
            output.exists()
        )

        event = json.loads(
            output.read_text()
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

    def test_kafka_transport_is_refused(self):
        result, output = self.run_publisher(
            DRIFT,
            transport="kafka",
        )

        self.assertEqual(
            result.returncode,
            2,
        )

        self.assertIn(
            "transport_enablement=REFUSED",
            result.stdout,
        )

        self.assertIn(
            "publish_attempted=NO",
            result.stdout,
        )

        self.assertIn(
            "kafka_contact_attempted=NO",
            result.stdout,
        )

        self.assertFalse(
            output.exists()
        )


if __name__ == "__main__":
    unittest.main()
