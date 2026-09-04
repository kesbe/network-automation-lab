import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]

PLAYBOOK = (
    ROOT
    / "playbooks"
    / "compliance_publish_v3_kafka.yml"
)


class V3KafkaPublishPlaybookTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.text = PLAYBOOK.read_text()
        cls.data = yaml.safe_load(cls.text)
        cls.play = cls.data[0]

    def test_is_local_orchestration(self):
        self.assertEqual(
            self.play["hosts"],
            "localhost",
        )
        self.assertFalse(
            self.play["gather_facts"],
        )

    def test_consumes_jt82_activation_batch(self):
        self.assertIn(
            "v3_activation_event_batch",
            self.text,
        )
        self.assertIn(
            "ACTIVATIONS_PREPARED",
            self.text,
        )
        self.assertIn(
            "NO_ACTIVATIONS",
            self.text,
        )
        self.assertIn(
            "PERSISTENCE_DUPLICATE",
            self.text,
        )

    def test_requires_exact_v3_event_type(self):
        self.assertIn(
            "NETWORK_COMPLIANCE_FINDING_ACTIVATED",
            self.text,
        )

    def test_uses_frozen_v3_publisher(self):
        self.assertIn(
            "run_v3_network_compliance_kafka_publisher.py",
            self.text,
        )

        self.assertNotIn(
            "scripts/run_network_compliance_kafka_publisher.py",
            self.text,
        )

    def test_uses_in_cluster_kafka_bootstrap(self):
        self.assertIn(
            (
                "network-automation-kafka-kafka-bootstrap."
                "kafka.svc:9092"
            ),
            self.text,
        )

    def test_does_not_override_frozen_topic(self):
        self.assertNotIn(
            "--topic",
            self.text,
        )

        self.assertIn(
            "network.compliance.events",
            self.text,
        )

    def test_private_event_file_mode(self):
        self.assertIn(
            'mode: "0600"',
            self.text,
        )

    def test_temporary_directory_is_removed(self):
        self.assertIn(
            "Remove V3 publisher temporary directory",
            self.text,
        )
        self.assertIn(
            "state: absent",
            self.text,
        )

    def test_requires_publisher_receipt(self):
        for value in (
            "v3_production_publisher_decision=EVENT_PUBLISHED",
            "published_event_id=",
            "published_topic=network.compliance.events",
            "kafka_record_published=YES",
        ):
            self.assertIn(
                value,
                self.text,
            )

    def test_publishes_safe_artifact(self):
        self.assertIn(
            "v3_kafka_publish:",
            self.text,
        )
        self.assertIn(
            "publisher_job_id:",
            self.text,
        )
        self.assertIn(
            "published_count:",
            self.text,
        )

    def test_has_no_postgres_or_awx_credentials(self):
        forbidden = (
            "NETAUTO_PG_PASSWORD",
            "AWX_PASSWORD",
            "Authorization:",
            "password:",
            "token:",
        )

        for value in forbidden:
            self.assertNotIn(
                value,
                self.text,
            )


if __name__ == "__main__":
    unittest.main()
