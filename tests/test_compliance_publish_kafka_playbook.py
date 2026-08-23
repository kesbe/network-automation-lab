import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

PLAYBOOK = (
    ROOT
    / "playbooks"
    / "compliance_publish_kafka.yml"
)


class KafkaPublisherPlaybookTests(
    unittest.TestCase
):

    @classmethod
    def setUpClass(cls):
        cls.text = PLAYBOOK.read_text()

    def test_publish_disabled_by_default(self):
        self.assertIn(
            "kafka_publish_enabled: false",
            self.text,
        )

    def test_production_adapter_is_used(self):
        self.assertIn(
            "run_network_compliance_kafka_publisher.py",
            self.text,
        )

    def test_topic_cannot_be_overridden_here(self):
        self.assertNotIn(
            "--topic",
            self.text,
        )

    def test_synthetic_envelope_uses_aggregator_id(self):
        self.assertIn(
            '"id": (aggregator_job_id | int)',
            self.text,
        )

    def test_awx_workflow_correlation_is_enforced(self):
        self.assertIn(
            "workflow_job_id | int "
            "== awx_workflow_job_id | int",
            self.text,
        )

        self.assertIn(
            "aggregator_job_id | int "
            "!= awx_job_id | int",
            self.text,
        )

    def test_bootstrap_required_only_when_enabled(self):
        self.assertIn(
            "kafka_bootstrap_servers | trim | length > 0",
            self.text,
        )

        self.assertIn(
            "kafka_publish_enabled | bool",
            self.text,
        )

    def test_no_awx_or_eda_credentials(self):
        forbidden = (
            "AWX_PASSWORD",
            "EDA_ADMIN_PASSWORD",
            "/api/v2/",
            "workflow_job_templates/40",
        )

        for value in forbidden:
            self.assertNotIn(
                value,
                self.text,
            )

    def test_no_retry_loop_around_publish(self):
        forbidden = (
            "retries:",
            "until:",
        )

        for value in forbidden:
            self.assertNotIn(
                value,
                self.text,
            )


if __name__ == "__main__":
    unittest.main()
