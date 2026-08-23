import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]

RULEBOOK = (
    ROOT
    / "rulebooks"
    / "network_compliance_kafka_production.yml"
)


class ProductionKafkaRulebookTests(
    unittest.TestCase
):

    @classmethod
    def setUpClass(cls):
        cls.text = RULEBOOK.read_text()
        cls.data = yaml.safe_load(cls.text)

        cls.ruleset = cls.data[0]

        cls.source = (
            cls.ruleset["sources"][0]
            ["ansible.eda.kafka"]
        )

        cls.rule = cls.ruleset["rules"][0]

        cls.action = (
            cls.rule["action"]
            ["run_workflow_template"]
        )

    def test_exact_production_topic(self):
        self.assertEqual(
            self.source["topic"],
            "network.compliance.events",
        )

    def test_dedicated_production_group(self):
        self.assertEqual(
            self.source["group_id"],
            "eda-network-compliance-production-v1",
        )

        self.assertNotEqual(
            self.source["group_id"],
            "eda-network-compliance-debug",
        )

    def test_new_group_starts_at_latest(self):
        self.assertEqual(
            self.source["offset"],
            "latest",
        )

    def test_only_production_event_type_matches(self):
        condition = self.rule["condition"]

        self.assertIn(
            "NETWORK_COMPLIANCE_DRIFT_DETECTED",
            condition,
        )

        self.assertNotIn(
            "COMPLIANCE_VIOLATION_EDA_TEST",
            condition,
        )

    def test_exact_wf40_target(self):
        self.assertEqual(
            self.action["name"],
            "WF02-NB - FRR Closed-Loop Remediation - NetBox",
        )

        self.assertEqual(
            self.action["organization"],
            "Default",
        )

    def test_event_is_not_injected_into_wf40(self):
        self.assertIs(
            self.action["include_events"],
            False,
        )

        self.assertEqual(
            self.action["job_args"],
            {},
        )

    def test_eda_action_retry_is_disabled(self):
        self.assertIs(
            self.action["retry"],
            False,
        )

        self.assertEqual(
            self.action["retries"],
            0,
        )

        self.assertEqual(
            self.action["delay"],
            0,
        )

    def test_action_feedback_is_disabled(self):
        self.assertIs(
            self.action["set_facts"],
            False,
        )

        self.assertIs(
            self.action["post_events"],
            False,
        )

    def test_event_uuid_label_is_disabled(self):
        self.assertIs(
            self.action["add_event_uuid_label"],
            False,
        )

    def test_no_direct_awx_api_or_credentials(self):
        forbidden = (
            "/api/v2/",
            "AWX_PASSWORD",
            "EDA_ADMIN_PASSWORD",
            "Authorization:",
            "Bearer ",
        )

        for token in forbidden:
            self.assertNotIn(
                token,
                self.text,
            )

    def test_no_publisher_or_producer_logic(self):
        forbidden = (
            "run_network_compliance_kafka_publisher.py",
            "kafka_event_transport.py",
            "Producer(",
            "produce(",
        )

        for token in forbidden:
            self.assertNotIn(
                token,
                self.text,
            )

    def test_single_source_and_single_rule(self):
        self.assertEqual(
            len(self.ruleset["sources"]),
            1,
        )

        self.assertEqual(
            len(self.ruleset["rules"]),
            1,
        )


if __name__ == "__main__":
    unittest.main()
