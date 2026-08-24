import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]

RULEBOOK = (
    ROOT
    / "rulebooks"
    / "network_compliance_kafka_production.yml"
)


class ProductionKafkaRulebookTests(unittest.TestCase):

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

        cls.job_args = (
            cls.action.get("job_args")
            or {}
        )

        cls.extra_vars = (
            cls.job_args.get("extra_vars")
            or {}
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

    def test_exact_transport_wrapper_target(self):
        self.assertEqual(
            self.action["name"],
            "WF03-T-NB - Durable Compliance Transport Wrapper",
        )

        self.assertEqual(
            self.action["organization"],
            "Default",
        )

    def test_direct_wf40_target_removed(self):
        self.assertNotEqual(
            self.action["name"],
            "WF02-NB - FRR Closed-Loop Remediation - NetBox",
        )

        self.assertNotIn(
            "WF02-NB - FRR Closed-Loop Remediation - NetBox",
            self.text,
        )

    def test_full_event_not_injected(self):
        self.assertIs(
            self.action["include_events"],
            False,
        )

    def test_exact_wrapper_extra_var_keys(self):
        self.assertEqual(
            set(self.extra_vars),
            {
                "transport_event_id",
                "transport_event_type",
                "compliance_run_id",
            },
        )

    def test_transport_event_id_mapping(self):
        self.assertEqual(
            self.extra_vars["transport_event_id"],
            "{{ event.body.event_id }}",
        )

    def test_transport_event_type_mapping(self):
        self.assertEqual(
            self.extra_vars["transport_event_type"],
            "{{ event.body.event_type }}",
        )

    def test_compliance_run_id_mapping(self):
        self.assertEqual(
            self.extra_vars["compliance_run_id"],
            (
                "{{ event.body.correlation."
                "compliance_run_id }}"
            ),
        )

    def test_no_consumer_supplied_awx_ids(self):
        forbidden = {
            "awx_job_id",
            "awx_workflow_job_id",
        }

        self.assertTrue(
            forbidden.isdisjoint(self.extra_vars)
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

    def test_no_workflow_feedback_into_rulebook(self):
        self.assertIs(
            self.action["set_facts"],
            False,
        )

        self.assertIs(
            self.action["post_events"],
            False,
        )

        self.assertIs(
            self.action["add_event_uuid_label"],
            False,
        )

    def test_rulebook_has_no_direct_awx_api_logic(self):
        forbidden = (
            "/api/v2/",
            "requests.post",
            "curl ",
        )

        for value in forbidden:
            self.assertNotIn(
                value,
                self.text,
            )

    def test_rulebook_has_no_credentials(self):
        forbidden = (
            "AWX_PASSWORD",
            "NETAUTO_PG_PASSWORD",
            "password:",
            "token:",
        )

        for value in forbidden:
            self.assertNotIn(
                value,
                self.text,
            )

    def test_rulebook_has_no_kafka_producer_logic(self):
        forbidden = (
            "Producer(",
            "produce(",
            "confluent_kafka",
            "kafka-python",
        )

        for value in forbidden:
            self.assertNotIn(
                value,
                self.text,
            )


if __name__ == "__main__":
    unittest.main()
