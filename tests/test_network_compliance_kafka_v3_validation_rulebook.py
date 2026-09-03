#!/usr/bin/env python3

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
RULEBOOK = (
    ROOT
    / "rulebooks"
    / "network_compliance_kafka_v3_validation.yml"
)


class NetworkComplianceKafkaV3ValidationRulebookTests(
    unittest.TestCase
):
    @classmethod
    def setUpClass(cls):
        cls.text = RULEBOOK.read_text(
            encoding="utf-8",
        )
        cls.data = yaml.safe_load(cls.text)

    def test_single_validation_ruleset(self):
        self.assertIsInstance(self.data, list)
        self.assertEqual(len(self.data), 1)

        play = self.data[0]

        self.assertEqual(
            play["name"],
            "Network Compliance Kafka V3 Validation",
        )
        self.assertEqual(
            play["hosts"],
            "all",
        )

    def test_isolated_kafka_consumer(self):
        source_item = self.data[0]["sources"][0]
        source = source_item["ansible.eda.kafka"]

        self.assertEqual(
            source["host"],
            (
                "network-automation-kafka-kafka-"
                "bootstrap.kafka.svc"
            ),
        )
        self.assertEqual(
            str(source["port"]),
            "9092",
        )
        self.assertEqual(
            source["topic"],
            "network.compliance.events",
        )
        self.assertEqual(
            source["group_id"],
            "eda-network-compliance-v3-validation",
        )
        self.assertEqual(
            source["offset"],
            "latest",
        )

    def test_v3_frr_activation_condition(self):
        rule = self.data[0]["rules"][0]

        condition = " ".join(
            str(rule["condition"]).split()
        )

        required = (
            'event.body.event_type == '
            '"NETWORK_COMPLIANCE_FINDING_ACTIVATED"',
            'event.body.lifecycle_event_type '
            'in ["DETECTED", "REOPENED"]',
            "event.body.finding.remediable == true",
            'event.body.finding.remediation_policy == "auto"',
            'event.body.finding.vendor == "generic"',
            'event.body.finding.platform == "frr"',
        )

        for fragment in required:
            with self.subTest(fragment=fragment):
                self.assertIn(
                    fragment,
                    condition,
                )

    def test_action_is_validation_job_only(self):
        action = (
            self.data[0]
            ["rules"][0]
            ["action"]
        )

        self.assertEqual(
            set(action),
            {"run_job_template"},
        )

        config = action["run_job_template"]

        self.assertEqual(
            config["name"],
            (
                "NW02-EV-V3-VAL - "
                "Validate EDA Activation Event"
            ),
        )
        self.assertEqual(
            config["organization"],
            "Default",
        )
        self.assertFalse(
            config["include_events"]
        )
        self.assertFalse(
            config["retry"]
        )
        self.assertEqual(
            config["retries"],
            0,
        )

    def test_only_canonical_event_fields_are_forwarded(self):
        event_vars = (
            self.data[0]
            ["rules"][0]
            ["action"]
            ["run_job_template"]
            ["job_args"]
            ["extra_vars"]
            ["v3_eda_event"]
        )

        self.assertEqual(
            set(event_vars),
            {
                "schema_version",
                "event_id",
                "event_type",
                "compliance_run_id",
                "lifecycle_event_type",
                "activated_at",
                "finding",
                "target",
            },
        )

        self.assertNotIn(
            "event.meta",
            self.text,
        )

    def test_no_workflow_or_production_target(self):
        prohibited = (
            "run_workflow_template",
            "WF03-T-NB",
            "WF02-NB",
            "transport_claim",
            "eda-network-compliance-production-v1",
        )

        for marker in prohibited:
            with self.subTest(marker=marker):
                self.assertNotIn(
                    marker,
                    self.text,
                )


if __name__ == "__main__":
    unittest.main()
