#!/usr/bin/env python3

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = (
    ROOT
    / "playbooks"
    / "compliance_v3_eda_validation_sink.yml"
)


class ComplianceV3EdaValidationSinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = PLAYBOOK.read_text(encoding="utf-8")
        cls.data = yaml.safe_load(cls.text)

    def test_single_local_validation_play(self):
        self.assertIsInstance(self.data, list)
        self.assertEqual(len(self.data), 1)

        play = self.data[0]

        self.assertEqual(play["hosts"], "localhost")
        self.assertEqual(play["connection"], "local")
        self.assertFalse(play["gather_facts"])

    def test_has_validation_assertions_and_safe_receipt(self):
        tasks = self.data[0]["tasks"]

        task_names = [
            task.get("name")
            for task in tasks
        ]

        self.assertIn(
            "Validate V3 EDA event envelope",
            task_names,
        )
        self.assertIn(
            "Validate V3 EDA finding contract",
            task_names,
        )
        self.assertIn(
            "Validate V3 EDA target contract",
            task_names,
        )
        self.assertIn(
            "Publish isolated V3 EDA validation receipt",
            task_names,
        )

        receipt_task = next(
            task
            for task in tasks
            if task.get("name")
            == "Publish isolated V3 EDA validation receipt"
        )

        self.assertEqual(
            set(receipt_task),
            {
                "name",
                "ansible.builtin.set_stats",
            },
        )

        receipt = (
            receipt_task
            ["ansible.builtin.set_stats"]
            ["data"]
            ["v3_eda_validation"]
        )

        self.assertEqual(
            receipt["decision"],
            "EDA_EVENT_VALIDATED",
        )
        self.assertEqual(
            receipt["side_effects"],
            "none",
        )

    def test_contract_markers_are_present(self):
        required = (
            "NETWORK_COMPLIANCE_FINDING_ACTIVATED",
            "DETECTED",
            "REOPENED",
            "NON_COMPLIANT",
            "generic",
            "frr",
            "remediable",
            "remediation_policy",
            "target_id",
            "device_names",
        )

        for marker in required:
            with self.subTest(marker=marker):
                self.assertIn(
                    marker,
                    self.text,
                )

    def test_no_mutating_or_production_actions(self):
        prohibited = (
            "ansible.builtin.command",
            "ansible.builtin.shell",
            "run_workflow_template",
            "transport_claim",
            "transport_complete",
            "transport_fail",
            "frr_remediate",
            "postgresql",
            "kafka_record_published",
            "run_v3_network_compliance_kafka_publisher",
        )

        lowered = self.text.lower()

        for marker in prohibited:
            with self.subTest(marker=marker):
                self.assertNotIn(
                    marker.lower(),
                    lowered,
                )


if __name__ == "__main__":
    unittest.main()
