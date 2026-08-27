#!/usr/bin/env python3

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]

PLAYBOOK = (
    ROOT
    / "playbooks"
    / "generic_compliance_detector_offline.yml"
)


class GenericComplianceOfflinePlaybookTests(
    unittest.TestCase
):

    def text(self):
        return PLAYBOOK.read_text()

    def document(self):
        return yaml.safe_load(
            PLAYBOOK.read_text()
        )

    def test_runs_on_localhost_only(self):
        document = self.document()

        self.assertIsInstance(
            document,
            list,
        )

        self.assertEqual(
            len(document),
            1,
        )

        play = document[0]

        self.assertEqual(
            play["hosts"],
            "localhost",
        )

        self.assertEqual(
            play["connection"],
            "local",
        )

        self.assertFalse(
            play["gather_facts"],
        )

    def test_uses_generic_runner(self):
        text = self.text()

        self.assertIn(
            "generic_compliance_runner.py",
            text,
        )

        self.assertIn(
            "--platform",
            text,
        )

        self.assertIn(
            "--device-name",
            text,
        )

        self.assertIn(
            "--role",
            text,
        )

    def test_publishes_set_stats_contract(
        self,
    ):
        text = self.text()

        self.assertIn(
            "ansible.builtin.set_stats",
            text,
        )

        self.assertIn(
            "'compliance_'",
            text,
        )

        self.assertIn(
            "'compliance_job_id'",
            text,
        )

    def test_validates_jt38_contract_fields(
        self,
    ):
        text = self.text()

        for field in (
            ".device",
            ".status",
            ".total_checks",
            ".passed",
            ".failed",
            ".violations",
        ):
            self.assertIn(
                "generic_compliance_result"
                + field,
                text,
            )

    def test_has_no_device_or_transport_action(
        self,
    ):
        lowered = self.text().lower()

        forbidden = (
            "vtysh",
            "ansible.netcommon",
            "cisco.ios",
            "arista.eos",
            "junipernetworks",
            "ansible.builtin.uri",
            "kubectl",
            "kafka",
            "eda",
        )

        for token in forbidden:
            self.assertNotIn(
                token,
                lowered,
            )

    def test_offline_job_id_is_validated(
        self,
    ):
        text = self.text()

        self.assertIn(
            "generic_resolved_compliance_job_id | int > 0",
            text,
        )

    def test_awx_job_id_has_precedence(
        self,
    ):
        text = self.text()

        self.assertIn(
            "awx_job_id is defined",
            text,
        )

        self.assertIn(
            "awx_job_id | int > 0",
            text,
        )

        self.assertIn(
            "(awx_job_id | int)",
            text,
        )

    def test_offline_fallback_is_explicit(
        self,
    ):
        text = self.text()

        self.assertIn(
            "generic_offline_mode: true",
            text,
        )

        self.assertIn(
            "generic_offline_job_id: 1",
            text,
        )

        self.assertIn(
            "generic_offline_mode | bool",
            text,
        )

    def test_artifact_uses_resolved_job_id(
        self,
    ):
        text = self.text()

        self.assertIn(
            "generic_resolved_compliance_job_id",
            text,
        )

        self.assertIn(
            "'compliance_job_id':",
            text,
        )

        self.assertNotIn(
            "'compliance_job_id':"
            " generic_offline_job_id",
            text,
        )


if __name__ == "__main__":
    unittest.main()
