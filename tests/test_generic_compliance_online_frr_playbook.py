import configparser
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]

PLAYBOOK = (
    ROOT
    / "playbooks"
    / "generic_compliance_detector_online_frr.yml"
)

ANSIBLE_CONFIG = ROOT / "ansible.cfg"


class OnlineFrrPlaybookTests(unittest.TestCase):
    def test_host_pattern_mismatch_is_error(self):
        parser = configparser.ConfigParser()
        parser.read(ANSIBLE_CONFIG)

        self.assertTrue(
            parser.has_section("inventory")
        )

        self.assertEqual(
            parser.get(
                "inventory",
                "host_pattern_mismatch",
            ).strip(),
            "error",
        )

    def _play(self):
        plays = yaml.safe_load(
            PLAYBOOK.read_text()
        )

        self.assertIsInstance(
            plays,
            list,
        )

        self.assertEqual(
            len(plays),
            1,
        )

        return plays[0]

    def test_named_host_pattern_is_required(self):
        play = self._play()

        hosts = str(
            play.get("hosts", "")
        )

        self.assertIn(
            "target_device",
            hosts,
        )

        self.assertNotEqual(
            hosts.strip(),
            "all",
        )

    def test_only_expected_raw_commands_exist(self):
        play = self._play()

        commands = []

        for task in play.get(
            "tasks",
            [],
        ):
            if "ansible.builtin.raw" in task:
                commands.append(
                    task[
                        "ansible.builtin.raw"
                    ].strip()
                )

                self.assertFalse(
                    task.get(
                        "changed_when",
                        True,
                    )
                )

        self.assertEqual(
            set(commands),
            {
                "vtysh -c 'show running-config'",
                (
                    "vtysh -c "
                    "'show bgp ipv4 unicast summary'"
                ),
            },
        )

        self.assertEqual(
            len(commands),
            2,
        )

    def test_forbidden_device_mutations_absent(self):
        text = PLAYBOOK.read_text().lower()

        forbidden = (
            "configure terminal",
            "conf t",
            "write memory",
            "write mem",
            "copy running-config startup-config",
            "copy run start",
            "reload",
        )

        for token in forbidden:
            self.assertNotIn(
                token,
                text,
            )

    def test_validation_is_leaf01_frr_only(self):
        play = self._play()

        variables = play.get(
            "vars",
            {},
        )

        self.assertEqual(
            variables.get(
                "generic_validation_target"
            ),
            "leaf01",
        )

        self.assertEqual(
            variables.get(
                "generic_platform"
            ),
            "frr",
        )

        self.assertEqual(
            variables.get(
                "generic_role"
            ),
            "leaf",
        )

    def test_uses_authoritative_intent_files(self):
        play = self._play()

        self.assertEqual(
            play.get("vars_files"),
            [
                "../vars/compliance_intent.yml",
                "../vars/compliance_policies.yml",
            ],
        )

        text = PLAYBOOK.read_text()

        self.assertIn(
            "netbox_maximum_paths",
            text,
        )

        self.assertIn(
            "network_intent[inventory_hostname]",
            text,
        )

    def test_requires_awx_job_id(self):
        text = PLAYBOOK.read_text()

        self.assertIn(
            "awx_job_id is defined",
            text,
        )

        self.assertIn(
            "awx_job_id | int",
            text,
        )

        self.assertNotIn(
            "generic_offline_job_id",
            text,
        )

    def test_publishes_jt38_compatible_artifact(self):
        text = PLAYBOOK.read_text()

        self.assertIn(
            "'compliance_'",
            text,
        )

        self.assertIn(
            "'compliance_job_id'",
            text,
        )

        self.assertIn(
            "ansible.builtin.set_stats",
            text,
        )

        self.assertIn(
            "per_host: false",
            text,
        )


if __name__ == "__main__":
    unittest.main()
