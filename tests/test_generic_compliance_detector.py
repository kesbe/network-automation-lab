#!/usr/bin/env python3

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

from scripts.generic_compliance_detector import (
    GenericDetectorError,
    evaluate_device,
)


ROOT = Path(__file__).resolve().parents[1]

STATE_FILE = (
    ROOT
    / "examples"
    / "state"
    / "normalized_leaf01_v1.yml"
)

POLICY_FILE = (
    ROOT
    / "vars"
    / "compliance_policies.yml"
)

DETECTOR = (
    ROOT
    / "scripts"
    / "generic_compliance_detector.py"
)


class GenericComplianceDetectorTests(
    unittest.TestCase
):

    def state(self):
        return yaml.safe_load(
            STATE_FILE.read_text()
        )

    def policies(self):
        return yaml.safe_load(
            POLICY_FILE.read_text()
        )["compliance_policies"]

    def intent(self):
        return {
            "maximum_paths": 2,
        }

    def test_clean_leaf_is_compliant(self):
        result = evaluate_device(
            self.state(),
            self.policies(),
            self.intent(),
        )

        self.assertEqual(
            result["status"],
            "COMPLIANT",
        )

        self.assertEqual(
            result["total_checks"],
            1,
        )

        self.assertEqual(
            result["passed"],
            1,
        )

        self.assertEqual(
            result["failed"],
            0,
        )

        self.assertEqual(
            result["violations"],
            [],
        )

    def test_drift_emits_existing_contract(
        self,
    ):
        state = self.state()

        state[
            "bgp"
        ][
            "ipv4_unicast"
        ][
            "maximum_paths"
        ] = 1

        result = evaluate_device(
            state,
            self.policies(),
            self.intent(),
        )

        self.assertEqual(
            result["status"],
            "NON_COMPLIANT",
        )

        self.assertEqual(
            result["total_checks"],
            1,
        )

        self.assertEqual(
            result["passed"],
            0,
        )

        self.assertEqual(
            result["failed"],
            1,
        )

        finding = result["violations"][0]

        self.assertEqual(
            set(finding),
            {
                "control",
                "expected",
                "actual",
                "policy_id",
                "policy_name",
                "category",
                "severity",
                "ticket_required",
                "owner",
                "remediation",
            },
        )

        self.assertEqual(
            finding["policy_id"],
            "NET-BGP-002",
        )

        self.assertEqual(
            finding["expected"],
            2,
        )

        self.assertEqual(
            finding["actual"],
            1,
        )

    def test_remediation_contract_is_backward_compatible(
        self,
    ):
        state = self.state()

        state[
            "bgp"
        ][
            "ipv4_unicast"
        ][
            "maximum_paths"
        ] = 1

        result = evaluate_device(
            state,
            self.policies(),
            self.intent(),
        )

        remediation = (
            result["violations"][0]
            ["remediation"]
        )

        self.assertEqual(
            set(remediation),
            {
                "supported",
                "mode",
                "risk",
            },
        )

        self.assertNotIn(
            "action",
            remediation,
        )

    def test_only_applicable_v2_policy_is_evaluated(
        self,
    ):
        result = evaluate_device(
            self.state(),
            self.policies(),
            self.intent(),
        )

        self.assertEqual(
            result["total_checks"],
            1,
        )

    def test_role_scope_mismatch_fails_closed(
        self,
    ):
        state = self.state()

        state["device"]["role"] = "spine"

        with self.assertRaises(
            GenericDetectorError
        ):
            evaluate_device(
                state,
                self.policies(),
                self.intent(),
            )

    def test_platform_scope_mismatch_fails_closed(
        self,
    ):
        state = self.state()

        state["device"]["platform"] = (
            "cisco_ios"
        )

        with self.assertRaises(
            GenericDetectorError
        ):
            evaluate_device(
                state,
                self.policies(),
                self.intent(),
            )

    def test_missing_role_fails_closed(self):
        state = self.state()

        state["device"].pop(
            "role",
            None,
        )

        with self.assertRaises(
            GenericDetectorError
        ):
            evaluate_device(
                state,
                self.policies(),
                self.intent(),
            )

    def test_missing_intent_fails_closed(
        self,
    ):
        with self.assertRaises(
            GenericDetectorError
        ):
            evaluate_device(
                self.state(),
                self.policies(),
                {},
            )

    def test_direct_cli_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_file = (
                Path(tmp)
                / "intent.yml"
            )

            intent_file.write_text(
                "maximum_paths: 2\n"
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(DETECTOR),
                    "--normalized-state",
                    str(STATE_FILE),
                    "--policy-file",
                    str(POLICY_FILE),
                    "--intent-file",
                    str(intent_file),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(
            result.returncode,
            0,
            msg=result.stderr,
        )

        artifact = yaml.safe_load(
            result.stdout
        )

        self.assertEqual(
            artifact["device"],
            "leaf01",
        )

        self.assertEqual(
            artifact["status"],
            "COMPLIANT",
        )


if __name__ == "__main__":
    unittest.main()
