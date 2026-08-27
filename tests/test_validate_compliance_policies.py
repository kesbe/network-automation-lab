#!/usr/bin/env python3

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]

VALIDATOR = (
    REPO_ROOT
    / "scripts"
    / "validate_compliance_policies.py"
)

POLICY_FILE = (
    REPO_ROOT
    / "vars"
    / "compliance_policies.yml"
)


class CompliancePolicyValidatorTests(
    unittest.TestCase
):

    def load_document(self):
        return yaml.safe_load(
            POLICY_FILE.read_text()
        )

    def run_validator(
        self,
        document=None,
    ):
        if document is None:
            policy_path = POLICY_FILE

            result = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    str(policy_path),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            return result

        with tempfile.TemporaryDirectory() as tmp:
            policy_path = (
                Path(tmp)
                / "compliance_policies.yml"
            )

            policy_path.write_text(
                yaml.safe_dump(
                    document,
                    sort_keys=False,
                )
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    str(policy_path),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            return result

    def test_current_mixed_policy_model_passes(
        self,
    ):
        result = self.run_validator()

        self.assertEqual(
            result.returncode,
            0,
            msg=result.stderr,
        )

        self.assertIn(
            "Policies validated: 8",
            result.stdout,
        )

        self.assertIn(
            "NET-BGP-002",
            result.stdout,
        )

        self.assertIn(
            "model=v2",
            result.stdout,
        )

    def test_legacy_policy_model_remains_supported(
        self,
    ):
        document = self.load_document()

        policy = document[
            "compliance_policies"
        ]["NET-BGP-002"]

        for field in (
            "scope",
            "intent",
            "state",
            "comparison",
            "verification",
        ):
            policy.pop(
                field,
                None,
            )

        policy[
            "remediation"
        ].pop(
            "action",
            None,
        )

        result = self.run_validator(
            document
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=result.stderr,
        )

        self.assertNotIn(
            "model=v2",
            result.stdout,
        )

    def test_empty_platform_scope_fails_closed(
        self,
    ):
        document = self.load_document()

        document[
            "compliance_policies"
        ][
            "NET-BGP-002"
        ][
            "scope"
        ][
            "platforms"
        ] = []

        result = self.run_validator(
            document
        )

        self.assertNotEqual(
            result.returncode,
            0,
        )

        self.assertIn(
            "scope.platforms must be "
            "a non-empty list",
            result.stderr,
        )

    def test_unsupported_comparison_fails_closed(
        self,
    ):
        document = self.load_document()

        document[
            "compliance_policies"
        ][
            "NET-BGP-002"
        ][
            "comparison"
        ][
            "operator"
        ] = "contains"

        result = self.run_validator(
            document
        )

        self.assertNotEqual(
            result.returncode,
            0,
        )

        self.assertIn(
            "invalid comparison operator",
            result.stderr,
        )

    def test_vendor_cli_action_fails_closed(
        self,
    ):
        document = self.load_document()

        document[
            "compliance_policies"
        ][
            "NET-BGP-002"
        ][
            "remediation"
        ][
            "action"
        ] = "vtysh -c maximum-paths 2"

        result = self.run_validator(
            document
        )

        self.assertNotEqual(
            result.returncode,
            0,
        )

        self.assertIn(
            "must be an abstract "
            "snake_case action",
            result.stderr,
        )

    def test_incomplete_v2_policy_fails_closed(
        self,
    ):
        document = self.load_document()

        del document[
            "compliance_policies"
        ][
            "NET-BGP-002"
        ][
            "state"
        ]

        result = self.run_validator(
            document
        )

        self.assertNotEqual(
            result.returncode,
            0,
        )

        self.assertIn(
            "incomplete v2 policy",
            result.stderr,
        )

        self.assertIn(
            "state",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
