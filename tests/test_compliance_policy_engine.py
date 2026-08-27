#!/usr/bin/env python3

import copy
from pathlib import Path
import unittest

import yaml

from scripts.compliance_policy_engine import (
    PolicyEvaluationError,
    evaluate_policy,
)


REPO_ROOT = Path(__file__).resolve().parents[1]

STATE_FILE = (
    REPO_ROOT
    / "examples"
    / "state"
    / "normalized_leaf01_v1.yml"
)

POLICY_FILE = (
    REPO_ROOT
    / "vars"
    / "compliance_policies.yml"
)


class CompliancePolicyEngineTests(
    unittest.TestCase
):

    def load_state(self):
        return yaml.safe_load(
            STATE_FILE.read_text()
        )

    def load_policy(self):
        document = yaml.safe_load(
            POLICY_FILE.read_text()
        )

        return document[
            "compliance_policies"
        ][
            "NET-BGP-002"
        ]

    def test_matching_value_is_compliant(
        self,
    ):
        result = evaluate_policy(
            "NET-BGP-002",
            self.load_policy(),
            self.load_state(),
            {
                "maximum_paths": 2,
            },
        )

        self.assertTrue(
            result["compliant"]
        )

        self.assertEqual(
            result["status"],
            "COMPLIANT",
        )

        self.assertEqual(
            result["expected"],
            2,
        )

        self.assertEqual(
            result["actual"],
            2,
        )

    def test_drift_is_non_compliant(
        self,
    ):
        state = self.load_state()

        state[
            "bgp"
        ][
            "ipv4_unicast"
        ][
            "maximum_paths"
        ] = 1

        result = evaluate_policy(
            "NET-BGP-002",
            self.load_policy(),
            state,
            {
                "maximum_paths": 2,
            },
        )

        self.assertFalse(
            result["compliant"]
        )

        self.assertEqual(
            result["status"],
            "NON_COMPLIANT",
        )

        self.assertEqual(
            result["actual"],
            1,
        )

        self.assertEqual(
            result["expected"],
            2,
        )

    def test_missing_intent_fails_closed(
        self,
    ):
        with self.assertRaises(
            PolicyEvaluationError
        ):
            evaluate_policy(
                "NET-BGP-002",
                self.load_policy(),
                self.load_state(),
                {},
            )

    def test_missing_state_path_fails_closed(
        self,
    ):
        state = self.load_state()

        del state[
            "bgp"
        ][
            "ipv4_unicast"
        ][
            "maximum_paths"
        ]

        with self.assertRaises(
            PolicyEvaluationError
        ):
            evaluate_policy(
                "NET-BGP-002",
                self.load_policy(),
                state,
                {
                    "maximum_paths": 2,
                },
            )

    def test_unsupported_operator_fails_closed(
        self,
    ):
        policy = copy.deepcopy(
            self.load_policy()
        )

        policy[
            "comparison"
        ][
            "operator"
        ] = "contains"

        with self.assertRaises(
            PolicyEvaluationError
        ):
            evaluate_policy(
                "NET-BGP-002",
                policy,
                self.load_state(),
                {
                    "maximum_paths": 2,
                },
            )

    def test_result_is_vendor_independent(
        self,
    ):
        result = evaluate_policy(
            "NET-BGP-002",
            self.load_policy(),
            self.load_state(),
            {
                "maximum_paths": 2,
            },
        )

        self.assertNotIn(
            "vtysh",
            str(result),
        )

        self.assertNotIn(
            "frr",
            str(result).lower(),
        )


if __name__ == "__main__":
    unittest.main()
