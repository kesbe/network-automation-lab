#!/usr/bin/env python3

import copy
from pathlib import Path
import unittest

import yaml

from scripts.normalized_network_state import (
    resolve_dotted_path,
    validate_normalized_state,
)


REPO_ROOT = Path(__file__).resolve().parents[1]

STATE_FIXTURE = (
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


class NormalizedNetworkStateTests(
    unittest.TestCase
):

    def load_state(self):
        return yaml.safe_load(
            STATE_FIXTURE.read_text()
        )

    def load_reference_policy(self):
        document = yaml.safe_load(
            POLICY_FILE.read_text()
        )

        return document[
            "compliance_policies"
        ][
            "NET-BGP-002"
        ]

    def test_valid_reference_state_passes(
        self,
    ):
        state = self.load_state()

        self.assertEqual(
            validate_normalized_state(state),
            [],
        )

    def test_reference_policy_state_path_resolves(
        self,
    ):
        state = self.load_state()
        policy = self.load_reference_policy()

        state_path = policy[
            "state"
        ][
            "path"
        ]

        actual = resolve_dotted_path(
            state,
            state_path,
        )

        self.assertEqual(
            state_path,
            "bgp.ipv4_unicast.maximum_paths",
        )

        self.assertEqual(
            actual,
            2,
        )

    def test_missing_state_path_fails_closed(
        self,
    ):
        state = self.load_state()

        with self.assertRaises(KeyError):
            resolve_dotted_path(
                state,
                "bgp.ipv4_unicast."
                "nonexistent",
            )

    def test_invalid_schema_version_is_rejected(
        self,
    ):
        state = self.load_state()
        state["schema_version"] = "99.0"

        errors = validate_normalized_state(
            state
        )

        self.assertTrue(
            any(
                "schema_version"
                in error
                for error in errors
            )
        )

    def test_invalid_maximum_paths_is_rejected(
        self,
    ):
        state = self.load_state()

        state[
            "bgp"
        ][
            "ipv4_unicast"
        ][
            "maximum_paths"
        ] = 0

        errors = validate_normalized_state(
            state
        )

        self.assertTrue(
            any(
                "maximum_paths"
                in error
                for error in errors
            )
        )

    def test_neighbor_collection_must_be_list(
        self,
    ):
        state = self.load_state()

        state[
            "bgp"
        ][
            "neighbors"
        ] = {
            "10.0.0.0": {
                "remote_as": 65000
            }
        }

        errors = validate_normalized_state(
            state
        )

        self.assertTrue(
            any(
                "bgp.neighbors must be a list"
                in error
                for error in errors
            )
        )

    def test_device_platform_is_required(
        self,
    ):
        state = copy.deepcopy(
            self.load_state()
        )

        del state[
            "device"
        ][
            "platform"
        ]

        errors = validate_normalized_state(
            state
        )

        self.assertTrue(
            any(
                "device.platform"
                in error
                for error in errors
            )
        )


if __name__ == "__main__":
    unittest.main()
