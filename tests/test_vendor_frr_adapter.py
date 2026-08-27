#!/usr/bin/env python3

from pathlib import Path
import subprocess
import sys
import unittest

import yaml

from scripts.compliance_policy_engine import (
    PolicyEvaluationError,
    evaluate_policy,
)

from scripts.normalized_network_state import (
    resolve_dotted_path,
    validate_normalized_state,
)

from scripts.vendor_frr_adapter import (
    FrrAdapterError,
    normalize_frr_state,
    parse_frr_bgp_summary,
    parse_frr_running_config,
)


REPO_ROOT = Path(__file__).resolve().parents[1]

RUNNING_CONFIG = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "frr"
    / "leaf01_running_config.txt"
)

BGP_SUMMARY = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "frr"
    / "leaf01_bgp_summary.txt"
)

POLICY_FILE = (
    REPO_ROOT
    / "vars"
    / "compliance_policies.yml"
)


class FrrAdapterTests(
    unittest.TestCase
):

    def running_config(self):
        return RUNNING_CONFIG.read_text()

    def bgp_summary(self):
        return BGP_SUMMARY.read_text()

    def policy(self):
        data = yaml.safe_load(
            POLICY_FILE.read_text()
        )

        return data[
            "compliance_policies"
        ][
            "NET-BGP-002"
        ]

    def normalized(self):
        return normalize_frr_state(
            self.running_config(),
            self.bgp_summary(),
            device_name="leaf01",
            role="leaf",
        )

    def test_running_config_hostname(
        self,
    ):
        parsed = parse_frr_running_config(
            self.running_config()
        )

        self.assertEqual(
            parsed["hostname"],
            "leaf01",
        )

    def test_running_config_bgp_values(
        self,
    ):
        parsed = parse_frr_running_config(
            self.running_config()
        )

        self.assertEqual(
            parsed["bgp"]["local_as"],
            65101,
        )

        self.assertEqual(
            parsed["bgp"]["router_id"],
            "10.255.1.1",
        )

        self.assertEqual(
            parsed["bgp"]["maximum_paths"],
            2,
        )

    def test_running_config_interfaces(
        self,
    ):
        parsed = parse_frr_running_config(
            self.running_config()
        )

        self.assertEqual(
            parsed["interfaces"]["eth1"],
            ["10.0.0.1/31"],
        )

        self.assertEqual(
            parsed["interfaces"]["eth2"],
            ["10.0.0.5/31"],
        )

        self.assertEqual(
            parsed["interfaces"]["lo"],
            ["10.255.1.1/32"],
        )

    def test_running_config_neighbors(
        self,
    ):
        parsed = parse_frr_running_config(
            self.running_config()
        )

        neighbors = parsed[
            "bgp"
        ][
            "neighbors"
        ]

        self.assertEqual(
            neighbors[
                "10.0.0.0"
            ][
                "remote_as"
            ],
            65000,
        )

        self.assertEqual(
            neighbors[
                "10.0.0.4"
            ][
                "description"
            ],
            "SPINE02",
        )

    def test_bgp_summary_header(
        self,
    ):
        parsed = parse_frr_bgp_summary(
            self.bgp_summary()
        )

        self.assertEqual(
            parsed["router_id"],
            "10.255.1.1",
        )

        self.assertEqual(
            parsed["local_as"],
            65101,
        )

    def test_bgp_summary_neighbors_established(
        self,
    ):
        parsed = parse_frr_bgp_summary(
            self.bgp_summary()
        )

        neighbors = parsed[
            "neighbors"
        ]

        self.assertEqual(
            neighbors[
                "10.0.0.0"
            ][
                "operational_state"
            ],
            "Established",
        )

        self.assertEqual(
            neighbors[
                "10.0.0.4"
            ][
                "operational_state"
            ],
            "Established",
        )

    def test_normalized_state_is_valid(
        self,
    ):
        normalized = self.normalized()

        self.assertEqual(
            validate_normalized_state(
                normalized
            ),
            [],
        )

    def test_runtime_loopback_name_is_lo(
        self,
    ):
        normalized = self.normalized()

        self.assertEqual(
            normalized["loopbacks"],
            [
                {
                    "name": "lo",
                    "ipv4_addresses": [
                        "10.255.1.1/32",
                    ],
                }
            ],
        )

    def test_reference_policy_path_resolves(
        self,
    ):
        normalized = self.normalized()

        value = resolve_dotted_path(
            normalized,
            self.policy()[
                "state"
            ][
                "path"
            ],
        )

        self.assertEqual(
            value,
            2,
        )

    def test_reference_policy_is_compliant(
        self,
    ):
        result = evaluate_policy(
            "NET-BGP-002",
            self.policy(),
            self.normalized(),
            {
                "maximum_paths": 2,
            },
        )

        self.assertEqual(
            result["status"],
            "COMPLIANT",
        )

    def test_maximum_paths_drift_is_detected(
        self,
    ):
        running = self.running_config()

        drifted = running.replace(
            "maximum-paths 2",
            "maximum-paths 1",
            1,
        )

        normalized = normalize_frr_state(
            drifted,
            self.bgp_summary(),
            device_name="leaf01",
            role="leaf",
        )

        result = evaluate_policy(
            "NET-BGP-002",
            self.policy(),
            normalized,
            {
                "maximum_paths": 2,
            },
        )

        self.assertEqual(
            result["status"],
            "NON_COMPLIANT",
        )

        self.assertEqual(
            result["expected"],
            2,
        )

        self.assertEqual(
            result["actual"],
            1,
        )

    def test_conflicting_summary_as_fails_closed(
        self,
    ):
        summary = self.bgp_summary()

        conflicting = summary.replace(
            "local AS number 65101",
            "local AS number 65000",
            1,
        )

        with self.assertRaises(
            FrrAdapterError
        ):
            normalize_frr_state(
                self.running_config(),
                conflicting,
                device_name="leaf01",
                role="leaf",
            )


    def test_direct_cli_invocation_succeeds(
        self,
    ):
        adapter = (
            REPO_ROOT
            / "scripts"
            / "vendor_frr_adapter.py"
        )

        result = subprocess.run(
            [
                sys.executable,
                str(adapter),
                "--running-config",
                str(RUNNING_CONFIG),
                "--bgp-summary",
                str(BGP_SUMMARY),
                "--device-name",
                "leaf01",
                "--role",
                "leaf",
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=result.stderr,
        )

        state = yaml.safe_load(
            result.stdout
        )

        self.assertEqual(
            state["device"]["name"],
            "leaf01",
        )

        self.assertEqual(
            state[
                "bgp"
            ][
                "ipv4_unicast"
            ][
                "maximum_paths"
            ],
            2,
        )


    def test_requested_hostname_mismatch_fails_closed(
        self,
    ):
        with self.assertRaises(
            FrrAdapterError
        ):
            normalize_frr_state(
                self.running_config(),
                self.bgp_summary(),
                device_name="leaf02",
                role="leaf",
            )

    def test_router_id_mismatch_fails_closed(
        self,
    ):
        summary = self.bgp_summary()

        conflicting = summary.replace(
            "BGP router identifier 10.255.1.1",
            "BGP router identifier 10.255.1.99",
            1,
        )

        with self.assertRaises(
            FrrAdapterError
        ):
            normalize_frr_state(
                self.running_config(),
                conflicting,
                device_name="leaf01",
                role="leaf",
            )

    def test_missing_maximum_paths_policy_fails_closed(
        self,
    ):
        running = self.running_config()

        without_maximum_paths = running.replace(
            "  maximum-paths 2\n",
            "",
            1,
        )

        normalized = normalize_frr_state(
            without_maximum_paths,
            self.bgp_summary(),
            device_name="leaf01",
            role="leaf",
        )

        self.assertNotIn(
            "maximum_paths",
            normalized[
                "bgp"
            ][
                "ipv4_unicast"
            ],
        )

        with self.assertRaises(
            PolicyEvaluationError
        ):
            evaluate_policy(
                "NET-BGP-002",
                self.policy(),
                normalized,
                {
                    "maximum_paths": 2,
                },
            )

    def test_neighbor_missing_from_summary_is_normalized_missing(
        self,
    ):
        summary = self.bgp_summary()

        lines = [
            line
            for line in summary.splitlines()
            if not line.startswith(
                "10.0.0.4 "
            )
        ]

        reduced_summary = (
            "\n".join(lines)
            + "\n"
        )

        normalized = normalize_frr_state(
            self.running_config(),
            reduced_summary,
            device_name="leaf01",
            role="leaf",
        )

        neighbors = {
            item["address"]: item
            for item in normalized[
                "bgp"
            ][
                "neighbors"
            ]
        }

        self.assertEqual(
            neighbors[
                "10.0.0.4"
            ][
                "operational_state"
            ],
            "Missing",
        )

    def test_active_neighbor_state_is_preserved(
        self,
    ):
        summary = self.bgp_summary()

        lines = summary.splitlines()

        changed = False
        new_lines = []

        for line in lines:
            if line.startswith(
                "10.0.0.0 "
            ):
                parts = line.split()

                self.assertGreaterEqual(
                    len(parts),
                    12,
                )

                parts[9] = "Active"

                line = " ".join(parts)
                changed = True

            new_lines.append(line)

        self.assertTrue(changed)

        active_summary = (
            "\n".join(new_lines)
            + "\n"
        )

        normalized = normalize_frr_state(
            self.running_config(),
            active_summary,
            device_name="leaf01",
            role="leaf",
        )

        neighbors = {
            item["address"]: item
            for item in normalized[
                "bgp"
            ][
                "neighbors"
            ]
        }

        self.assertEqual(
            neighbors[
                "10.0.0.0"
            ][
                "operational_state"
            ],
            "Active",
        )

        self.assertNotEqual(
            neighbors[
                "10.0.0.0"
            ][
                "operational_state"
            ],
            "Established",
        )

    def test_malformed_bgp_neighbor_row_fails_closed(
        self,
    ):
        summary = self.bgp_summary()

        malformed = (
            summary
            + "10.0.0.8 4 65000\n"
        )

        with self.assertRaises(
            FrrAdapterError
        ):
            parse_frr_bgp_summary(
                malformed
            )


if __name__ == "__main__":
    unittest.main()
