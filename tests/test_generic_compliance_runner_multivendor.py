from copy import deepcopy
from pathlib import Path
import unittest

import yaml

from scripts.generic_compliance_runner import (
    normalize_platform_state,
    run_compliance,
)


ROOT = Path(__file__).resolve().parents[1]

POLICY_FILE = (
    ROOT
    / "vars/compliance_policies.yml"
)


class GenericMultiVendorRunnerTests(
    unittest.TestCase
):

    def policies_for(
        self,
        platform,
        role,
    ):
        document = yaml.safe_load(
            POLICY_FILE.read_text()
        )

        source = document[
            "compliance_policies"
        ][
            "NET-BGP-002"
        ]

        policy = deepcopy(source)

        policy["scope"] = {
            "roles": [role],
            "platforms": [platform],
        }

        return {
            "NET-BGP-002": policy
        }

    def raw(
        self,
        vendor_dir,
        device,
    ):
        base = (
            ROOT
            / "tests/fixtures"
            / vendor_dir
        )

        return {
            "running_config": (
                base
                / f"{device}_running_config.txt"
            ).read_text(),
            "bgp_summary": (
                base
                / f"{device}_bgp_summary.txt"
            ).read_text(),
        }

    def test_cisco_dispatch(self):
        state = normalize_platform_state(
            "cisco_ios",
            self.raw(
                "cisco_ios",
                "edge01",
            ),
            device_name="edge01",
            role="edge",
            site="syd01",
        )

        self.assertEqual(
            state["device"]["platform"],
            "cisco_ios",
        )

        self.assertEqual(
            state["bgp"][
                "ipv4_unicast"
            ][
                "maximum_paths"
            ],
            2,
        )

    def test_arista_dispatch(self):
        state = normalize_platform_state(
            "arista_eos",
            self.raw(
                "arista_eos",
                "spine01",
            ),
            device_name="spine01",
            role="spine",
            site="syd01",
        )

        self.assertEqual(
            state["device"]["platform"],
            "arista_eos",
        )

        self.assertEqual(
            state["bgp"][
                "ipv4_unicast"
            ][
                "maximum_paths"
            ],
            2,
        )

    def test_cisco_pipeline_is_compliant(self):
        result = run_compliance(
            "cisco_ios",
            self.raw(
                "cisco_ios",
                "edge01",
            ),
            self.policies_for(
                "cisco_ios",
                "edge",
            ),
            {
                "maximum_paths": 2,
            },
            device_name="edge01",
            role="edge",
            site="syd01",
        )

        self.assertEqual(
            result["status"],
            "COMPLIANT",
        )

        self.assertEqual(
            result["total_checks"],
            1,
        )

    def test_arista_pipeline_is_compliant(self):
        result = run_compliance(
            "arista_eos",
            self.raw(
                "arista_eos",
                "spine01",
            ),
            self.policies_for(
                "arista_eos",
                "spine",
            ),
            {
                "maximum_paths": 2,
            },
            device_name="spine01",
            role="spine",
            site="syd01",
        )

        self.assertEqual(
            result["status"],
            "COMPLIANT",
        )

        self.assertEqual(
            result["total_checks"],
            1,
        )

    def test_cisco_drift_detected(self):
        raw = self.raw(
            "cisco_ios",
            "edge01",
        )

        raw["running_config"] = (
            raw["running_config"].replace(
                "maximum-paths 2",
                "maximum-paths 1",
                1,
            )
        )

        result = run_compliance(
            "cisco_ios",
            raw,
            self.policies_for(
                "cisco_ios",
                "edge",
            ),
            {
                "maximum_paths": 2,
            },
            device_name="edge01",
            role="edge",
        )

        self.assertEqual(
            result["status"],
            "NON_COMPLIANT",
        )

        self.assertEqual(
            result["violations"][0]["actual"],
            1,
        )

    def test_arista_drift_detected(self):
        raw = self.raw(
            "arista_eos",
            "spine01",
        )

        raw["running_config"] = (
            raw["running_config"].replace(
                "maximum-paths 2",
                "maximum-paths 1",
                1,
            )
        )

        result = run_compliance(
            "arista_eos",
            raw,
            self.policies_for(
                "arista_eos",
                "spine",
            ),
            {
                "maximum_paths": 2,
            },
            device_name="spine01",
            role="spine",
        )

        self.assertEqual(
            result["status"],
            "NON_COMPLIANT",
        )

        self.assertEqual(
            result["violations"][0]["actual"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
