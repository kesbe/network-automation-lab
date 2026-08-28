#!/usr/bin/env python3

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

from scripts.generic_compliance_runner import (
    GenericComplianceRunnerError,
    normalize_platform_state,
    run_compliance,
)


ROOT = Path(__file__).resolve().parents[1]

RUNNING_CONFIG = (
    ROOT
    / "tests"
    / "fixtures"
    / "frr"
    / "leaf01_running_config.txt"
)

BGP_SUMMARY = (
    ROOT
    / "tests"
    / "fixtures"
    / "frr"
    / "leaf01_bgp_summary.txt"
)

POLICY_FILE = (
    ROOT
    / "vars"
    / "compliance_policies.yml"
)

RUNNER = (
    ROOT
    / "scripts"
    / "generic_compliance_runner.py"
)


class GenericComplianceRunnerTests(
    unittest.TestCase
):

    def running_config(self):
        return RUNNING_CONFIG.read_text()

    def bgp_summary(self):
        return BGP_SUMMARY.read_text()

    def policies(self):
        return yaml.safe_load(
            POLICY_FILE.read_text()
        )["compliance_policies"]

    def raw_inputs(
        self,
        running_config=None,
    ):
        return {
            "running_config": (
                self.running_config()
                if running_config is None
                else running_config
            ),
            "bgp_summary":
                self.bgp_summary(),
        }

    def intent(self):
        return {
            "maximum_paths": 2,
        }

    def test_frr_normalization_dispatch(
        self,
    ):
        state = normalize_platform_state(
            "frr",
            self.raw_inputs(),
            device_name="leaf01",
            role="leaf",
        )

        self.assertEqual(
            state["device"]["name"],
            "leaf01",
        )

        self.assertEqual(
            state["device"]["platform"],
            "frr",
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

    def test_clean_frr_pipeline_is_compliant(
        self,
    ):
        result = run_compliance(
            "frr",
            self.raw_inputs(),
            self.policies(),
            self.intent(),
            device_name="leaf01",
            role="leaf",
        )

        self.assertEqual(
            result,
            {
                "device": "leaf01",
                "status": "COMPLIANT",
                "total_checks": 1,
                "passed": 1,
                "failed": 0,
                "violations": [],
            },
        )

    def test_frr_drift_pipeline_is_non_compliant(
        self,
    ):
        drifted = (
            self.running_config()
            .replace(
                "maximum-paths 2",
                "maximum-paths 1",
                1,
            )
        )

        result = run_compliance(
            "frr",
            self.raw_inputs(
                running_config=drifted,
            ),
            self.policies(),
            self.intent(),
            device_name="leaf01",
            role="leaf",
        )

        self.assertEqual(
            result["status"],
            "NON_COMPLIANT",
        )

        finding = result[
            "violations"
        ][0]

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

    def test_unsupported_platform_fails_closed(
        self,
    ):
        with self.assertRaises(
            GenericComplianceRunnerError
        ):
            normalize_platform_state(
                "juniper_junos",
                self.raw_inputs(),
                device_name="leaf01",
                role="leaf",
            )

    def test_missing_frr_input_fails_closed(
        self,
    ):
        with self.assertRaises(
            GenericComplianceRunnerError
        ):
            normalize_platform_state(
                "frr",
                {
                    "running_config":
                        self.running_config(),
                },
                device_name="leaf01",
                role="leaf",
            )

    def test_direct_cli_real_fixture_succeeds(
        self,
    ):
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
                    str(RUNNER),
                    "--platform",
                    "frr",
                    "--device-name",
                    "leaf01",
                    "--role",
                    "leaf",
                    "--running-config",
                    str(RUNNING_CONFIG),
                    "--bgp-summary",
                    str(BGP_SUMMARY),
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
