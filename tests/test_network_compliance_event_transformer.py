#!/usr/bin/env python3

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

TRANSFORMER_PATH = (
    ROOT
    / "scripts"
    / "build_network_compliance_drift_event.py"
)

VALIDATOR_PATH = (
    ROOT
    / "scripts"
    / "validate_network_compliance_event.py"
)

DRIFT_FIXTURE = (
    ROOT
    / "tests"
    / "fixtures"
    / "awx_aggregator_drift_realshape.json"
)

CLEAN_FIXTURE = (
    ROOT
    / "tests"
    / "fixtures"
    / "awx_aggregator_clean_realshape.json"
)


spec = importlib.util.spec_from_file_location(
    "network_compliance_transformer",
    TRANSFORMER_PATH,
)

transformer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transformer)


def load_json(path):
    return json.loads(
        Path(path).read_text()
    )


class NetworkComplianceEventTransformerTests(
    unittest.TestCase
):

    def setUp(self):
        self.drift = load_json(
            DRIFT_FIXTURE
        )

        self.clean = load_json(
            CLEAN_FIXTURE
        )

    def test_real_drift_fixture_maps_correctly(self):
        event = transformer.build_event(
            copy.deepcopy(self.drift)
        )

        self.assertIsInstance(
            event,
            dict,
        )

        self.assertEqual(
            event["schema_version"],
            "1.0",
        )

        self.assertEqual(
            event["event_type"],
            "NETWORK_COMPLIANCE_DRIFT_DETECTED",
        )

        correlation = event["correlation"]

        self.assertEqual(
            correlation["compliance_run_id"],
            "compliance-43c5eacb-51b2-4580-b831-32dd05097585",
        )

        self.assertEqual(
            correlation["compliance_job_id"],
            529,
        )

        self.assertEqual(
            correlation["aggregator_job_id"],
            531,
        )

        summary = event["summary"]

        self.assertEqual(
            summary["devices_evaluated"],
            4,
        )

        self.assertEqual(
            summary["devices_noncompliant"],
            1,
        )

        self.assertEqual(
            summary["findings_total"],
            1,
        )

        finding = event["findings"][0]

        self.assertEqual(
            finding["finding_id"],
            "finding-c4773cf087b147948a8f",
        )

        self.assertEqual(
            finding["fingerprint"],
            "leaf01|NET-BGP-002|device",
        )

        self.assertEqual(
            finding["device"],
            "leaf01",
        )

        self.assertEqual(
            finding["policy_id"],
            "NET-BGP-002",
        )

        self.assertEqual(
            finding["severity"],
            "high",
        )

        self.assertFalse(
            finding["ticket_required"]
        )

        self.assertEqual(
            finding["remediation_mode"],
            "auto",
        )

        self.assertEqual(
            finding["observed"],
            "missing or different",
        )

        self.assertEqual(
            finding["expected"],
            2,
        )

    def test_awx_string_ids_are_normalized(self):
        event = transformer.build_event(
            copy.deepcopy(self.drift)
        )

        self.assertIsInstance(
            event["correlation"]["compliance_job_id"],
            int,
        )

        self.assertIsInstance(
            event["correlation"]["aggregator_job_id"],
            int,
        )

        self.assertEqual(
            event["correlation"]["compliance_job_id"],
            529,
        )

        self.assertEqual(
            event["correlation"]["aggregator_job_id"],
            531,
        )

    def test_clean_run_produces_no_event(self):
        event = transformer.build_event(
            copy.deepcopy(self.clean)
        )

        self.assertIsNone(event)

    def test_event_id_is_deterministic(self):
        first = transformer.build_event(
            copy.deepcopy(self.drift)
        )

        second = transformer.build_event(
            copy.deepcopy(self.drift)
        )

        self.assertEqual(
            first["event_id"],
            second["event_id"],
        )

        self.assertEqual(
            json.dumps(
                first,
                sort_keys=True,
            ),
            json.dumps(
                second,
                sort_keys=True,
            ),
        )

    def test_multiple_findings_still_produce_one_event(self):
        source = copy.deepcopy(
            self.drift
        )

        run = (
            source["artifacts"]
                  ["compliance_run"]
        )

        second = copy.deepcopy(
            run["findings"][0]
        )

        second.update({
            "finding_id":
                "finding-aaaaaaaaaaaaaaaaaaaa",

            "finding_fingerprint":
                "leaf02|NET-BGP-003|device",

            "device":
                "leaf02",

            "policy_id":
                "NET-BGP-003",
        })

        run["findings"].append(second)

        run["summary"]["total_findings"] = 2
        run["summary"]["devices_noncompliant"] = 2
        run["summary"]["high_findings"] = 2

        event = transformer.build_event(
            source
        )

        self.assertIsInstance(
            event,
            dict,
        )

        self.assertEqual(
            len(event["findings"]),
            2,
        )

    def test_aggregator_job_mismatch_fails_closed(self):
        source = copy.deepcopy(
            self.drift
        )

        source["artifacts"][
            "aggregator_job_id"
        ] = "999999"

        with self.assertRaises(ValueError):
            transformer.build_event(source)

    def test_summary_finding_count_mismatch_fails_closed(self):
        source = copy.deepcopy(
            self.drift
        )

        source["artifacts"][
            "compliance_run"
        ]["summary"]["total_findings"] = 999

        with self.assertRaises(ValueError):
            transformer.build_event(source)

    def test_missing_remediation_mode_fails_closed(self):
        source = copy.deepcopy(
            self.drift
        )

        finding = (
            source["artifacts"]
                  ["compliance_run"]
                  ["findings"][0]
        )

        finding["remediation"].pop(
            "mode",
            None,
        )

        with self.assertRaises(ValueError):
            transformer.build_event(source)

    def test_generated_real_event_passes_contract_validator(self):
        event = transformer.build_event(
            copy.deepcopy(self.drift)
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = (
                Path(tmp)
                / "event.json"
            )

            path.write_text(
                json.dumps(event)
                + "\n"
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR_PATH),
                    str(path),
                ],
                capture_output=True,
                text=True,
            )

        self.assertEqual(
            result.returncode,
            0,
            msg=result.stdout + result.stderr,
        )

        self.assertIn(
            "network_compliance_event_contract=PASS",
            result.stdout,
        )

    def test_transformer_contains_no_transport_or_awx_action(self):
        source = (
            TRANSFORMER_PATH
            .read_text()
            .lower()
        )

        forbidden = (
            "kafka-console-producer",
            "run_workflow_template",
            "wf40",
            "awx_token",
            "awx_password",
        )

        for term in forbidden:
            self.assertNotIn(
                term,
                source,
                msg=f"forbidden term present: {term}",
            )


if __name__ == "__main__":
    unittest.main()
