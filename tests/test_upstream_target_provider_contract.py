\
import copy
import json
import unittest
from pathlib import Path

import yaml

from scripts.v3_target_contract import (
    V3ContractError,
    validate_finding,
)


ROOT = Path(
    __file__
).resolve().parents[1]


TICKET_POLICIES = {
    "NET-BGP-001",
    "NET-BGP-003",
    "NET-BGP-004",
    "NET-BGP-005",
    "NET-IP-001",
    "NET-IP-002",
}

NON_TICKET_POLICIES = {
    "NET-BGP-002",
    "NET-SYS-001",
}


class UpstreamTargetProviderContractTests(
    unittest.TestCase
):

    def test_policy_assignment_matrix(
        self,
    ):
        obj = yaml.safe_load(
            (
                ROOT
                / "vars/"
                  "compliance_policies.yml"
            ).read_text(
                encoding="utf-8"
            )
        )

        policies = obj[
            "compliance_policies"
        ]

        self.assertEqual(
            set(policies),
            TICKET_POLICIES
            | NON_TICKET_POLICIES,
        )

        for policy_id in (
            TICKET_POLICIES
        ):
            self.assertEqual(
                policies[
                    policy_id
                ][
                    "target_providers"
                ],
                [
                    "servicenow",
                ],
            )

        for policy_id in (
            NON_TICKET_POLICIES
        ):
            self.assertNotIn(
                "target_providers",
                policies[
                    policy_id
                ],
            )


    def test_v3_ticket_finding_requires_targets(
        self,
    ):
        finding = {
            "finding_id": "f-1",
            "device": "leaf01",
            "vendor": "frr",
            "platform": "frr",
            "control": "maximum_paths",
            "severity": "high",
            "status": "NON_COMPLIANT",
            "remediable": True,
            "remediation_policy": "auto",
            "ticket_required": True,
        }

        with self.assertRaises(
            V3ContractError
        ):
            validate_finding(
                finding
            )

        finding[
            "target_providers"
        ] = [
            "servicenow",
        ]

        result = validate_finding(
            finding
        )

        self.assertEqual(
            result[
                "target_providers"
            ],
            [
                "servicenow",
            ],
        )


    def test_v3_non_ticket_finding_forbids_targets(
        self,
    ):
        finding = {
            "finding_id": "f-2",
            "device": "leaf01",
            "vendor": "frr",
            "platform": "frr",
            "control": "hostname",
            "severity": "medium",
            "status": "NON_COMPLIANT",
            "remediable": False,
            "remediation_policy": "manual",
            "ticket_required": False,
            "target_providers": [
                "servicenow",
            ],
        }

        with self.assertRaises(
            V3ContractError
        ):
            validate_finding(
                finding
            )


    def test_v3_schema_contract(
        self,
    ):
        schema = json.loads(
            (
                ROOT
                / "schemas/"
                  "network_compliance_finding_event_v3.schema.json"
            ).read_text(
                encoding="utf-8"
            )
        )

        finding = schema[
            "$defs"
        ][
            "finding"
        ]

        self.assertIn(
            "target_providers",
            finding[
                "properties"
            ],
        )

        serialized = json.dumps(
            finding
        )

        self.assertIn(
            "target_providers",
            serialized,
        )


    def test_drift_schema_contract(
        self,
    ):
        schema = json.loads(
            (
                ROOT
                / "schemas/"
                  "network_compliance_drift_event_v1.schema.json"
            ).read_text(
                encoding="utf-8"
            )
        )

        finding = (
            schema[
                "properties"
            ][
                "findings"
            ][
                "items"
            ]
        )

        self.assertIn(
            "target_providers",
            finding[
                "properties"
            ],
        )


    def test_frr_policy_propagation(
        self,
    ):
        text = (
            ROOT
            / "playbooks/"
              "frr_compliance.yml"
        ).read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "policy_entry.value.target_providers",
            text,
        )

        self.assertIn(
            "if policy_entry.value.ticket_required",
            text,
        )


if __name__ == "__main__":
    unittest.main()
