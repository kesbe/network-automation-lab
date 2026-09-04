#!/usr/bin/env python3

import copy
import json
import unittest
from pathlib import Path

from scripts.v3_compliance_event import (
    EVENT_TYPE,
    build_event,
    deterministic_event_id,
    validate_event,
)
from scripts.v3_target_contract import (
    V3ContractError,
    build_resolved_target,
)

try:
    import jsonschema
except ImportError:
    jsonschema = None


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_PATH = (
    ROOT
    / "schemas"
    / "network_compliance_finding_event_v3.schema.json"
)


def make_target():
    return build_resolved_target(
        selector={
            "devices": [
                "leaf02",
                "leaf01",
            ],
            "tags": [
                "production",
                "network",
            ],
        },
        devices=[
            {
                "name": "leaf02",
                "platform": "frr",
                "vendor": "FRRouting",
                "site": "lab",
                "role": "leaf",
                "tags": [
                    "network",
                    "production",
                ],
            },
            {
                "name": "leaf01",
                "platform": "frr",
                "vendor": "FRRouting",
                "site": "lab",
                "role": "leaf",
                "tags": [
                    "production",
                    "network",
                ],
            },
        ],
    )


def make_finding():
    return {
        "finding_id":
            "finding-v3-event-test",

        "device":
            "leaf01",

        "vendor":
            "FRRouting",

        "platform":
            "frr",

        "control":
            "bgp_maximum_paths",

        "severity":
            "high",

        "status":
            "NON_COMPLIANT",

        "remediable":
            True,

        "remediation_policy":
            "auto",

        "ticket_required":
            False,

        "policy_id":
            "NET-BGP-002",

        "expected":
            2,

        "actual":
            1,
    }


def make_event(
    lifecycle_event_type="DETECTED",
):
    return build_event(
        finding=make_finding(),
        resolved_target=make_target(),
        lifecycle_event_type=
            lifecycle_event_type,
        compliance_run_id=
            "compliance-v3-event-test",
        activated_at=
            "2026-08-31T01:30:00+10:00",
    )


class V3ComplianceEventTests(
    unittest.TestCase
):

    def test_build_event_contract(self):
        target = make_target()

        event = build_event(
            finding=make_finding(),
            resolved_target=target,
            lifecycle_event_type="DETECTED",
            compliance_run_id=
                "compliance-v3-event-test",
            activated_at=
                "2026-08-31T01:30:00+10:00",
        )

        self.assertEqual(
            event["schema_version"],
            "3.0",
        )

        self.assertEqual(
            event["event_type"],
            EVENT_TYPE,
        )

        self.assertEqual(
            event["lifecycle_event_type"],
            "DETECTED",
        )

        self.assertEqual(
            event["activated_at"],
            "2026-08-30T15:30:00Z",
        )

        self.assertEqual(
            event["finding"]["status"],
            "NON_COMPLIANT",
        )

        self.assertEqual(
            event["finding"]
                 ["remediation_policy"],
            "auto",
        )

        self.assertTrue(
            event["event_id"].startswith(
                "v3-compliance-event-"
            )
        )

        validate_event(event)


    def test_resolved_target_identity_is_preserved(
        self,
    ):
        target = make_target()

        self.assertEqual(
            target["device_count"],
            2,
        )

        event = build_event(
            finding=make_finding(),
            resolved_target=target,
            lifecycle_event_type="DETECTED",
            compliance_run_id=
                "compliance-v3-event-test",
            activated_at=
                "2026-08-31T01:30:00+10:00",
        )

        self.assertEqual(
            event["target"]["target_id"],
            target["target_id"],
        )

        self.assertEqual(
            event["target"],
            target,
        )

        self.assertEqual(
            event["target"]["device_count"],
            2,
        )


    def test_event_identity_is_deterministic(
        self,
    ):
        first = make_event()
        second = make_event()

        self.assertEqual(
            first["event_id"],
            second["event_id"],
        )

        self.assertEqual(
            first,
            second,
        )


    def test_event_id_matches_public_builder(
        self,
    ):
        event = make_event()

        expected = deterministic_event_id(
            compliance_run_id=
                event["compliance_run_id"],
            lifecycle_event_type=
                event["lifecycle_event_type"],
            finding_id=
                event["finding"]["finding_id"],
            target_id=
                event["target"]["target_id"],
        )

        self.assertEqual(
            event["event_id"],
            expected,
        )


    def test_reopened_is_an_activation(self):
        event = make_event(
            lifecycle_event_type="REOPENED"
        )

        self.assertEqual(
            event["lifecycle_event_type"],
            "REOPENED",
        )

        validate_event(event)


    def test_detected_and_reopened_have_distinct_ids(
        self,
    ):
        detected = make_event(
            lifecycle_event_type="DETECTED"
        )

        reopened = make_event(
            lifecycle_event_type="REOPENED"
        )

        self.assertNotEqual(
            detected["event_id"],
            reopened["event_id"],
        )


    def test_seen_again_is_not_an_activation(
        self,
    ):
        with self.assertRaises(
            V3ContractError
        ):
            build_event(
                finding=make_finding(),
                resolved_target=make_target(),
                lifecycle_event_type=
                    "SEEN_AGAIN",
                compliance_run_id=
                    "compliance-v3-event-test",
                activated_at=
                    "2026-08-31T01:30:00+10:00",
            )


    def test_compliant_finding_is_rejected(
        self,
    ):
        finding = make_finding()
        finding["status"] = "COMPLIANT"

        with self.assertRaises(
            V3ContractError
        ):
            build_event(
                finding=finding,
                resolved_target=make_target(),
                lifecycle_event_type=
                    "DETECTED",
                compliance_run_id=
                    "compliance-v3-event-test",
                activated_at=
                    "2026-08-31T01:30:00+10:00",
            )


    def test_finding_device_must_be_in_target(
        self,
    ):
        finding = make_finding()

        finding["device"] = "edge99"

        with self.assertRaises(
            V3ContractError
        ):
            build_event(
                finding=finding,
                resolved_target=make_target(),
                lifecycle_event_type=
                    "DETECTED",
                compliance_run_id=
                    "compliance-v3-event-test",
                activated_at=
                    "2026-08-31T01:30:00+10:00",
            )


    def test_finding_platform_must_match_target(
        self,
    ):
        finding = make_finding()

        finding["platform"] = "cisco_ios"

        with self.assertRaises(
            V3ContractError
        ):
            build_event(
                finding=finding,
                resolved_target=make_target(),
                lifecycle_event_type=
                    "DETECTED",
                compliance_run_id=
                    "compliance-v3-event-test",
                activated_at=
                    "2026-08-31T01:30:00+10:00",
            )


    def test_finding_vendor_must_match_target(
        self,
    ):
        finding = make_finding()

        finding["vendor"] = "Cisco"

        with self.assertRaises(
            V3ContractError
        ):
            build_event(
                finding=finding,
                resolved_target=make_target(),
                lifecycle_event_type=
                    "DETECTED",
                compliance_run_id=
                    "compliance-v3-event-test",
                activated_at=
                    "2026-08-31T01:30:00+10:00",
            )


    def test_aliases_are_canonicalized(
        self,
    ):
        finding = make_finding()

        finding["platform"] = "FRR"

        finding["status"] = (
            "non_compliant"
        )

        finding["remediation_policy"] = (
            "automatic"
        )

        event = build_event(
            finding=finding,
            resolved_target=make_target(),
            lifecycle_event_type=
                "detected",
            compliance_run_id=
                " compliance-v3-event-test ",
            activated_at=
                "2026-08-30T15:30:00Z",
        )

        self.assertEqual(
            event["finding"]["platform"],
            "frr",
        )

        self.assertEqual(
            event["finding"]["status"],
            "NON_COMPLIANT",
        )

        self.assertEqual(
            event["finding"]
                 ["remediation_policy"],
            "auto",
        )

        self.assertEqual(
            event["lifecycle_event_type"],
            "DETECTED",
        )

        self.assertEqual(
            event["compliance_run_id"],
            "compliance-v3-event-test",
        )


    def test_tampered_event_id_is_rejected(
        self,
    ):
        event = make_event()

        event["event_id"] = (
            "v3-compliance-event-"
            + ("0" * 32)
        )

        with self.assertRaises(
            V3ContractError
        ):
            validate_event(event)


    def test_noncanonical_timestamp_is_rejected(
        self,
    ):
        event = make_event()

        event["activated_at"] = (
            "2026-08-31T01:30:00+10:00"
        )

        with self.assertRaises(
            V3ContractError
        ):
            validate_event(event)


    def test_approval_requires_ticket(
        self,
    ):
        finding = make_finding()

        finding["remediation_policy"] = (
            "approval_required"
        )

        finding["ticket_required"] = False

        with self.assertRaises(
            V3ContractError
        ):
            build_event(
                finding=finding,
                resolved_target=make_target(),
                lifecycle_event_type=
                    "DETECTED",
                compliance_run_id=
                    "compliance-v3-event-test",
                activated_at=
                    "2026-08-30T15:30:00Z",
            )


    def test_schema_is_valid_json(self):
        schema = json.loads(
            SCHEMA_PATH.read_text()
        )

        self.assertEqual(
            schema["properties"]
                  ["schema_version"]
                  ["const"],
            "3.0",
        )

        self.assertEqual(
            schema["properties"]
                  ["event_type"]
                  ["const"],
            EVENT_TYPE,
        )


    @unittest.skipIf(
        jsonschema is None,
        "jsonschema package is not installed",
    )
    def test_event_matches_json_schema(self):
        schema = json.loads(
            SCHEMA_PATH.read_text()
        )

        jsonschema.Draft202012Validator\
            .check_schema(schema)

        validator = (
            jsonschema.Draft202012Validator(
                schema,
                format_checker=
                    jsonschema.FormatChecker(),
            )
        )

        validator.validate(
            make_event()
        )


if __name__ == "__main__":
    unittest.main()
