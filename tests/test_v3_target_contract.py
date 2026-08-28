import unittest

from scripts.v3_target_contract import (
    V3ContractError,
    build_resolved_target,
    normalize_remediation_policy,
    validate_finding,
    validate_resolved_target,
)


class V3TargetContractTests(
    unittest.TestCase
):

    def test_auto_alias_is_normalized(
        self,
    ):
        self.assertEqual(
            normalize_remediation_policy(
                "automatic"
            ),
            "auto",
        )

        self.assertEqual(
            normalize_remediation_policy(
                "auto"
            ),
            "auto",
        )

    def test_approval_policy_supported(
        self,
    ):
        self.assertEqual(
            normalize_remediation_policy(
                "approval_required"
            ),
            "approval_required",
        )

    def test_target_is_deterministic(
        self,
    ):
        selector = {
            "devices": [
                "leaf02",
                "leaf01",
            ]
        }

        devices = [
            {
                "name": "leaf02",
                "platform": "frr",
                "vendor": "FRRouting",
                "role": "leaf",
            },
            {
                "name": "leaf01",
                "platform": "frr",
                "vendor": "FRRouting",
                "role": "leaf",
            },
        ]

        first = build_resolved_target(
            selector=selector,
            devices=devices,
        )

        second = build_resolved_target(
            selector=selector,
            devices=list(reversed(devices)),
        )

        self.assertEqual(
            first["target_id"],
            second["target_id"],
        )

        self.assertEqual(
            first["device_names"],
            [
                "leaf01",
                "leaf02",
            ],
        )

        validate_resolved_target(
            first
        )

    def test_target_id_ignores_selector_device_order(
        self,
    ):
        devices = [
            {
                "name": "leaf01",
                "platform": "frr",
                "vendor": "FRRouting",
                "role": "leaf",
                "site": "lab",
                "tags": [
                    "network",
                    "production",
                ],
            },
            {
                "name": "leaf02",
                "platform": "frr",
                "vendor": "FRRouting",
                "role": "leaf",
                "site": "lab",
                "tags": [
                    "network",
                    "production",
                ],
            },
        ]

        first = build_resolved_target(
            selector={
                "devices": [
                    "leaf01",
                    "leaf02",
                ],
            },
            devices=devices,
        )

        second = build_resolved_target(
            selector={
                "devices": [
                    "leaf02",
                    "leaf01",
                ],
            },
            devices=devices,
        )

        self.assertEqual(
            first["target_id"],
            second["target_id"],
        )


    def test_target_id_ignores_selector_tag_order(
        self,
    ):
        devices = [
            {
                "name": "leaf01",
                "platform": "frr",
                "vendor": "FRRouting",
                "role": "leaf",
                "site": "lab",
                "tags": [
                    "network",
                    "production",
                ],
            },
        ]

        first = build_resolved_target(
            selector={
                "tags": [
                    "network",
                    "production",
                ],
            },
            devices=devices,
        )

        second = build_resolved_target(
            selector={
                "tags": [
                    "production",
                    "network",
                ],
            },
            devices=devices,
        )

        self.assertEqual(
            first["target_id"],
            second["target_id"],
        )


    def test_approval_requires_ticket(
        self,
    ):
        finding = {
            "finding_id": "finding-test",
            "device": "leaf01",
            "vendor": "FRRouting",
            "platform": "frr",
            "control": "bgp_maximum_paths",
            "severity": "high",
            "status": "NON_COMPLIANT",
            "remediable": True,
            "remediation_policy":
                "approval_required",
            "ticket_required": False,
        }

        with self.assertRaises(
            V3ContractError
        ):
            validate_finding(
                finding
            )

    def test_nonremediable_cannot_auto(
        self,
    ):
        finding = {
            "finding_id": "finding-test",
            "device": "leaf01",
            "vendor": "FRRouting",
            "platform": "frr",
            "control": "firmware",
            "severity": "high",
            "status": "NON_COMPLIANT",
            "remediable": False,
            "remediation_policy": "auto",
            "ticket_required": True,
        }

        with self.assertRaises(
            V3ContractError
        ):
            validate_finding(
                finding
            )


if __name__ == "__main__":
    unittest.main()
