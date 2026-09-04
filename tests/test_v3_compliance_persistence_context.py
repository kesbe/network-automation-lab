import copy
import json
import unittest
from pathlib import Path

from scripts.v3_compliance_event import (
    FINDING_FIELDS,
)
from scripts.v3_compliance_persistence_context import (
    LEGACY_REMEDIATION_POLICY_MAP,
    PERSISTENCE_CONTEXT_FIELDS,
    PersistenceContextError,
    build_persistence_context,
    translate_legacy_remediation_policy,
    validate_persistence_context,
)
from scripts.v3_target_contract import (
    V3ContractError,
    build_resolved_target,
)


ROOT = Path(
    __file__
).resolve().parents[1]

REAL_FIXTURE = (
    ROOT
    / "tests"
    / "fixtures"
    / "awx_aggregator_drift_realshape.json"
)


class V3CompliancePersistenceContextTests(
    unittest.TestCase
):

    def _run(self):
        payload = json.loads(
            REAL_FIXTURE.read_text()
        )

        return copy.deepcopy(
            payload[
                "artifacts"
            ][
                "compliance_run"
            ]
        )

    def _target(
        self,
        name="leaf01",
    ):
        return build_resolved_target(
            selector={
                "devices": [
                    name
                ]
            },
            devices=[
                {
                    "name":
                        name,

                    "platform":
                        "frr",

                    "vendor":
                        "FRRouting",

                    "site":
                        "syd01",

                    "role":
                        "leaf",

                    "tags": [
                        "production"
                    ],
                }
            ],
        )

    def test_legacy_policy_mapping_is_explicit(
        self,
    ):
        expected = {
            "auto":
                "auto",

            "approval_required":
                "approval_required",

            "manual":
                "manual",

            "report_only":
                "observe_only",
        }

        self.assertEqual(
            LEGACY_REMEDIATION_POLICY_MAP,
            expected,
        )

        for legacy, canonical in (
            expected.items()
        ):
            with self.subTest(
                legacy=legacy
            ):
                self.assertEqual(
                    translate_legacy_remediation_policy(
                        legacy
                    ),
                    canonical,
                )

    def test_v3_only_alias_is_not_accepted_as_legacy(
        self,
    ):
        with self.assertRaises(
            PersistenceContextError
        ):
            translate_legacy_remediation_policy(
                "automatic"
            )

    def test_build_real_aggregator_finding(
        self,
    ):
        context = build_persistence_context(
            compliance_run=self._run(),
            resolved_target=self._target(),
        )

        self.assertEqual(
            set(context),
            set(
                PERSISTENCE_CONTEXT_FIELDS
            ),
        )

        self.assertEqual(
            context["schema_version"],
            "3.0",
        )

        self.assertEqual(
            len(context["findings"]),
            1,
        )

        finding = context[
            "findings"
        ][0]

        self.assertEqual(
            tuple(finding),
            FINDING_FIELDS + (
                "expected",
            ),
        )

        self.assertEqual(
            finding["expected"],
            2,
        )

        self.assertNotIn(
            "actual",
            finding,
        )

        self.assertNotIn(
            "category",
            finding,
        )

        self.assertEqual(
            finding["finding_id"],
            "finding-c4773cf087b147948a8f",
        )

        self.assertEqual(
            finding["device"],
            "leaf01",
        )

        self.assertEqual(
            finding["vendor"],
            "FRRouting",
        )

        self.assertEqual(
            finding["platform"],
            "frr",
        )

        self.assertEqual(
            finding["control"],
            "maximum_paths",
        )

        self.assertEqual(
            finding["status"],
            "NON_COMPLIANT",
        )

        self.assertTrue(
            finding["remediable"]
        )

        self.assertEqual(
            finding["remediation_policy"],
            "auto",
        )

        self.assertFalse(
            finding["ticket_required"]
        )

    def test_both_noncompliant_spellings_are_accepted(
        self,
    ):
        for status in (
            "NON_COMPLIANT",
            "NON-COMPLIANT",
        ):
            with self.subTest(
                status=status
            ):
                run = self._run()

                run[
                    "findings"
                ][0][
                    "device_status"
                ] = status

                context = (
                    build_persistence_context(
                        compliance_run=run,
                        resolved_target=
                            self._target(),
                    )
                )

                self.assertEqual(
                    context[
                        "findings"
                    ][0][
                        "status"
                    ],
                    "NON_COMPLIANT",
                )

    def test_report_only_nonremediable_maps_to_observe_only(
        self,
    ):
        run = self._run()

        remediation = run[
            "findings"
        ][0][
            "remediation"
        ]

        remediation[
            "supported"
        ] = False

        remediation[
            "mode"
        ] = "report_only"

        context = build_persistence_context(
            compliance_run=run,
            resolved_target=self._target(),
        )

        finding = context[
            "findings"
        ][0]

        self.assertFalse(
            finding["remediable"]
        )

        self.assertEqual(
            finding["remediation_policy"],
            "observe_only",
        )

    def test_manual_nonremediable_remains_manual(
        self,
    ):
        run = self._run()

        remediation = run[
            "findings"
        ][0][
            "remediation"
        ]

        remediation[
            "supported"
        ] = False

        remediation[
            "mode"
        ] = "manual"

        context = build_persistence_context(
            compliance_run=run,
            resolved_target=self._target(),
        )

        self.assertEqual(
            context[
                "findings"
            ][0][
                "remediation_policy"
            ],
            "manual",
        )

    def test_auto_maximum_paths_requires_expected(
        self,
    ):
        run = self._run()

        finding = run[
            "findings"
        ][0]

        finding.pop(
            "expected"
        )

        with self.assertRaises(
            PersistenceContextError
        ):
            build_persistence_context(
                compliance_run=run,
                resolved_target=self._target(),
            )

    def test_validate_context_rejects_missing_auto_detail(
        self,
    ):
        context = build_persistence_context(
            compliance_run=self._run(),
            resolved_target=self._target(),
        )

        context[
            "findings"
        ][0].pop(
            "expected"
        )

        with self.assertRaises(
            PersistenceContextError
        ):
            validate_persistence_context(
                context
            )

    def test_bgp_neighbor_configuration_preserves_details(
        self,
    ):
        run = self._run()

        finding = run[
            "findings"
        ][0]

        finding[
            "control"
        ] = "bgp_neighbor_configuration"

        finding.pop(
            "expected",
            None,
        )

        finding[
            "neighbor"
        ] = "10.0.0.1"

        finding[
            "expected_remote_as"
        ] = 65101

        finding[
            "expected_description"
        ] = "LEAF01"

        context = build_persistence_context(
            compliance_run=run,
            resolved_target=self._target(),
        )

        persisted = context[
            "findings"
        ][0]

        self.assertEqual(
            tuple(persisted),
            FINDING_FIELDS + (
                "neighbor",
                "expected_remote_as",
                "expected_description",
            ),
        )

        self.assertEqual(
            persisted["neighbor"],
            "10.0.0.1",
        )

        self.assertEqual(
            persisted[
                "expected_remote_as"
            ],
            65101,
        )

        self.assertEqual(
            persisted[
                "expected_description"
            ],
            "LEAF01",
        )

        self.assertNotIn(
            "actual",
            persisted,
        )

    def test_auto_bgp_neighbor_requires_all_details(
        self,
    ):
        required = (
            "neighbor",
            "expected_remote_as",
            "expected_description",
        )

        for missing_field in required:
            with self.subTest(
                missing_field=missing_field
            ):
                run = self._run()

                finding = run[
                    "findings"
                ][0]

                finding[
                    "control"
                ] = (
                    "bgp_neighbor_configuration"
                )

                finding.pop(
                    "expected",
                    None,
                )

                finding.update({
                    "neighbor":
                        "10.0.0.1",
                    "expected_remote_as":
                        65101,
                    "expected_description":
                        "LEAF01",
                })

                finding.pop(
                    missing_field
                )

                with self.assertRaises(
                    PersistenceContextError
                ):
                    build_persistence_context(
                        compliance_run=run,
                        resolved_target=
                            self._target(),
                    )

    def test_target_missing_finding_device_is_rejected(
        self,
    ):
        with self.assertRaises(
            PersistenceContextError
        ):
            build_persistence_context(
                compliance_run=self._run(),
                resolved_target=
                    self._target(
                        "leaf02"
                    ),
            )

    def test_duplicate_finding_ids_are_rejected(
        self,
    ):
        run = self._run()

        run["findings"].append(
            copy.deepcopy(
                run["findings"][0]
            )
        )

        with self.assertRaises(
            PersistenceContextError
        ):
            build_persistence_context(
                compliance_run=run,
                resolved_target=self._target(),
            )

    def test_unsupported_legacy_run_schema_is_rejected(
        self,
    ):
        run = self._run()

        run[
            "schema_version"
        ] = "2.0"

        with self.assertRaises(
            PersistenceContextError
        ):
            build_persistence_context(
                compliance_run=run,
                resolved_target=self._target(),
            )

    def test_nonremediable_auto_is_rejected_by_v3_contract(
        self,
    ):
        run = self._run()

        run[
            "findings"
        ][0][
            "remediation"
        ][
            "supported"
        ] = False

        with self.assertRaises(
            V3ContractError
        ):
            build_persistence_context(
                compliance_run=run,
                resolved_target=self._target(),
            )

    def test_approval_required_requires_ticket(
        self,
    ):
        run = self._run()

        run[
            "findings"
        ][0][
            "remediation"
        ][
            "mode"
        ] = "approval_required"

        run[
            "findings"
        ][0][
            "ticket_required"
        ] = False

        with self.assertRaises(
            V3ContractError
        ):
            build_persistence_context(
                compliance_run=run,
                resolved_target=self._target(),
            )

    def test_source_vendor_conflict_is_rejected(
        self,
    ):
        run = self._run()

        run[
            "findings"
        ][0][
            "vendor"
        ] = "DifferentVendor"

        with self.assertRaises(
            PersistenceContextError
        ):
            build_persistence_context(
                compliance_run=run,
                resolved_target=self._target(),
            )

    def test_validate_context_rejects_tampered_target_identity(
        self,
    ):
        context = build_persistence_context(
            compliance_run=self._run(),
            resolved_target=self._target(),
        )

        context[
            "resolved_target"
        ][
            "target_id"
        ] = "target-tampered"

        with self.assertRaises(
            V3ContractError
        ):
            validate_persistence_context(
                context
            )

    def test_validate_context_rejects_extra_finding_field(
        self,
    ):
        context = build_persistence_context(
            compliance_run=self._run(),
            resolved_target=self._target(),
        )

        context[
            "findings"
        ][0][
            "unexpected"
        ] = True

        with self.assertRaises(
            PersistenceContextError
        ):
            validate_persistence_context(
                context
            )

    def test_context_is_independent_of_input_target_mutation(
        self,
    ):
        target = self._target()

        context = build_persistence_context(
            compliance_run=self._run(),
            resolved_target=target,
        )

        target[
            "devices"
        ][0][
            "vendor"
        ] = "TamperedVendor"

        self.assertEqual(
            context[
                "resolved_target"
            ][
                "devices"
            ][0][
                "vendor"
            ],
            "FRRouting",
        )


if __name__ == "__main__":
    unittest.main()
