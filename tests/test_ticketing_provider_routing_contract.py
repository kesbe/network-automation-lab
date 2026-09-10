import ast
import unittest
from pathlib import Path

from scripts.ticketing_runtime_common import (
    RuntimeContractError,
    normalize_event_row,
)


ROOT = Path(__file__).resolve().parents[1]

COMMON = (
    ROOT
    / "scripts"
    / "ticketing_runtime_common.py"
)

SN_ADAPTER = (
    ROOT
    / "scripts"
    / "servicenow_ticketing_adapter.py"
)

ZAMMAD_ADAPTER = (
    ROOT
    / "scripts"
    / "zammad_ticketing_adapter.py"
)

PUBLISHER = (
    ROOT
    / "scripts"
    / "ticketing_lifecycle_publisher.py"
)

MIGRATION = (
    ROOT
    / "db"
    / "migrations"
    / "019_ticketing_provider_routing.sql"
)


def function_source(
    path: Path,
    name: str,
) -> str:
    text = path.read_text(
        encoding="utf-8"
    )

    tree = ast.parse(text)

    matches = [
        node
        for node in ast.walk(tree)
        if (
            isinstance(
                node,
                ast.FunctionDef,
            )
            and node.name == name
        )
    ]

    if len(matches) != 1:
        raise AssertionError(
            f"{path}: {name} count="
            f"{len(matches)}"
        )

    return (
        ast.get_source_segment(
            text,
            matches[0],
        )
        or ""
    )


def base_event(
    targets=None,
    ticket_required=True,
):
    details = {}

    if targets is not None:
        details[
            "target_providers"
        ] = targets

    return {
        "source_event_id": 901,
        "source_finding_id":
            "provider-routing-test",

        "run_id":
            "provider-routing-run",

        "lifecycle_event_type":
            "DETECTED",

        "event_details":
            details,

        "finding_snapshot": {
            "ticket_required":
                ticket_required,
        },
    }


class ProviderRoutingContractTests(
    unittest.TestCase
):

    def test_legacy_non_ticket_event_can_lack_targets(
        self,
    ):
        event = normalize_event_row(
            base_event(
                targets=None,
                ticket_required=False,
            )
        )

        self.assertEqual(
            event["target_providers"],
            [],
        )

    def test_ticket_event_requires_targets(
        self,
    ):
        with self.assertRaises(
            RuntimeContractError
        ):
            normalize_event_row(
                base_event(
                    targets=None,
                    ticket_required=True,
                )
            )

    def test_empty_targets_are_rejected(
        self,
    ):
        with self.assertRaises(
            RuntimeContractError
        ):
            normalize_event_row(
                base_event([])
            )

    def test_unknown_provider_is_rejected(
        self,
    ):
        with self.assertRaises(
            RuntimeContractError
        ):
            normalize_event_row(
                base_event(
                    ["unknown-provider"]
                )
            )

    def test_duplicate_provider_is_rejected(
        self,
    ):
        with self.assertRaises(
            RuntimeContractError
        ):
            normalize_event_row(
                base_event(
                    [
                        "servicenow",
                        "ServiceNow",
                    ]
                )
            )

    def test_targets_are_canonicalized(
        self,
    ):
        event = normalize_event_row(
            base_event(
                [
                    "ZAMMAD",
                    "servicenow",
                ]
            )
        )

        expected = [
            "servicenow",
            "zammad",
        ]

        self.assertEqual(
            event["target_providers"],
            expected,
        )

        self.assertEqual(
            event[
                "event_details"
            ][
                "target_providers"
            ],
            expected,
        )

    def test_servicenow_filter_precedes_receipt_claim(
        self,
    ):
        source = function_source(
            SN_ADAPTER,
            "process_event",
        )

        normalize = source.find(
            "normalize_event_row"
        )

        skip = source.find(
            "SKIPPED_NOT_TARGETED"
        )

        claim = source.find(
            "repository.claim"
        )

        self.assertGreaterEqual(
            normalize,
            0,
        )

        self.assertGreater(
            skip,
            normalize,
        )

        self.assertGreater(
            claim,
            skip,
        )

        self.assertIn(
            '"servicenow"',
            source,
        )

    def test_zammad_filter_precedes_receipt_claim(
        self,
    ):
        source = function_source(
            ZAMMAD_ADAPTER,
            "process_event",
        )

        normalize = source.find(
            "normalize_event_row"
        )

        skip = source.find(
            "SKIPPED_NOT_TARGETED"
        )

        claim = source.find(
            "repository.claim"
        )

        self.assertGreaterEqual(
            normalize,
            0,
        )

        self.assertGreater(
            skip,
            normalize,
        )

        self.assertGreater(
            claim,
            skip,
        )

        self.assertIn(
            '"zammad"',
            source,
        )

    def test_non_target_terminal_result_commits(
        self,
    ):
        for path in (
            SN_ADAPTER,
            ZAMMAD_ADAPTER,
        ):
            source = function_source(
                path,
                "process_message",
            )

            self.assertIn(
                '"SKIPPED_NOT_TARGETED"',
                source,
            )

            self.assertIn(
                ".commit(",
                source,
            )

    def test_publisher_handles_already_skipped(
        self,
    ):
        process = function_source(
            PUBLISHER,
            "process_event",
        )

        run_once = function_source(
            PUBLISHER,
            "run_once",
        )

        skip = process.find(
            'disposition == "SKIPPED"'
        )

        publish = process.find(
            "self.transport.publish"
        )

        self.assertGreaterEqual(
            skip,
            0,
        )

        self.assertGreater(
            publish,
            skip,
        )

        self.assertIn(
            '"ALREADY_SKIPPED"',
            process,
        )

        self.assertIn(
            '"already_skipped"',
            run_once,
        )

    def test_migration_has_skipped_terminal_contract(
        self,
    ):
        sql = MIGRATION.read_text(
            encoding="utf-8"
        )

        required = (
            "ALTER COLUMN claimed_at DROP NOT NULL",
            "ADD COLUMN skipped_at TIMESTAMPTZ",
            "'SKIPPED'",
            "'ALREADY_SKIPPED'",
            "attempt_count = 0",
            "pub.state NOT IN ('COMPLETED', 'SKIPPED')",
            "PRE_ROUTING_CONTRACT_ZAMMAD_E2E_LINEAGE_FROZEN",
        )

        for token in required:
            self.assertIn(
                token,
                sql,
            )

    def test_migration_routes_ingest_and_resolution(
        self,
    ):
        sql = MIGRATION.read_text(
            encoding="utf-8"
        )

        self.assertIn(
            "ticket-required finding requires target_providers",
            sql,
        )

        self.assertIn(
            "'target_providers'",
            sql,
        )

        self.assertIn(
            "FROM compliance.ticket_records",
            sql,
        )

        self.assertIn(
            "NO_EXISTING_PROVIDER_TICKET_ON_RESOLUTION",
            sql,
        )

        self.assertIn(
            "event_id = 21",
            sql,
        )


if __name__ == "__main__":
    unittest.main()
