import re
import unittest
from pathlib import Path


ROOT = Path(
    __file__
).resolve().parents[1]

MIGRATION = (
    ROOT
    / "db"
    / "migrations"
    / "011_v3_activation_source_durability.sql"
)

SQL = MIGRATION.read_text()


def normalized_sql():
    return re.sub(
        r"\s+",
        " ",
        SQL,
    ).strip()


class V3ActivationSourceMigrationTests(
    unittest.TestCase
):

    def test_migration_is_transactional(self):
        text = SQL.strip()

        self.assertTrue(
            text.startswith(
                "--"
            )
        )

        self.assertRegex(
            text,
            r"(?m)^BEGIN;\s*$",
        )

        self.assertRegex(
            text,
            r"(?m)^COMMIT;\s*$",
        )

    def test_activation_source_table_exists(self):
        self.assertIn(
            "CREATE TABLE "
            "compliance.v3_activation_sources",
            normalized_sql(),
        )

    def test_finding_event_is_primary_identity(self):
        text = normalized_sql()

        self.assertRegex(
            text,
            r"finding_event_id\s+BIGINT\s+"
            r"PRIMARY KEY",
        )

    def test_lifecycle_metadata_is_bound_to_event(
        self,
    ):
        text = normalized_sql()

        self.assertRegex(
            text,
            r"UNIQUE\s*\(\s*"
            r"event_id\s*,\s*"
            r"run_id\s*,\s*"
            r"finding_id\s*,\s*"
            r"event_type\s*,\s*"
            r"event_time\s*"
            r"\)",
        )

        self.assertRegex(
            text,
            r"FOREIGN KEY\s*\(\s*"
            r"finding_event_id\s*,\s*"
            r"run_id\s*,\s*"
            r"finding_id\s*,\s*"
            r"lifecycle_event_type\s*,\s*"
            r"activated_at\s*"
            r"\)\s*"
            r"REFERENCES\s+"
            r"compliance\.finding_events\s*"
            r"\(\s*"
            r"event_id\s*,\s*"
            r"run_id\s*,\s*"
            r"finding_id\s*,\s*"
            r"event_type\s*,\s*"
            r"event_time\s*"
            r"\)",
        )

    def test_only_activation_lifecycles_allowed(
        self,
    ):
        text = normalized_sql()

        match = re.search(
            r"CONSTRAINT\s+"
            r"v3_activation_lifecycle\s+"
            r"CHECK\s*\((.*?)\)",
            text,
        )

        self.assertIsNotNone(
            match
        )

        boundary = match.group(
            1
        )

        self.assertIn(
            "'DETECTED'",
            boundary,
        )

        self.assertIn(
            "'REOPENED'",
            boundary,
        )

        self.assertNotIn(
            "'SEEN_AGAIN'",
            boundary,
        )

        self.assertNotIn(
            "'DUPLICATE'",
            boundary,
        )

    def test_canonical_finding_snapshot_is_required(
        self,
    ):
        text = normalized_sql()

        self.assertRegex(
            text,
            r"finding_snapshot\s+JSONB\s+"
            r"NOT NULL",
        )

        for field in (
            "finding_id",
            "device",
            "vendor",
            "platform",
            "control",
            "severity",
            "status",
            "remediable",
            "remediation_policy",
            "ticket_required",
        ):
            self.assertIn(
                f"'{field}'",
                text,
            )

        self.assertRegex(
            text,
            r"finding_snapshot->>'finding_id'"
            r"\s*=\s*finding_id",
        )

        self.assertRegex(
            text,
            r"finding_snapshot->>'status'"
            r"\s*=\s*'NON_COMPLIANT'",
        )

    def test_resolved_target_snapshot_is_required(
        self,
    ):
        text = normalized_sql()

        self.assertRegex(
            text,
            r"resolved_target\s+JSONB\s+"
            r"NOT NULL",
        )

        for field in (
            "target_id",
            "selector",
            "devices",
            "device_count",
        ):
            self.assertIn(
                f"'{field}'",
                text,
            )

        self.assertRegex(
            text,
            r"resolved_target->>'target_id'"
            r"\s+LIKE\s+'target-%'",
        )

    def test_activation_timestamp_is_durable(
        self,
    ):
        self.assertRegex(
            normalized_sql(),
            r"activated_at\s+TIMESTAMPTZ\s+"
            r"NOT NULL",
        )

    def test_existing_ingestion_and_transport_are_not_redefined(
        self,
    ):
        upper = SQL.upper()

        self.assertNotIn(
            "CREATE FUNCTION",
            upper,
        )

        self.assertNotIn(
            "CREATE OR REPLACE FUNCTION",
            upper,
        )

        self.assertNotIn(
            "ALTER TABLE "
            "COMPLIANCE.TRANSPORT_EVENTS",
            upper,
        )

        self.assertNotIn(
            "CREATE TABLE "
            "COMPLIANCE.TRANSPORT_EVENTS",
            upper,
        )


if __name__ == "__main__":
    unittest.main()
