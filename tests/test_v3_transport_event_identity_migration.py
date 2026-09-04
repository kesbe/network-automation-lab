#!/usr/bin/env python3

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

MIGRATION = (
    ROOT
    / "db"
    / "migrations"
    / "010_v3_transport_event_identity.sql"
)

SQL = MIGRATION.read_text()

V2_EVENT_TYPE = (
    "NETWORK_COMPLIANCE_DRIFT_DETECTED"
)

V3_EVENT_TYPE = (
    "NETWORK_COMPLIANCE_FINDING_ACTIVATED"
)

INDEX_NAME = (
    "idx_transport_events_v2_logical_event_unique"
)


class V3TransportEventIdentityMigrationTests(
    unittest.TestCase
):
    def test_migration_is_transactional(self):
        text = SQL.strip()

        self.assertTrue(
            text.startswith("--")
        )

        self.assertIn(
            "\nBEGIN;",
            text,
        )

        self.assertTrue(
            text.endswith("COMMIT;")
        )

    def test_global_logical_unique_constraint_is_removed(
        self,
    ):
        self.assertIn(
            "DROP CONSTRAINT "
            "transport_events_logical_event_unique",
            SQL,
        )

    def test_v2_partial_unique_index_exists(self):
        self.assertIn(
            "CREATE UNIQUE INDEX",
            SQL,
        )

        self.assertIn(
            INDEX_NAME,
            SQL,
        )

    def test_partial_index_preserves_v2_identity(
        self,
    ):
        match = re.search(
            r"CREATE\s+UNIQUE\s+INDEX\s+"
            + re.escape(INDEX_NAME)
            + r".*?;",
            SQL,
            flags=re.IGNORECASE | re.DOTALL,
        )

        self.assertIsNotNone(
            match
        )

        index_sql = match.group(0)

        self.assertRegex(
            index_sql,
            re.compile(
                r"ON\s+compliance\.transport_events"
                r"\s*\(\s*"
                r"event_type\s*,\s*"
                r"compliance_run_id\s*"
                r"\)",
                re.IGNORECASE | re.DOTALL,
            ),
        )

        self.assertRegex(
            index_sql,
            re.compile(
                r"WHERE\s+event_type\s*=\s*"
                r"'"
                + re.escape(V2_EVENT_TYPE)
                + r"'",
                re.IGNORECASE | re.DOTALL,
            ),
        )

    def test_v3_is_outside_v2_unique_boundary(
        self,
    ):
        match = re.search(
            r"CREATE\s+UNIQUE\s+INDEX\s+"
            + re.escape(INDEX_NAME)
            + r".*?;",
            SQL,
            flags=re.IGNORECASE | re.DOTALL,
        )

        self.assertIsNotNone(
            match
        )

        index_sql = match.group(0)

        self.assertNotIn(
            V3_EVENT_TYPE,
            index_sql,
        )

    def test_event_id_primary_key_is_not_removed(
        self,
    ):
        self.assertNotRegex(
            SQL,
            re.compile(
                r"DROP\s+CONSTRAINT\s+"
                r"[^\s;]*pkey",
                re.IGNORECASE,
            ),
        )

        self.assertNotIn(
            "DROP COLUMN event_id",
            SQL.upper(),
        )

    def test_claim_transport_event_is_not_redefined(
        self,
    ):
        self.assertNotRegex(
            SQL,
            re.compile(
                r"CREATE(?:\s+OR\s+REPLACE)?"
                r"\s+FUNCTION\s+"
                r"compliance\.claim_transport_event",
                re.IGNORECASE,
            ),
        )

    def test_no_second_transport_table_is_created(
        self,
    ):
        self.assertNotRegex(
            SQL,
            re.compile(
                r"CREATE\s+TABLE\s+"
                r"compliance\.",
                re.IGNORECASE,
            ),
        )


if __name__ == "__main__":
    unittest.main()
