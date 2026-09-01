#!/usr/bin/env python3

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

MIGRATION = (
    ROOT
    / "db"
    / "migrations"
    / "013_v3_activation_source_reader.sql"
)

SQL = MIGRATION.read_text()


class V3ActivationSourceReaderMigrationTests(
    unittest.TestCase
):

    def test_migration_is_transactional(self):
        text = SQL.strip()

        self.assertRegex(
            text,
            r"(?m)^BEGIN;\s*$",
        )

        self.assertRegex(
            text,
            r"(?m)^COMMIT;\s*$",
        )

    def test_run_finding_identity_is_unique(self):
        self.assertRegex(
            SQL,
            re.compile(
                r"ADD\s+CONSTRAINT\s+"
                r"v3_activation_sources_run_finding_unique"
                r"\s+UNIQUE\s*\(\s*"
                r"run_id\s*,\s*finding_id\s*\)",
                re.IGNORECASE | re.DOTALL,
            ),
        )

    def test_reader_has_two_argument_identity(self):
        self.assertRegex(
            SQL,
            re.compile(
                r"CREATE\s+FUNCTION\s+"
                r"compliance\.read_v3_activation_source"
                r"\s*\(\s*"
                r"p_run_id\s+TEXT\s*,\s*"
                r"p_finding_id\s+TEXT\s*\)",
                re.IGNORECASE | re.DOTALL,
            ),
        )

    def test_reader_returns_typed_source_fields(self):
        for field in (
            "finding_event_id      BIGINT",
            "run_id                TEXT",
            "finding_id            TEXT",
            "lifecycle_event_type  TEXT",
            "activated_at          TIMESTAMPTZ",
            "finding_snapshot      JSONB",
            "resolved_target       JSONB",
        ):
            self.assertIn(
                field,
                SQL,
            )

    def test_empty_identity_fails_closed(self):
        self.assertIn(
            "run_id must not be empty",
            SQL,
        )

        self.assertIn(
            "finding_id must not be empty",
            SQL,
        )

        self.assertGreaterEqual(
            SQL.count("ERRCODE = '22023'"),
            2,
        )

    def test_absent_source_fails_closed(self):
        self.assertIn(
            "V3 activation source not found",
            SQL,
        )

        self.assertIn(
            "ERRCODE = 'P0002'",
            SQL,
        )

    def test_reader_uses_exact_unique_predicate(self):
        normalized = re.sub(
            r"\s+",
            " ",
            SQL,
        )

        self.assertIn(
            "source.run_id = v_run_id "
            "AND source.finding_id = v_finding_id",
            normalized,
        )

    def test_reader_returns_stored_snapshots(self):
        self.assertIn(
            "v_source.finding_snapshot",
            SQL,
        )

        self.assertIn(
            "v_source.resolved_target",
            SQL,
        )

    def test_security_definer_boundary(self):
        self.assertIn(
            "OWNER TO compliance_api_owner",
            SQL,
        )

        self.assertIn(
            "SECURITY DEFINER",
            SQL,
        )

        self.assertIn(
            "SET search_path = pg_catalog, compliance",
            SQL,
        )

    def test_public_execute_is_revoked(self):
        self.assertRegex(
            SQL,
            re.compile(
                r"REVOKE\s+EXECUTE\s+ON\s+FUNCTION\s+"
                r"compliance\.read_v3_activation_source"
                r"\s*\(\s*TEXT\s*,\s*TEXT\s*\)"
                r"\s+FROM\s+PUBLIC",
                re.IGNORECASE | re.DOTALL,
            ),
        )

    def test_ingest_role_receives_execute_only(self):
        self.assertRegex(
            SQL,
            re.compile(
                r"GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+"
                r"compliance\.read_v3_activation_source"
                r"\s*\(\s*TEXT\s*,\s*TEXT\s*\)"
                r"\s+TO\s+compliance_ingest",
                re.IGNORECASE | re.DOTALL,
            ),
        )

        self.assertNotRegex(
            SQL,
            re.compile(
                r"GRANT\s+SELECT\s+ON"
                r".*v3_activation_sources"
                r".*TO\s+compliance_ingest",
                re.IGNORECASE | re.DOTALL,
            ),
        )

    def test_existing_v3_apis_are_not_redefined(self):
        self.assertNotIn(
            "CREATE FUNCTION compliance.ingest_v3_compliance_run",
            SQL,
        )

        self.assertNotIn(
            "CREATE OR REPLACE FUNCTION "
            "compliance.ingest_v3_compliance_run",
            SQL,
        )

        self.assertNotIn(
            "CREATE FUNCTION compliance.claim_transport_event",
            SQL,
        )


if __name__ == "__main__":
    unittest.main()
