#!/usr/bin/env python3

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

MIGRATION = (
    ROOT
    / "db"
    / "migrations"
    / "014_v3_activation_sources_for_run_reader.sql"
)

SQL = MIGRATION.read_text()


class V3ActivationSourcesForRunReaderMigrationTests(
    unittest.TestCase
):

    def test_migration_is_transactional(self):
        text = SQL.strip()

        self.assertTrue(
            text.startswith("BEGIN;")
        )

        self.assertTrue(
            text.endswith("COMMIT;")
        )

    def test_reader_has_run_only_identity(self):
        self.assertRegex(
            SQL,
            re.compile(
                r"""
                CREATE\s+FUNCTION\s+
                compliance\.read_v3_activation_sources_for_run
                \s*\(
                \s*p_run_id\s+TEXT\s*
                \)
                """,
                re.IGNORECASE | re.VERBOSE,
            ),
        )

        self.assertNotIn(
            "p_finding_id",
            SQL,
        )

    def test_reader_returns_typed_source_fields(self):
        required = [
            "finding_event_id      BIGINT",
            "run_id                TEXT",
            "finding_id            TEXT",
            "lifecycle_event_type  TEXT",
            "activated_at          TIMESTAMPTZ",
            "finding_snapshot      JSONB",
            "resolved_target       JSONB",
        ]

        for field in required:
            self.assertIn(
                field,
                SQL,
            )

    def test_empty_run_identity_fails_closed(self):
        self.assertIn(
            "IF v_run_id = '' THEN",
            SQL,
        )

        self.assertIn(
            "ERRCODE = '22023'",
            SQL,
        )

    def test_unknown_run_fails_closed(self):
        self.assertIn(
            "compliance.v3_run_persistence_contexts",
            SQL,
        )

        self.assertRegex(
            SQL,
            re.compile(
                r"""
                run_context\.run_id
                \s*=\s*
                v_run_id
                """,
                re.IGNORECASE | re.VERBOSE,
            ),
        )

        self.assertIn(
            "ERRCODE = 'P0002'",
            SQL,
        )

        self.assertIn(
            "V3 persistence context not found",
            SQL,
        )

    def test_zero_activation_run_can_return_empty(self):
        self.assertIn(
            "RETURN QUERY",
            SQL,
        )

        self.assertNotIn(
            "IF NOT FOUND",
            SQL,
        )

    def test_reader_selects_only_run_activations(self):
        self.assertRegex(
            SQL,
            re.compile(
                r"""
                FROM\s+
                compliance\.v3_activation_sources
                \s+AS\s+source
                .*?
                WHERE\s+
                source\.run_id
                \s*=\s*
                v_run_id
                """,
                re.IGNORECASE
                | re.DOTALL
                | re.VERBOSE,
            ),
        )

    def test_reader_order_is_deterministic(self):
        self.assertRegex(
            SQL,
            re.compile(
                r"""
                ORDER\s+BY\s+
                source\.finding_event_id
                \s+ASC
                """,
                re.IGNORECASE | re.VERBOSE,
            ),
        )

    def test_reader_returns_stored_snapshots(self):
        self.assertIn(
            "source.finding_snapshot",
            SQL,
        )

        self.assertIn(
            "source.resolved_target",
            SQL,
        )

    def test_reader_is_read_only(self):
        forbidden = [
            r"\bINSERT\s+INTO\b",
            r"\bUPDATE\s+compliance\.",
            r"\bDELETE\s+FROM\b",
            r"\bTRUNCATE\b",
        ]

        for pattern in forbidden:
            self.assertNotRegex(
                SQL,
                re.compile(
                    pattern,
                    re.IGNORECASE,
                ),
            )

    def test_security_definer_boundary(self):
        self.assertRegex(
            SQL,
            re.compile(
                r"""
                ALTER\s+FUNCTION\s+
                compliance\.read_v3_activation_sources_for_run
                \s*\(\s*TEXT\s*\)
                \s*
                OWNER\s+TO\s+
                compliance_api_owner
                """,
                re.IGNORECASE | re.VERBOSE,
            ),
        )

        self.assertRegex(
            SQL,
            re.compile(
                r"""
                ALTER\s+FUNCTION\s+
                compliance\.read_v3_activation_sources_for_run
                \s*\(\s*TEXT\s*\)
                \s*
                SECURITY\s+DEFINER
                """,
                re.IGNORECASE | re.VERBOSE,
            ),
        )

        self.assertIn(
            "SET search_path = pg_catalog, compliance",
            SQL,
        )

    def test_public_execute_is_revoked(self):
        self.assertRegex(
            SQL,
            re.compile(
                r"""
                REVOKE\s+EXECUTE\s+ON\s+FUNCTION
                \s+
                compliance\.read_v3_activation_sources_for_run
                \s*\(\s*TEXT\s*\)
                \s+
                FROM\s+PUBLIC
                """,
                re.IGNORECASE | re.VERBOSE,
            ),
        )

    def test_ingest_role_receives_execute_only(self):
        self.assertRegex(
            SQL,
            re.compile(
                r"""
                GRANT\s+EXECUTE\s+ON\s+FUNCTION
                \s+
                compliance\.read_v3_activation_sources_for_run
                \s*\(\s*TEXT\s*\)
                \s+
                TO\s+compliance_ingest
                """,
                re.IGNORECASE | re.VERBOSE,
            ),
        )

        self.assertNotRegex(
            SQL,
            re.compile(
                r"""
                GRANT\s+
                (SELECT|INSERT|UPDATE|DELETE)
                .*?
                TO\s+
                (compliance_ingest|compliance_writer)
                """,
                re.IGNORECASE
                | re.DOTALL
                | re.VERBOSE,
            ),
        )

    def test_existing_v3_apis_are_not_redefined(self):
        self.assertNotRegex(
            SQL,
            re.compile(
                r"""
                CREATE(?:\s+OR\s+REPLACE)?\s+FUNCTION
                \s+
                compliance\.ingest_v3_compliance_run
                """,
                re.IGNORECASE | re.VERBOSE,
            ),
        )

        self.assertNotRegex(
            SQL,
            re.compile(
                r"""
                CREATE(?:\s+OR\s+REPLACE)?\s+FUNCTION
                \s+
                compliance\.read_v3_activation_source
                \s*\(
                """,
                re.IGNORECASE | re.VERBOSE,
            ),
        )

    def test_no_storage_schema_is_modified(self):
        forbidden = [
            r"\bCREATE\s+TABLE\b",
            r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\b",
            r"\bALTER\s+TABLE\b",
            r"\bADD\s+CONSTRAINT\b",
        ]

        for pattern in forbidden:
            self.assertNotRegex(
                SQL,
                re.compile(
                    pattern,
                    re.IGNORECASE,
                ),
            )


if __name__ == "__main__":
    unittest.main()
