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
    / "012_v3_transactional_run_ingestion.sql"
)


class V3TransactionalRunIngestionMigrationTests(
    unittest.TestCase
):

    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text()
        cls.upper = cls.sql.upper()

    def test_migration_is_transactional(
        self,
    ):
        stripped = self.sql.strip()

        self.assertTrue(
            stripped.startswith("BEGIN;")
        )

        self.assertTrue(
            stripped.endswith("COMMIT;")
        )

    def test_run_context_table_is_created(
        self,
    ):
        self.assertIn(
            "CREATE TABLE "
            "compliance.v3_run_persistence_contexts",
            self.sql,
        )

        self.assertRegex(
            self.sql,
            r"run_id\s+TEXT\s+PRIMARY KEY",
        )

        self.assertRegex(
            self.sql,
            r"persistence_context\s+JSONB\s+NOT NULL",
        )

        self.assertIn(
            "REFERENCES "
            "compliance.compliance_runs(run_id)",
            self.sql,
        )

    def test_run_context_binds_v3_identity(
        self,
    ):
        self.assertIn(
            "persistence_context->>'schema_version' = '3.0'",
            self.sql,
        )

        self.assertIn(
            "persistence_context->>'compliance_run_id'",
            self.sql,
        )

        self.assertIn(
            "jsonb_typeof("
            "persistence_context->'resolved_target'"
            ")='object'",
            re.sub(
                r"\s+",
                "",
                self.sql,
            ),
        )

    def test_v3_run_level_function_exists(
        self,
    ):
        self.assertRegex(
            self.sql,
            r"CREATE OR REPLACE FUNCTION\s+"
            r"compliance\.ingest_v3_compliance_run\s*\(\s*"
            r"p_compliance_run\s+JSONB\s*,\s*"
            r"p_persistence_context\s+JSONB",
        )

        self.assertIn(
            "activation_sources_inserted INTEGER",
            self.sql,
        )

    def test_wrapper_uses_existing_run_level_api_only(
        self,
    ):
        function_start = self.sql.index(
            "CREATE OR REPLACE FUNCTION "
            "compliance.ingest_v3_compliance_run"
        )

        function_end = self.sql.index(
            "COMMENT ON FUNCTION "
            "compliance.ingest_v3_compliance_run",
            function_start,
        )

        body = self.sql[
            function_start:
            function_end
        ]

        self.assertIn(
            "FROM compliance.ingest_compliance_run(",
            body,
        )

        self.assertNotIn(
            "FROM compliance.ingest_finding(",
            body,
        )

    def test_legacy_and_v3_finding_sets_are_exact(
        self,
    ):
        self.assertIn(
            "compliance_run contains duplicate finding_id",
            self.sql,
        )

        self.assertIn(
            "persistence_context contains duplicate finding_id",
            self.sql,
        )

        self.assertIn(
            "legacy/V3 persistence finding "
            "identity set mismatch",
            self.sql,
        )

        self.assertGreaterEqual(
            self.upper.count("EXCEPT"),
            2,
        )

    def test_seen_again_is_not_an_activation_source(
        self,
    ):
        self.assertGreaterEqual(
            self.sql.count(
                "event_type IN (\n"
                "                'DETECTED',\n"
                "                'REOPENED'"
            ),
            1,
        )

        insert_start = self.sql.index(
            "INSERT INTO "
            "compliance.v3_activation_sources"
        )

        insert_end = self.sql.index(
            "GET DIAGNOSTICS",
            insert_start,
        )

        insert_sql = self.sql[
            insert_start:
            insert_end
        ]

        self.assertIn(
            "'DETECTED'",
            insert_sql,
        )

        self.assertIn(
            "'REOPENED'",
            insert_sql,
        )

        self.assertNotIn(
            "'SEEN_AGAIN'",
            insert_sql,
        )

    def test_lifecycle_counts_are_verified(
        self,
    ):
        self.assertIn(
            "v_ingest_result.detected_count",
            self.sql,
        )

        self.assertIn(
            "v_ingest_result.reopened_count",
            self.sql,
        )

        self.assertIn(
            "DETECTED lifecycle count mismatch",
            self.sql,
        )

        self.assertIn(
            "REOPENED lifecycle count mismatch",
            self.sql,
        )

    def test_activation_cardinality_fails_closed(
        self,
    ):
        self.assertRegex(
            self.sql,
            r"GROUP BY\s+"
            r"finding_id\s+"
            r"HAVING\s+"
            r"count\(\*\)\s*<>\s*1",
        )

        self.assertIn(
            "multiple activation lifecycle events "
            "exist for one run/finding",
            self.sql,
        )

    def test_fresh_run_persists_whole_context(
        self,
    ):
        self.assertIn(
            "INSERT INTO "
            "compliance.v3_run_persistence_contexts",
            self.sql,
        )

        self.assertIn(
            "p_persistence_context",
            self.sql,
        )

    def test_activation_source_uses_durable_event_identity(
        self,
    ):
        self.assertIn(
            "lifecycle_event.event_id",
            self.sql,
        )

        self.assertIn(
            "lifecycle_event.run_id",
            self.sql,
        )

        self.assertIn(
            "lifecycle_event.finding_id",
            self.sql,
        )

        self.assertIn(
            "lifecycle_event.event_type",
            self.sql,
        )

        self.assertIn(
            "lifecycle_event.event_time",
            self.sql,
        )

        self.assertIn(
            "context_finding.finding",
            self.sql,
        )

        self.assertIn(
            "p_persistence_context->'resolved_target'",
            self.sql,
        )

    def test_duplicate_requires_existing_v3_context(
        self,
    ):
        self.assertIn(
            "has no transactional V3 "
            "persistence context",
            self.sql,
        )

        self.assertIn(
            "v_existing_context IS DISTINCT FROM",
            self.sql,
        )

        self.assertIn(
            "V3 persistence context identity "
            "collision for run_id",
            self.sql,
        )

    def test_duplicate_verifies_activation_sources(
        self,
    ):
        self.assertIn(
            "stored V3 activation-source count mismatch",
            self.sql,
        )

        self.assertIn(
            "source.finding_snapshot IS DISTINCT FROM",
            self.sql,
        )

        self.assertIn(
            "source.resolved_target IS DISTINCT FROM",
            self.sql,
        )

        self.assertIn(
            "stored V3 activation source does not "
            "match immutable retry context",
            self.sql,
        )

    def test_security_boundary_is_explicit(
        self,
    ):
        self.assertIn(
            "OWNER TO compliance_api_owner",
            self.sql,
        )

        self.assertIn(
            "SECURITY DEFINER",
            self.sql,
        )

        self.assertIn(
            "SET search_path = pg_catalog, compliance",
            self.sql,
        )

        self.assertRegex(
            self.sql,
            r"GRANT EXECUTE ON FUNCTION\s+"
            r"compliance\.ingest_v3_compliance_run",
        )

        self.assertIn(
            ") TO compliance_ingest;",
            self.sql,
        )

        self.assertRegex(
            self.sql,
            r"REVOKE EXECUTE ON FUNCTION\s+"
            r"compliance\.ingest_v3_compliance_run",
        )

    def test_v3_tables_are_not_directly_exposed(
        self,
    ):
        self.assertIn(
            "ON TABLE "
            "compliance.v3_run_persistence_contexts\n"
            "    FROM compliance_ingest",
            self.sql,
        )

        self.assertIn(
            "ON TABLE "
            "compliance.v3_activation_sources\n"
            "    FROM compliance_ingest",
            self.sql,
        )

        self.assertIn(
            "GRANT SELECT, INSERT\n"
            "    ON TABLE "
            "compliance.v3_run_persistence_contexts\n"
            "    TO compliance_api_owner",
            self.sql,
        )

        self.assertIn(
            "GRANT SELECT, INSERT\n"
            "    ON TABLE "
            "compliance.v3_activation_sources\n"
            "    TO compliance_api_owner",
            self.sql,
        )

    def test_existing_lifecycle_and_run_apis_are_not_redefined(
        self,
    ):
        self.assertNotRegex(
            self.sql,
            r"CREATE OR REPLACE FUNCTION\s+"
            r"compliance\.ingest_finding\s*\(",
        )

        self.assertNotRegex(
            self.sql,
            r"CREATE OR REPLACE FUNCTION\s+"
            r"compliance\.ingest_compliance_run\s*\(",
        )

        self.assertNotRegex(
            self.sql,
            r"ALTER TABLE\s+"
            r"compliance\.finding_events",
        )


    def test_duplicate_context_read_preserves_immutable_privileges(
        self,
    ):
        normalized = re.sub(
            r"\s+",
            " ",
            self.sql,
        )

        self.assertIn(
            "SELECT persistence_context "
            "INTO v_existing_context "
            "FROM compliance.v3_run_persistence_contexts "
            "WHERE run_id = v_run_id;",
            normalized,
        )

        self.assertNotIn(
            "SELECT persistence_context "
            "INTO v_existing_context "
            "FROM compliance.v3_run_persistence_contexts "
            "WHERE run_id = v_run_id "
            "FOR UPDATE;",
            normalized,
        )

        self.assertNotRegex(
            self.sql,
            r"GRANT\s+[^;]*UPDATE[^;]*"
            r"v3_run_persistence_contexts",
        )


if __name__ == "__main__":
    unittest.main()
