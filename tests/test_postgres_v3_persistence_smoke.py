from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]

PLAYBOOK = (
    ROOT
    / "playbooks"
    / "postgres_v3_persistence_smoke.yml"
)


class TestPostgresV3PersistenceSmoke(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.text = PLAYBOOK.read_text()

    def test_uses_frozen_v3_persistence_context_adapter(self):
        self.assertIn(
            "scripts/v3_compliance_persistence_context.py",
            self.text,
        )

        self.assertIn(
            "'compliance_run': smoke_compliance_run",
            self.text,
        )

        self.assertIn(
            "'resolved_target': smoke_resolved_target",
            self.text,
        )

        self.assertIn(
            "changed_when: false",
            self.text,
        )

    def test_smoke_fixture_is_compliant_and_has_no_findings(self):
        self.assertIn(
            'schema_version: "1.0"',
            self.text,
        )

        self.assertIn(
            'run_id: "awx-v3-postgres-smoke"',
            self.text,
        )

        self.assertIn(
            "status: COMPLIANT",
            self.text,
        )

        self.assertRegex(
            self.text,
            r"(?m)^\s+findings:\s*\[\]\s*$",
        )

    def test_resolved_target_is_frozen_v3_leaf01_fixture(self):
        self.assertIn(
            'schema_version: "3.0"',
            self.text,
        )

        self.assertIn(
            'target_id: "target-4ca1ea939749e425b01cf1f448dec657"',
            self.text,
        )

        self.assertIn(
            "platform: frr",
            self.text,
        )

        self.assertIn(
            "vendor: generic",
            self.text,
        )

        self.assertIn(
            "site: network-lab",
            self.text,
        )

        self.assertIn(
            "role: leaf",
            self.text,
        )

    def test_checks_exact_v3_function_execute_privilege(self):
        self.assertIn(
            (
                "compliance.ingest_v3_compliance_run"
                "(jsonb,jsonb,bigint,bigint,bigint,text,text)"
            ),
            self.text,
        )

        self.assertIn(
            "v3_run_api_execute",
            self.text,
        )

    def test_calls_only_run_level_v3_ingestion_api(self):
        self.assertIn(
            "FROM compliance.ingest_v3_compliance_run(",
            self.text,
        )

        self.assertNotIn(
            "ingest_finding(",
            self.text,
        )

        self.assertNotRegex(
            self.text,
            r"(?i)\bINSERT\s+INTO\b",
        )

        self.assertNotRegex(
            self.text,
            r"(?i)\bUPDATE\s+[A-Za-z_]",
        )

        self.assertNotRegex(
            self.text,
            r"(?i)\bDELETE\s+FROM\b",
        )

    def test_v3_api_call_is_wrapped_in_begin_and_rollback(self):
        begin_pos = self.text.find(
            "- BEGIN"
        )

        call_pos = self.text.find(
            "FROM compliance.ingest_v3_compliance_run("
        )

        rollback_pos = self.text.find(
            "- ROLLBACK"
        )

        self.assertGreaterEqual(
            begin_pos,
            0,
        )

        self.assertGreater(
            call_pos,
            begin_pos,
        )

        self.assertGreater(
            rollback_pos,
            call_pos,
        )

    def test_database_query_is_no_log(self):
        query_task = re.search(
            (
                r"- name: Exercise V3 PostgreSQL writer API "
                r"and roll back"
                r".*?"
                r"register: postgres_v3_smoke"
                r"\s+no_log: true"
            ),
            self.text,
            re.DOTALL,
        )

        self.assertIsNotNone(
            query_task
        )

    def test_asserts_no_direct_table_access(self):
        required = (
            "direct_run_select",
            "direct_run_insert",
            "direct_v3_context_select",
            "direct_v3_context_insert",
            "direct_activation_source_select",
            "direct_activation_source_insert",
        )

        for field in required:
            self.assertIn(
                field,
                self.text,
            )

        self.assertIn(
            "not (postgres_v3_identity.direct_run_select | bool)",
            self.text,
        )

        self.assertIn(
            "not (postgres_v3_identity.direct_run_insert | bool)",
            self.text,
        )

    def test_asserts_compliant_v3_result_contract(self):
        required = (
            "result_status == 'INSERTED'",
            "device_results_inserted | int == 1",
            "findings_processed | int == 0",
            "detected_count | int == 0",
            "seen_again_count | int == 0",
            "reopened_count | int == 0",
            "duplicate_finding_count | int == 0",
            "activation_sources_inserted | int == 0",
        )

        for fragment in required:
            self.assertIn(
                fragment,
                self.text,
            )

    def test_asserts_rollback_completion(self):
        self.assertIn(
            "rollback_completed",
            self.text,
        )

        self.assertIn(
            (
                "postgres_v3_rollback_result."
                "rollback_completed | bool"
            ),
            self.text,
        )

    def test_has_no_kafka_or_transport_side_effects(self):
        lowered = self.text.lower()

        self.assertNotIn(
            "kafka_bootstrap",
            lowered,
        )

        self.assertNotIn(
            "transport_claim",
            lowered,
        )

        self.assertNotIn(
            "transport_complete",
            lowered,
        )

        self.assertNotIn(
            "transport_fail",
            lowered,
        )


if __name__ == "__main__":
    unittest.main()
