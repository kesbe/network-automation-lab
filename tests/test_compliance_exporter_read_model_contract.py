import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SQL = (
    ROOT
    / "db"
    / "migrations"
    / "009_compliance_exporter_read_model.sql"
).read_text()


class ComplianceExporterReadModelTests(
    unittest.TestCase
):

    def test_migration_is_transactional(self):
        self.assertIn(
            "BEGIN;",
            SQL,
        )
        self.assertIn(
            "COMMIT;",
            SQL,
        )

    def test_exporter_roles_are_nologin(self):
        self.assertIn(
            "CREATE ROLE compliance_exporter_owner",
            SQL,
        )
        self.assertIn(
            "CREATE ROLE compliance_exporter",
            SQL,
        )
        self.assertIn(
            "NOLOGIN",
            SQL,
        )

    def test_findings_summary_exists(self):
        self.assertIn(
            "exporter_findings_summary",
            SQL,
        )

    def test_remediation_summary_exists(self):
        self.assertIn(
            "exporter_remediation_summary",
            SQL,
        )

    def test_active_ticket_summary_exists(self):
        self.assertIn(
            "exporter_active_ticket_summary",
            SQL,
        )

    def test_overview_exists(self):
        self.assertIn(
            "exporter_overview",
            SQL,
        )

    def test_exporter_has_no_base_table_dml(self):
        for verb in (
            "INSERT ON",
            "UPDATE ON",
            "DELETE ON",
            "TRUNCATE ON",
        ):
            self.assertNotIn(
                verb,
                SQL,
            )

    def test_runtime_base_table_access_is_revoked(self):
        self.assertIn(
            "FROM compliance_exporter;",
            SQL,
        )

    def test_metrics_are_low_cardinality(self):
        prohibited = (
            "GROUP BY finding_id",
            "GROUP BY event_id",
            "GROUP BY target_id",
            "GROUP BY device",
            "GROUP BY external_ticket_id",
            "GROUP BY external_ticket_number",
            "GROUP BY workflow_job_id",
            "GROUP BY remediation_job_id",
            "GROUP BY recheck_job_id",
        )

        for item in prohibited:
            self.assertNotIn(
                item,
                SQL,
            )

    def test_active_ticket_view_excludes_closed(self):
        self.assertIn(
            "'RESOLVED'",
            SQL,
        )
        self.assertIn(
            "'CLOSED'",
            SQL,
        )


if __name__ == "__main__":
    unittest.main()
