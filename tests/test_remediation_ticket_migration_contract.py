from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]

MIGRATION = (
    ROOT
    / "db/migrations"
    / "008_remediation_ticket_lifecycle.sql"
)

SQL = MIGRATION.read_text()


class RemediationTicketMigrationContractTests(
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

    def test_remediation_table_exists(self):
        self.assertIn(
            "CREATE TABLE compliance.remediation_attempts",
            SQL,
        )

    def test_ticket_table_exists(self):
        self.assertIn(
            "CREATE TABLE compliance.ticket_records",
            SQL,
        )

    def test_ticket_active_dedup_exists(self):
        self.assertIn(
            "CREATE UNIQUE INDEX "
            "idx_ticket_one_active_per_finding",
            SQL,
        )

        self.assertIn(
            "ticket_state NOT IN",
            SQL,
        )

    def test_remediation_attempt_idempotency_exists(self):
        self.assertIn(
            "ON CONFLICT (remediation_attempt_id)",
            SQL,
        )

        self.assertIn(
            "'duplicate'",
            SQL,
        )

    def test_finding_device_correlation_enforced(self):
        self.assertIn(
            "remediation device mismatch",
            SQL,
        )

        self.assertIn(
            "remediation control mismatch",
            SQL,
        )

    def test_approval_required_has_explicit_gate(self):
        self.assertIn(
            "'WAITING_FOR_APPROVAL'",
            SQL,
        )

        self.assertIn(
            "record_remediation_approval",
            SQL,
        )

        self.assertIn(
            "'APPROVED'",
            SQL,
        )

        self.assertIn(
            "'REJECTED'",
            SQL,
        )

    def test_failure_classification_exists(self):
        for value in (
            "TRANSIENT",
            "CONFIGURATION",
            "AUTHENTICATION",
            "SAFETY",
            "UNKNOWN",
        ):
            self.assertIn(
                f"'{value}'",
                SQL,
            )

    def test_remediation_does_not_directly_resolve_finding(self):
        # The transition API may move OPEN -> REMEDIATING
        # and failures back to OPEN, but it must never SET
        # compliance_findings.status to RESOLVED.
        transition = SQL.split(
            "CREATE FUNCTION "
            "compliance.transition_remediation_attempt",
            1,
        )[1].split(
            "-- ============================================================================",
            1,
        )[0]

        self.assertNotRegex(
            transition,
            re.compile(
                r"status\s*=\s*'RESOLVED'",
                re.IGNORECASE,
            ),
        )

    def test_terminal_recheck_state_requires_recheck_job(self):
        self.assertIn(
            "'COMPLETED',",
            SQL,
        )

        self.assertIn(
            "'RECHECK_FAILED'",
            SQL,
        )

        self.assertIn(
            "p_recheck_job_id IS NULL",
            SQL,
        )

        self.assertIn(
            "v_row.recheck_job_id IS NULL",
            SQL,
        )

        self.assertIn(
            "recheck_job_id is required",
            SQL,
        )


    def test_remediation_attempt_persists_target_id(self):
        self.assertIn(
            "target_id                TEXT NOT NULL",
            SQL,
        )

        self.assertIn(
            "p_target_id              TEXT",
            SQL,
        )

        self.assertIn(
            "v_existing.target_id <> p_target_id",
            SQL,
        )


    def test_remediation_policy_is_correlated_to_finding(self):
        self.assertIn(
            "v_finding.remediation_mode",
            SQL,
        )

        self.assertIn(
            "remediation policy mismatch:",
            SQL,
        )


    def test_approval_policy_requires_durable_ticket_flag(self):
        self.assertIn(
            "AND NOT v_finding.ticket_required",
            SQL,
        )

        self.assertIn(
            "approval_required remediation requires",
            SQL,
        )


    def test_blocked_policy_is_safe_override(self):
        self.assertIn(
            "p_remediation_policy <> 'blocked'",
            SQL,
        )

        self.assertIn(
            "v_finding.remediation_mode = 'report_only'",
            SQL,
        )

        self.assertIn(
            "'observe_only'",
            SQL,
        )



    def test_security_definer_used(self):
        names = (
            "create_remediation_attempt",
            "record_remediation_approval",
            "transition_remediation_attempt",
            "upsert_ticket_record",
            "update_ticket_record",
        )

        for name in names:
            self.assertIn(
                f"compliance.{name}",
                SQL,
            )

        self.assertGreaterEqual(
            SQL.count("SECURITY DEFINER"),
            len(names),
        )

    def test_fixed_search_path_used(self):
        self.assertGreaterEqual(
            SQL.count(
                "SET search_path = "
                "pg_catalog, compliance"
            ),
            5,
        )

    def test_application_roles_are_nologin(self):
        self.assertIn(
            "CREATE ROLE compliance_remediation",
            SQL,
        )

        self.assertIn(
            "CREATE ROLE compliance_ticketing",
            SQL,
        )

        self.assertGreaterEqual(
            SQL.count("NOLOGIN"),
            4,
        )

    def test_no_application_table_dml_grants(self):
        forbidden = (
            "GRANT INSERT ON "
            "compliance.remediation_attempts "
            "TO compliance_remediation",
            "GRANT UPDATE ON "
            "compliance.remediation_attempts "
            "TO compliance_remediation",
            "GRANT INSERT ON "
            "compliance.ticket_records "
            "TO compliance_ticketing",
            "GRANT UPDATE ON "
            "compliance.ticket_records "
            "TO compliance_ticketing",
        )

        for text in forbidden:
            self.assertNotIn(
                text,
                SQL,
            )

    def test_ticketing_cannot_execute_remediation(self):
        self.assertRegex(
            SQL,
            re.compile(
                r"REVOKE EXECUTE ON FUNCTION\s+"
                r"compliance\.transition_remediation_attempt"
                r"\([\s\S]*?\)\s+"
                r"FROM compliance_ticketing;",
                re.MULTILINE,
            ),
        )

    def test_remediation_cannot_approve_itself(self):
        self.assertRegex(
            SQL,
            re.compile(
                r"REVOKE EXECUTE ON FUNCTION\s+"
                r"compliance\.record_remediation_approval"
                r"\([\s\S]*?\)\s+"
                r"FROM compliance_remediation;",
                re.MULTILINE,
            ),
        )


if __name__ == "__main__":
    unittest.main()
