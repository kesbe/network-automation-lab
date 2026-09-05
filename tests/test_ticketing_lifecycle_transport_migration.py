from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]

MIGRATION = (
    ROOT
    / "db"
    / "migrations"
    / "016_ticketing_lifecycle_transport.sql"
)

SQL = MIGRATION.read_text()


class TicketingLifecycleTransportMigrationTests(
    unittest.TestCase
):
    def test_migration_transactional(self):
        text = SQL.strip()

        self.assertTrue(text.startswith("--"))
        self.assertIn("\nBEGIN;", text)
        self.assertTrue(text.endswith("COMMIT;"))

    def test_does_not_modify_existing_remediation_transport(self):
        forbidden = (
            "ALTER TABLE compliance.transport_events",
            "DROP TABLE compliance.transport_events",
            "TRUNCATE compliance.transport_events",
            "INSERT INTO compliance.transport_events",
            "UPDATE compliance.transport_events",
            "DELETE FROM compliance.transport_events",
            "ALTER TABLE compliance.v3_activation_sources",
            "DROP TABLE compliance.v3_activation_sources",
        )

        for value in forbidden:
            self.assertNotIn(value, SQL)

    def test_publication_ledger_exists(self):
        self.assertIn(
            "CREATE TABLE "
            "compliance.lifecycle_event_publications",
            SQL,
        )

        self.assertRegex(
            SQL,
            re.compile(
                r"PRIMARY KEY\s*\(\s*"
                r"topic\s*,\s*source_event_id\s*\)",
                re.MULTILINE,
            ),
        )

    def test_ticket_receipt_ledger_exists(self):
        self.assertIn(
            "CREATE TABLE "
            "compliance.ticket_event_receipts",
            SQL,
        )

        self.assertRegex(
            SQL,
            re.compile(
                r"PRIMARY KEY\s*\(\s*"
                r"provider\s*,\s*source_event_id\s*\)",
                re.MULTILINE,
            ),
        )

    def test_source_event_foreign_keys_exist(self):
        self.assertGreaterEqual(
            SQL.count(
                "REFERENCES "
                "compliance.finding_events(event_id)"
            ),
            2,
        )

    def test_full_ticket_lifecycle_supported(self):
        for value in (
            "DETECTED",
            "SEEN_AGAIN",
            "REOPENED",
            "RESOLVED",
        ):
            self.assertIn(
                f"'{value}'",
                SQL,
            )

    def test_reader_filters_ticket_required(self):
        reader = SQL.split(
            "CREATE FUNCTION "
            "compliance.read_unpublished_ticket_lifecycle_events",
            1,
        )[1].split(
            "-- ============================================================================",
            1,
        )[0]

        self.assertIn(
            "cf.ticket_required",
            reader,
        )

        self.assertIn(
            "pub.state <> 'COMPLETED'",
            reader,
        )

    def test_reader_is_not_cursor_based(self):
        self.assertNotRegex(
            SQL,
            re.compile(
                r"high[_ ]?water|last[_ ]?event[_ ]?id",
                re.IGNORECASE,
            ),
        )

    def test_publication_claim_has_lease_and_retry(self):
        self.assertIn(
            "CLAIMED_NEW",
            SQL,
        )

        self.assertIn(
            "DUPLICATE_COMPLETED",
            SQL,
        )

        self.assertIn(
            "DUPLICATE_INFLIGHT",
            SQL,
        )

        self.assertIn(
            "CLAIMED_RETRY",
            SQL,
        )

        self.assertIn(
            "lease_seconds must be between 60 and 86400",
            SQL,
        )

    def test_receipt_claim_has_same_retry_contract(self):
        receipt = SQL.split(
            "CREATE FUNCTION "
            "compliance.claim_ticket_event_receipt",
            1,
        )[1].split(
            "-- ============================================================================",
            1,
        )[0]

        for value in (
            "CLAIMED_NEW",
            "DUPLICATE_COMPLETED",
            "DUPLICATE_INFLIGHT",
            "CLAIMED_RETRY",
        ):
            self.assertIn(value, receipt)

    def test_ticket_correlation_table_is_reused(self):
        self.assertNotIn(
            "CREATE TABLE compliance.zammad_ticket_links",
            SQL,
        )

        self.assertIn(
            "compliance.ticket_records",
            SQL,
        )

    def test_zammad_wrappers_force_provider_and_type(self):
        self.assertIn(
            "'zammad'",
            SQL,
        )

        self.assertIn(
            "'INCIDENT'",
            SQL,
        )

        names = (
            "claim_zammad_ticket_event_receipt",
            "complete_zammad_ticket_event_receipt",
            "fail_zammad_ticket_event_receipt",
            "read_zammad_ticket_record",
            "upsert_zammad_ticket_record",
            "update_zammad_ticket_record",
        )

        for name in names:
            self.assertIn(
                f"compliance.{name}",
                SQL,
            )

    def test_narrow_roles_are_nologin_noinherit(self):
        self.assertIn(
            "CREATE ROLE compliance_lifecycle_publisher",
            SQL,
        )

        self.assertIn(
            "CREATE ROLE compliance_zammad_runtime_api",
            SQL,
        )

        self.assertGreaterEqual(
            SQL.count("NOLOGIN"),
            2,
        )

        self.assertGreaterEqual(
            SQL.count("NOINHERIT"),
            2,
        )

    def test_security_definer_used(self):
        required = (
            "read_unpublished_ticket_lifecycle_events",
            "claim_lifecycle_event_publication",
            "complete_lifecycle_event_publication",
            "fail_lifecycle_event_publication",
            "claim_ticket_event_receipt",
            "complete_ticket_event_receipt",
            "fail_ticket_event_receipt",
            "claim_zammad_ticket_event_receipt",
            "complete_zammad_ticket_event_receipt",
            "fail_zammad_ticket_event_receipt",
            "read_zammad_ticket_record",
            "upsert_zammad_ticket_record",
            "update_zammad_ticket_record",
        )

        self.assertGreaterEqual(
            SQL.count("SECURITY DEFINER"),
            len(required),
        )

    def test_fixed_search_path_used(self):
        self.assertGreaterEqual(
            SQL.count(
                "SET search_path = pg_catalog, compliance"
            ),
            13,
        )

    def test_public_execute_revoked(self):
        required = (
            "read_unpublished_ticket_lifecycle_events",
            "claim_lifecycle_event_publication",
            "complete_lifecycle_event_publication",
            "fail_lifecycle_event_publication",
            "claim_ticket_event_receipt",
            "complete_ticket_event_receipt",
            "fail_ticket_event_receipt",
            "claim_zammad_ticket_event_receipt",
            "complete_zammad_ticket_event_receipt",
            "fail_zammad_ticket_event_receipt",
            "read_zammad_ticket_record",
            "upsert_zammad_ticket_record",
            "update_zammad_ticket_record",
        )

        for name in required:
            self.assertRegex(
                SQL,
                re.compile(
                    r"REVOKE ALL\s+"
                    r"ON FUNCTION\s+"
                    rf"compliance\.{name}\(",
                    re.MULTILINE,
                ),
            )

    def test_no_direct_application_role_table_dml_grants(self):
        forbidden = (
            "GRANT SELECT ON "
            "compliance.lifecycle_event_publications",
            "GRANT INSERT ON "
            "compliance.lifecycle_event_publications",
            "GRANT UPDATE ON "
            "compliance.lifecycle_event_publications",
            "GRANT DELETE ON "
            "compliance.lifecycle_event_publications",
            "GRANT SELECT ON "
            "compliance.ticket_event_receipts",
            "GRANT INSERT ON "
            "compliance.ticket_event_receipts",
            "GRANT UPDATE ON "
            "compliance.ticket_event_receipts",
            "GRANT DELETE ON "
            "compliance.ticket_event_receipts",
        )

        for value in forbidden:
            self.assertNotIn(value, SQL)

    def test_zammad_role_does_not_get_generic_receipt_core(self):
        generic_grants = (
            "claim_ticket_event_receipt",
            "complete_ticket_event_receipt",
            "fail_ticket_event_receipt",
        )

        for name in generic_grants:
            pattern = re.compile(
                r"GRANT EXECUTE\s+"
                r"ON FUNCTION\s+"
                rf"compliance\.{name}\("
                r"[\s\S]*?"
                r"TO compliance_zammad_runtime_api;",
                re.MULTILINE,
            )

            self.assertIsNone(
                pattern.search(SQL)
            )

    def test_zammad_role_cannot_approve_or_remediate(self):
        for name in (
            "record_remediation_approval",
            "create_remediation_attempt",
            "transition_remediation_attempt",
        ):
            self.assertRegex(
                SQL,
                re.compile(
                    r"REVOKE EXECUTE\s+"
                    r"ON FUNCTION\s+"
                    rf"compliance\.{name}\("
                    r"[\s\S]*?"
                    r"FROM compliance_zammad_runtime_api;",
                    re.MULTILINE,
                ),
            )

    def test_no_runtime_login_created_yet(self):
        self.assertNotIn(
            "CREATE ROLE "
            "compliance_lifecycle_publisher_runtime",
            SQL,
        )

        self.assertNotIn(
            "CREATE ROLE "
            "compliance_zammad_runtime ",
            SQL,
        )

    def test_no_kafka_or_zammad_side_effects_in_migration(self):
        for value in (
            "network.compliance.lifecycle.events",
            "/api/v1/tickets",
            "Authorization: Token",
        ):
            self.assertNotIn(
                value,
                SQL,
            )


if __name__ == "__main__":
    unittest.main()
