import ast
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

MIGRATION = (
    ROOT
    / "db"
    / "migrations"
    / "018_servicenow_ticketing_provider.sql"
)

COMMON = (
    ROOT
    / "scripts"
    / "ticketing_runtime_common.py"
)

SQL = MIGRATION.read_text(
    encoding="utf-8"
)

NORMALIZED_SQL = " ".join(
    SQL.split()
)


WRAPPERS = (
    "claim_servicenow_ticket_event_receipt",
    "complete_servicenow_ticket_event_receipt",
    "fail_servicenow_ticket_event_receipt",
    "read_servicenow_ticket_record",
    "upsert_servicenow_ticket_record",
    "update_servicenow_ticket_record",
)


def database_allowlist():
    tree = ast.parse(
        COMMON.read_text(
            encoding="utf-8"
        )
    )

    for node in tree.body:
        targets = []

        if isinstance(
            node,
            ast.Assign,
        ):
            targets = node.targets

        elif isinstance(
            node,
            ast.AnnAssign,
        ):
            targets = [
                node.target
            ]

        else:
            continue

        if not any(
            isinstance(
                target,
                ast.Name,
            )
            and target.id
                == "ALLOWED_DATABASE_FUNCTIONS"
            for target in targets
        ):
            continue

        value = node.value

        if not (
            isinstance(
                value,
                ast.Call,
            )
            and isinstance(
                value.func,
                ast.Name,
            )
            and value.func.id
                == "frozenset"
            and len(
                value.args
            )
                == 1
        ):
            raise AssertionError(
                "unexpected allowlist shape"
            )

        container = value.args[0]

        return {
            element.value
            for element
            in container.elts
            if (
                isinstance(
                    element,
                    ast.Constant,
                )
                and isinstance(
                    element.value,
                    str,
                )
            )
        }

    raise AssertionError(
        "database allowlist not found"
    )


class ServiceNowTicketingProviderMigrationTests(
    unittest.TestCase
):

    def test_migration_is_transactional(
        self,
    ):
        stripped = SQL.strip()

        self.assertTrue(
            stripped.startswith(
                "BEGIN;"
            )
        )

        self.assertTrue(
            stripped.endswith(
                "COMMIT;"
            )
        )


    def test_only_expected_six_wrappers_created(
        self,
    ):
        created = set(
            re.findall(
                r"CREATE FUNCTION "
                r"compliance\.([a-z0-9_]+)"
                r"\s*\(",
                SQL,
                re.IGNORECASE,
            )
        )

        self.assertEqual(
            created,
            set(WRAPPERS),
        )


    def test_receipt_wrappers_force_servicenow(
        self,
    ):
        for name in (
            "claim_servicenow_ticket_event_receipt",
            "complete_servicenow_ticket_event_receipt",
            "fail_servicenow_ticket_event_receipt",
        ):

            pattern = re.compile(
                r"CREATE FUNCTION "
                r"compliance\."
                + re.escape(name)
                + r"\s*\("
                + r"[\s\S]*?"
                + r"'servicenow'"
                + r"[\s\S]*?"
                + r"\$\$;",
                re.IGNORECASE,
            )

            self.assertRegex(
                SQL,
                pattern,
            )


    def test_ticket_wrappers_force_incident_provider(
        self,
    ):
        self.assertIn(
            "AND provider = 'servicenow'",
            SQL,
        )

        self.assertIn(
            "AND ticket_type = 'INCIDENT'",
            SQL,
        )

        self.assertIn(
            "'servicenow',\n"
            "        'INCIDENT',",
            SQL,
        )

        self.assertIn(
            "v_provider <> 'servicenow'",
            SQL,
        )

        self.assertIn(
            "v_type <> 'INCIDENT'",
            SQL,
        )


    def test_role_is_nologin_noinherit(
        self,
    ):
        self.assertRegex(
            NORMALIZED_SQL,
            re.compile(
                r"CREATE ROLE "
                r"compliance_servicenow_runtime_api "
                r"NOLOGIN NOINHERIT;",
                re.IGNORECASE,
            ),
        )


    def test_security_definer_and_fixed_search_path(
        self,
    ):
        self.assertEqual(
            SQL.count(
                "SECURITY DEFINER"
            ),
            6,
        )

        self.assertEqual(
            SQL.count(
                "SET search_path = "
                "pg_catalog, compliance"
            ),
            6,
        )


    def test_owner_is_api_owner(
        self,
    ):
        self.assertEqual(
            SQL.count(
                "OWNER TO "
                "compliance_api_owner;"
            ),
            6,
        )


    def test_public_execute_revoked(
        self,
    ):
        for name in WRAPPERS:
            pattern = re.compile(
                r"REVOKE EXECUTE\s+"
                r"ON FUNCTION "
                r"compliance\."
                + re.escape(name)
                + r"\s*\("
                + r"[\s\S]*?"
                + r"FROM PUBLIC;",
                re.IGNORECASE,
            )

            self.assertRegex(
                SQL,
                pattern,
            )


    def test_role_receives_only_wrapper_execute(
        self,
    ):
        grants = re.findall(
            r"GRANT EXECUTE\s+"
            r"ON FUNCTION "
            r"compliance\.([a-z0-9_]+)"
            r"\s*\("
            r"[\s\S]*?"
            r"TO "
            r"compliance_servicenow_runtime_api;",
            SQL,
            re.IGNORECASE,
        )

        self.assertEqual(
            set(grants),
            set(WRAPPERS),
        )

        self.assertEqual(
            len(grants),
            6,
        )


    def test_generic_receipt_core_not_granted(
        self,
    ):
        for name in (
            "claim_ticket_event_receipt",
            "complete_ticket_event_receipt",
            "fail_ticket_event_receipt",
        ):
            pattern = re.compile(
                r"GRANT EXECUTE"
                r"[\s\S]*?"
                r"compliance\."
                + re.escape(name)
                + r"\s*\("
                r"[\s\S]*?"
                r"TO "
                r"compliance_servicenow_runtime_api;",
                re.IGNORECASE,
            )

            self.assertIsNone(
                pattern.search(
                    SQL
                )
            )


    def test_no_direct_table_dml_grants(
        self,
    ):
        for privilege in (
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
        ):
            self.assertNotRegex(
                SQL,
                re.compile(
                    r"GRANT\s+"
                    + privilege
                    + r"\s+ON\s+"
                    r"(?:TABLE\s+)?"
                    r"compliance\.",
                    re.IGNORECASE,
                ),
            )


    def test_no_remediation_or_approval_grants(
        self,
    ):
        for name in (
            "record_remediation_approval",
            "create_remediation_attempt",
            "transition_remediation_attempt",
        ):
            self.assertNotRegex(
                SQL,
                re.compile(
                    r"GRANT EXECUTE"
                    r"[\s\S]*?"
                    + re.escape(name)
                    + r"[\s\S]*?"
                    r"compliance_servicenow_runtime_api",
                    re.IGNORECASE,
                ),
            )


    def test_no_servicenow_credentials_or_http(
        self,
    ):
        lowered = SQL.lower()

        for forbidden in (
            "servicenow_token",
            "servicenow_password",
            "authorization:",
            "/api/now/",
            "service" + "-now.com",
            "http://",
            "https://",
        ):
            self.assertNotIn(
                forbidden,
                lowered,
            )


    def test_no_storage_schema_redefinition(
        self,
    ):
        for value in (
            "CREATE TABLE compliance.ticket_records",
            "CREATE TABLE compliance.ticket_event_receipts",
            "CREATE TABLE compliance.lifecycle_event_publications",
            "ALTER TABLE compliance.ticket_records",
            "ALTER TABLE compliance.ticket_event_receipts",
            "ALTER TABLE compliance.lifecycle_event_publications",
        ):
            self.assertNotIn(
                value,
                SQL,
            )


    def test_no_existing_generic_function_redefinition(
        self,
    ):
        for name in (
            "claim_ticket_event_receipt",
            "complete_ticket_event_receipt",
            "fail_ticket_event_receipt",
            "upsert_ticket_record",
            "update_ticket_record",
            "read_unpublished_ticket_lifecycle_events",
        ):
            self.assertNotRegex(
                SQL,
                re.compile(
                    r"CREATE "
                    r"(?:OR REPLACE )?"
                    r"FUNCTION "
                    r"compliance\."
                    + re.escape(name)
                    + r"\s*\(",
                    re.IGNORECASE,
                ),
            )


    def test_local_state_contract_remains_generic(
        self,
    ):
        self.assertIn(
            "'PENDING_CREATE'",
            SQL,
        )

        self.assertIn(
            "'RESOLVED'",
            SQL,
        )

        self.assertIn(
            "'CLOSED'",
            SQL,
        )

        for provider_state in (
            "INSTANCE_ACTIVE",
            "INSTANCE_RESOLVED",
            "new_state_id",
            "open_state_id",
            "closed_state_id",
        ):
            self.assertNotIn(
                provider_state,
                SQL,
            )


    def test_servicenow_identity_uses_generic_columns(
        self,
    ):
        self.assertIn(
            "external_ticket_id",
            SQL,
        )

        self.assertIn(
            "external_ticket_number",
            SQL,
        )

        self.assertNotIn(
            "sys_id TEXT",
            SQL,
        )

        self.assertNotIn(
            "incident_number TEXT",
            SQL,
        )


    def test_runtime_allowlist_contains_wrappers(
        self,
    ):
        allowed = database_allowlist()

        for name in WRAPPERS:
            self.assertIn(
                name,
                allowed,
            )


    def test_runtime_allowlist_keeps_zammad_wrappers(
        self,
    ):
        allowed = database_allowlist()

        for name in (
            "claim_zammad_ticket_event_receipt",
            "complete_zammad_ticket_event_receipt",
            "fail_zammad_ticket_event_receipt",
            "read_zammad_ticket_record",
            "upsert_zammad_ticket_record",
            "update_zammad_ticket_record",
        ):
            self.assertIn(
                name,
                allowed,
            )


    def test_runtime_allowlist_does_not_expose_generic_receipts(
        self,
    ):
        allowed = database_allowlist()

        for name in (
            "claim_ticket_event_receipt",
            "complete_ticket_event_receipt",
            "fail_ticket_event_receipt",
        ):
            self.assertNotIn(
                name,
                allowed,
            )


if __name__ == "__main__":
    unittest.main()
