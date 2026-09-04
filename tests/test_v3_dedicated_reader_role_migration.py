import re
import unittest
from pathlib import Path


MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "db"
    / "migrations"
    / "015_v3_dedicated_reader_role.sql"
)


class V3DedicatedReaderRoleMigrationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.sql = MIGRATION.read_text(encoding="utf-8")
        cls.flat = re.sub(
            r"\s+",
            " ",
            cls.sql,
        ).lower()


    def test_migration_is_transactional(self):
        self.assertRegex(
            self.flat,
            r"\bbegin\s*;",
        )

        self.assertRegex(
            self.flat,
            r"\bcommit\s*;",
        )


    def test_creates_dedicated_privilege_role(self):
        self.assertIn(
            "create role compliance_v3_reader",
            self.flat,
        )


    def test_role_is_nologin(self):
        self.assertRegex(
            self.flat,
            r"create role compliance_v3_reader .*?\bnologin\b",
        )

        self.assertRegex(
            self.flat,
            r"alter role compliance_v3_reader .*?\bnologin\b",
        )


    def test_role_is_nonsuperuser(self):
        self.assertIn(
            "nosuperuser",
            self.flat,
        )


    def test_role_cannot_create_database(self):
        self.assertIn(
            "nocreatedb",
            self.flat,
        )


    def test_role_cannot_create_roles(self):
        self.assertIn(
            "nocreaterole",
            self.flat,
        )


    def test_role_cannot_replicate_or_bypass_rls(self):
        self.assertIn(
            "noreplication",
            self.flat,
        )

        self.assertIn(
            "nobypassrls",
            self.flat,
        )


    def test_role_does_not_inherit_privilege_roles(self):
        self.assertIn(
            "noinherit",
            self.flat,
        )


    def test_schema_privileges_are_reset_before_usage_grant(self):
        self.assertIn(
            "revoke all privileges on schema compliance "
            "from compliance_v3_reader",
            self.flat,
        )

        self.assertIn(
            "grant usage on schema compliance "
            "to compliance_v3_reader",
            self.flat,
        )


    def test_direct_table_privileges_are_revoked(self):
        self.assertIn(
            "revoke all privileges on all tables in schema compliance "
            "from compliance_v3_reader",
            self.flat,
        )


    def test_direct_sequence_privileges_are_revoked(self):
        self.assertIn(
            "revoke all privileges on all sequences in schema compliance "
            "from compliance_v3_reader",
            self.flat,
        )


    def test_existing_function_execute_is_reset(self):
        self.assertIn(
            "revoke execute on all functions in schema compliance "
            "from compliance_v3_reader",
            self.flat,
        )


    def test_single_source_reader_execute_is_granted(self):
        self.assertRegex(
            self.flat,
            r"grant execute on function "
            r"compliance\.read_v3_activation_source"
            r"\(\s*text\s*,\s*text\s*\) "
            r"to compliance_v3_reader",
        )


    def test_run_reader_execute_is_granted(self):
        self.assertRegex(
            self.flat,
            r"grant execute on function "
            r"compliance\.read_v3_activation_sources_for_run"
            r"\(\s*text\s*\) "
            r"to compliance_v3_reader",
        )


    def test_v3_ingest_execute_is_explicitly_revoked(self):
        self.assertRegex(
            self.flat,
            r"revoke execute on function "
            r"compliance\.ingest_v3_compliance_run"
            r"\("
            r"\s*jsonb\s*,"
            r"\s*jsonb\s*,"
            r"\s*bigint\s*,"
            r"\s*bigint\s*,"
            r"\s*bigint\s*,"
            r"\s*text\s*,"
            r"\s*text\s*"
            r"\) "
            r"from compliance_v3_reader",
        )


    def test_compliance_ingest_membership_is_revoked(self):
        self.assertIn(
            "revoke compliance_ingest from compliance_v3_reader",
            self.flat,
        )


    def test_compliance_ingest_membership_is_never_granted(self):
        self.assertNotIn(
            "grant compliance_ingest to compliance_v3_reader",
            self.flat,
        )


    def test_membership_contract_fails_closed(self):
        self.assertIn(
            "pg_catalog.pg_auth_members",
            self.flat,
        )

        self.assertIn(
            "compliance_v3_reader must not inherit any role membership",
            self.flat,
        )


    def test_runtime_login_is_not_created_here(self):
        self.assertNotIn(
            "create role compliance_v3_reader_runtime",
            self.flat,
        )

        self.assertNotIn(
            "create user compliance_v3_reader_runtime",
            self.flat,
        )


    def test_no_password_material_is_defined(self):
        self.assertNotRegex(
            self.flat,
            r"\bpassword\b\s+'",
        )


    def test_no_direct_dml_grant_exists(self):
        self.assertNotRegex(
            self.flat,
            r"grant\s+[^;]*\b"
            r"(insert|update|delete|truncate)\b"
            r"[^;]*to\s+compliance_v3_reader",
        )


if __name__ == "__main__":
    unittest.main()
