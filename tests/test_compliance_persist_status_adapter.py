from pathlib import Path
import unittest


PLAYBOOK = (
    Path(__file__).resolve().parents[1]
    / "playbooks"
    / "compliance_persist.yml"
)


class CompliancePersistStatusAdapterTests(
    unittest.TestCase
):

    @classmethod
    def setUpClass(cls):
        cls.text = PLAYBOOK.read_text()

    def test_canonical_noncompliant_is_explicitly_mapped(
        self,
    ):
        self.assertIn(
            "NON_COMPLIANT: NON-COMPLIANT",
            self.text,
        )

    def test_compliant_is_preserved(
        self,
    ):
        self.assertIn(
            "COMPLIANT: COMPLIANT",
            self.text,
        )

    def test_legacy_noncompliant_remains_supported(
        self,
    ):
        self.assertIn(
            "NON-COMPLIANT: NON-COMPLIANT",
            self.text,
        )

    def test_database_receives_compatibility_copy(
        self,
    ):
        self.assertIn(
            'compliance_run: "{{ db_compliance_run | to_json }}"',
            self.text,
        )

        self.assertNotIn(
            'compliance_run: "{{ compliance_run | to_json }}"',
            self.text,
        )

    def test_original_findings_are_not_rewritten(
        self,
    ):
        self.assertIn(
            "db_compliance_run.findings == compliance_run.findings",
            self.text,
        )

    def test_unknown_statuses_fail_closed(
        self,
    ):
        self.assertIn(
            "Unsupported compliance device status for PostgreSQL",
            self.text,
        )


if __name__ == "__main__":
    unittest.main()
