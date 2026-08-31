from pathlib import Path
import unittest


PLAYBOOK = (
    Path(__file__).resolve().parents[1]
    / "playbooks"
    / "compliance_persist.yml"
)


class V3CompliancePersistOrchestrationTests(
    unittest.TestCase
):

    @classmethod
    def setUpClass(cls):
        cls.text = PLAYBOOK.read_text()

    def test_v3_is_explicit_opt_in(self):
        self.assertIn(
            "v3_persistence_enabled",
            self.text,
        )
        self.assertIn(
            "| default(false)",
            self.text,
        )

    def test_v3_requires_explicit_target(self):
        self.assertIn(
            "resolved_target is defined",
            self.text,
        )
        self.assertIn(
            "resolved_target is mapping",
            self.text,
        )
        self.assertIn(
            "resolved_target.schema_version | string == '3.0'",
            self.text,
        )

    def test_frozen_adapter_is_used(self):
        self.assertIn(
            "../scripts/v3_compliance_persistence_context.py",
            self.text,
        )
        self.assertIn(
            "'compliance_run': compliance_run",
            self.text,
        )
        self.assertIn(
            "'resolved_target': resolved_target",
            self.text,
        )

    def test_context_uses_original_run(self):
        start = self.text.index(
            "Build canonical V3 persistence context"
        )
        end = self.text.index(
            "Capture canonical V3 persistence context",
            start,
        )

        block = self.text[start:end]

        self.assertIn(
            "'compliance_run': compliance_run",
            block,
        )
        self.assertNotIn(
            "'compliance_run': db_compliance_run",
            block,
        )

    def test_legacy_api_remains_once(self):
        self.assertEqual(
            self.text.count(
                "FROM compliance.ingest_compliance_run("
            ),
            1,
        )

    def test_v3_api_exists_once(self):
        self.assertEqual(
            self.text.count(
                "FROM compliance.ingest_v3_compliance_run("
            ),
            1,
        )

    def test_database_compatibility_copy_preserved(self):
        self.assertIn(
            'compliance_run: "{{ db_compliance_run | to_json }}"',
            self.text,
        )
        self.assertIn(
            "db_compliance_run.findings == compliance_run.findings",
            self.text,
        )

    def test_branches_are_mutually_exclusive(self):
        v2 = self.text.index(
            "Persist compliance run through approved PostgreSQL API"
        )
        v3 = self.text.index(
            "Persist V3 compliance run through transactional PostgreSQL API"
        )
        end = self.text.index(
            "Validate PostgreSQL persistence response structure",
            v3,
        )

        v2_block = self.text[v2:v3]
        v3_block = self.text[v3:end]

        self.assertIn(
            "when: not (v3_persistence_active | bool)",
            v2_block,
        )
        self.assertIn(
            "when: v3_persistence_active | bool",
            v3_block,
        )

    def test_activation_source_result_is_required(self):
        self.assertIn(
            "activation_sources_inserted",
            self.text,
        )

    def test_no_direct_ingest_finding(self):
        self.assertNotIn(
            "compliance.ingest_finding(",
            self.text,
        )

    def test_target_resolution_not_duplicated_here(self):
        for token in (
            "v3_target_resolver.py",
            "resolve_target(",
            "build_resolved_target(",
            "policy_applies(",
        ):
            with self.subTest(token=token):
                self.assertNotIn(
                    token,
                    self.text,
                )

    def test_v2_status_adapter_remains(self):
        self.assertIn(
            "COMPLIANT: COMPLIANT",
            self.text,
        )
        self.assertIn(
            "NON_COMPLIANT: NON-COMPLIANT",
            self.text,
        )
        self.assertIn(
            "NON-COMPLIANT: NON-COMPLIANT",
            self.text,
        )


    def test_adapter_stdin_uses_mapping_literal(
        self,
    ):
        start = self.text.index(
            "Build canonical V3 persistence context"
        )

        end = self.text.index(
            "Capture canonical V3 persistence context",
            start,
        )

        block = self.text[
            start:end
        ]

        self.assertIn(
            "stdin: >-\n"
            "          {{\n"
            "            {\n",
            block,
        )

        self.assertNotIn(
            "stdin: >-\n"
            "          {{\n"
            "            {{\n",
            block,
        )


if __name__ == "__main__":
    unittest.main()
