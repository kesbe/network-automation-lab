#!/usr/bin/env python3

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

PLAYBOOK = (
    ROOT
    / "playbooks"
    / "compliance_prepare_v3_activation_events.yml"
)


class V3ActivationEventPrepareOrchestrationTests(
    unittest.TestCase
):
    @classmethod
    def setUpClass(cls):
        cls.source = PLAYBOOK.read_text()

    def test_uses_only_run_level_reader(self):
        self.assertIn(
            "compliance.read_v3_activation_sources_for_run(",
            self.source,
        )

        self.assertNotIn(
            "compliance.read_v3_activation_source(",
            self.source,
        )

    def test_reader_is_deterministically_ordered(self):
        self.assertRegex(
            self.source,
            re.compile(
                r"ORDER BY\s+"
                r"source\.finding_event_id\s+ASC",
                re.MULTILINE,
            ),
        )

    def test_reader_uses_named_run_argument(self):
        self.assertIn(
            "%(run_id)s::text",
            self.source,
        )

        self.assertIn(
            'run_id: "{{ v3_run_id }}"',
            self.source,
        )

    def test_activated_at_is_explicit_text(self):
        self.assertIn(
            "source.activated_at AT TIME ZONE 'UTC'",
            self.source,
        )

        self.assertIn(
            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"',
            self.source,
        )

    def test_reuses_postgresql_execution_boundary(self):
        self.assertGreaterEqual(
            self.source.count(
                "community.postgresql.postgresql_query:"
            ),
            2,
        )

        for env_name in (
            "NETAUTO_PG_HOST",
            "NETAUTO_PG_PORT",
            "NETAUTO_PG_DATABASE",
            "NETAUTO_PG_USERNAME",
            "NETAUTO_PG_PASSWORD",
            "NETAUTO_PG_SSLMODE",
        ):
            self.assertIn(
                env_name,
                self.source,
            )

        self.assertIn(
            "pg_database == 'network_compliance'",
            self.source,
        )

        self.assertIn(
            "pg_username == 'compliance_writer'",
            self.source,
        )

        self.assertIn(
            "pg_sslmode == 'disable'",
            self.source,
        )

    def test_postgresql_queries_are_no_log(self):
        query_positions = [
            match.start()
            for match in re.finditer(
                "community.postgresql.postgresql_query:",
                self.source,
            )
        ]

        self.assertEqual(
            len(query_positions),
            2,
        )

        for position in query_positions:
            window = self.source[
                position:
                position + 1400
            ]

            self.assertIn(
                "no_log: true",
                window,
            )

    def test_does_not_read_v3_tables_directly(self):
        for forbidden in (
            "FROM compliance.v3_activation_sources",
            "FROM compliance.v3_run_persistence_contexts",
        ):
            self.assertNotIn(
                forbidden,
                self.source,
            )

    def test_does_not_write_compliance_state(self):
        for forbidden in (
            "ingest_compliance_run(",
            "ingest_v3_compliance_run(",
            "INSERT INTO",
            "UPDATE compliance.",
            "DELETE FROM compliance.",
        ):
            self.assertNotIn(
                forbidden,
                self.source,
            )

    def test_invokes_frozen_adapter_as_cli(self):
        self.assertIn(
            "../scripts/v3_activation_event_adapter.py",
            self.source,
        )

        self.assertIn(
            "ansible.builtin.command:",
            self.source,
        )

        self.assertIn(
            'stdin: "{{ item | to_json }}"',
            self.source,
        )

        self.assertIn(
            "| from_json",
            self.source,
        )

    def test_does_not_reimplement_event_builder(self):
        for forbidden in (
            "build_event(",
            "deterministic_event_id(",
            "v3_compliance_event.py",
        ):
            self.assertNotIn(
                forbidden,
                self.source,
            )

    def test_has_no_kafka_role(self):
        for forbidden in (
            "run_v3_network_compliance_kafka_publisher.py",
            "v3_kafka_event_transport",
            "network.compliance.events",
            "kafka_bootstrap",
            "publish_event(",
        ):
            self.assertNotIn(
                forbidden,
                self.source,
            )

    def test_zero_activation_is_valid_batch(self):
        self.assertIn(
            "'NO_ACTIVATIONS'",
            self.source,
        )

        self.assertIn(
            "'ACTIVATIONS_PREPARED'",
            self.source,
        )

    def test_exports_single_batch_artifact(self):
        self.assertEqual(
            self.source.count(
                "ansible.builtin.set_stats:"
            ),
            1,
        )

        self.assertIn(
            "v3_activation_event_batch:",
            self.source,
        )

        for field in (
            "run_id:",
            "persistence_result_status:",
            "persistence_run_inserted:",
            "decision:",
            "activation_count:",
            "finding_event_ids:",
            "events:",
            "persistence_job_id:",
            "preparer_job_id:",
        ):
            self.assertIn(
                field,
                self.source,
            )

        self.assertIn(
            "per_host: false",
            self.source,
        )

    def test_duplicate_persistence_is_non_publishable(self):
        self.assertIn(
            "v3_persistence_is_new:",
            self.source,
        )

        self.assertIn(
            "v3_input_persistence.run_inserted is defined",
            self.source,
        )

        self.assertIn(
            "v3_input_persistence.result_status == 'DUPLICATE'",
            self.source,
        )

        self.assertIn(
            "'PERSISTENCE_DUPLICATE'",
            self.source,
        )

        self.assertIn(
            "not (v3_persistence_is_new | bool)",
            self.source,
        )

    def test_zero_row_reader_uses_documented_rowcount(self):
        self.assertIn(
            "v3_activation_source_query.rowcount is defined",
            self.source,
        )

        self.assertIn(
            "Validate normalized V3 activation source count",
            self.source,
        )

        self.assertIn(
            "v3_activation_source_query.rowcount",
            self.source,
        )

        self.assertIn(
            "query_all_results[0]",
            self.source,
        )

        self.assertNotIn(
            "query_result[0]",
            self.source,
        )

    def test_source_and_event_counts_must_match(self):
        self.assertRegex(
            self.source,
            re.compile(
                r"v3_canonical_events\s*\|\s*length"
                r"\s*==\s*"
                r"v3_activation_sources\s*\|\s*length",
                re.MULTILINE,
            ),
        )

    def test_only_activation_lifecycle_types_allowed(self):
        self.assertGreaterEqual(
            self.source.count(
                "['DETECTED', 'REOPENED']"
            ),
            2,
        )

    def test_no_shell_execution(self):
        self.assertNotIn(
            "ansible.builtin.shell:",
            self.source,
        )

        self.assertNotRegex(
            self.source,
            re.compile(
                r"^\s*shell:",
                re.MULTILINE,
            ),
        )


if __name__ == "__main__":
    unittest.main()
