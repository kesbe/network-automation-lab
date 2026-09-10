import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

COMMON = (
    ROOT
    / "scripts"
    / "ticketing_runtime_common.py"
)

PUBLISHER = (
    ROOT
    / "scripts"
    / "ticketing_lifecycle_publisher.py"
)

ADAPTER = (
    ROOT
    / "scripts"
    / "zammad_ticketing_adapter.py"
)

REQUIREMENTS = (
    ROOT
    / "execution-environments"
    / "ticketing-runtime-ee"
    / "requirements.txt"
)


class RuntimeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.common = COMMON.read_text()
        cls.publisher = PUBLISHER.read_text()
        cls.adapter = ADAPTER.read_text()
        cls.requirements = (
            REQUIREMENTS.read_text()
        )

    def test_publisher_uses_only_runtime_api_names(self):
        for name in (
            "read_unpublished_ticket_lifecycle_events",
            "claim_lifecycle_event_publication",
            "complete_lifecycle_event_publication",
            "fail_lifecycle_event_publication",
        ):
            self.assertIn(
                name,
                self.publisher,
            )

    def test_adapter_uses_zammad_runtime_wrappers(self):
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
                self.adapter,
            )

    def test_no_generic_receipt_api_in_adapter(self):
        for forbidden in (
            '"claim_ticket_event_receipt"',
            '"complete_ticket_event_receipt"',
            '"fail_ticket_event_receipt"',
        ):
            self.assertNotIn(
                forbidden,
                self.adapter,
            )

    def test_no_direct_compliance_table_dml(self):
        combined = (
            self.common
            + "\n"
            + self.publisher
            + "\n"
            + self.adapter
        )

        patterns = (
            r"\bINSERT\s+INTO\s+compliance\.",
            r"\bUPDATE\s+compliance\.",
            r"\bDELETE\s+FROM\s+compliance\.",
        )

        for pattern in patterns:
            self.assertIsNone(
                re.search(
                    pattern,
                    combined,
                    re.I,
                )
            )

    def test_lifecycle_topic_is_frozen(self):
        self.assertIn(
            'DEFAULT_TOPIC = '
            '"network.compliance.lifecycle.events"',
            self.publisher,
        )

        self.assertIn(
            'DEFAULT_TOPIC = '
            '"network.compliance.lifecycle.events"',
            self.adapter,
        )

    def test_zammad_group_is_frozen(self):
        self.assertIn(
            '"zammad-network-compliance-production-v1"',
            self.adapter,
        )

    def test_manual_offset_commit(self):
        self.assertIn(
            '"enable.auto.commit":',
            self.adapter,
        )

        self.assertRegex(
            self.adapter,
            r'"enable\.auto\.commit"\s*:\s*False',
        )

        self.assertRegex(
            self.adapter,
            r'"enable\.auto\.offset\.store"\s*:\s*False',
        )

    def test_sync_commit_after_processing(self):
        self.assertIn(
            "asynchronous=False",
            self.adapter,
        )

    def test_seen_again_branch_has_no_zammad_write(self):
        marker = (
            'elif event_type == "SEEN_AGAIN":'
        )

        self.assertIn(
            marker,
            self.adapter,
        )

    def test_search_before_create(self):
        search_at = self.adapter.index(
            "self.zammad.search_ticket("
        )

        create_at = self.adapter.index(
            "self.zammad.create_ticket("
        )

        self.assertLess(
            search_at,
            create_at,
        )

    def test_zammad_state_ids(self):
        for expected in (
            "target_group_id=2",
            "new_state_id=1",
            "open_state_id=2",
            "closed_state_id=4",
        ):
            self.assertIn(
                expected,
                self.adapter,
            )

    def test_secret_values_not_hardcoded(self):
        self.assertNotIn(
            "api-secret",
            self.adapter,
        )

        self.assertNotIn(
            "db-secret",
            self.publisher,
        )

    def test_dependencies_pinned(self):
        self.assertIn(
            "confluent-kafka==2.15.0",
            self.requirements,
        )

        self.assertIn(
            "psycopg2-binary==2.9.12",
            self.requirements,
        )

    def test_protected_remediation_topic_absent(self):
        for source in (
            self.publisher,
            self.adapter,
        ):
            self.assertNotIn(
                '"network.compliance.events"',
                source,
            )

    def test_remediation_api_names_absent(self):
        combined = (
            self.publisher
            + "\n"
            + self.adapter
        )

        for name in (
            "record_remediation_approval",
            "create_remediation_attempt",
            "transition_remediation_attempt",
        ):
            self.assertNotIn(
                name,
                combined,
            )

    def test_publisher_run_scope_contract(self):
        self.assertIn(
            '"TICKETING_PUBLISH_RUN_ID"',
            self.publisher,
        )

        self.assertIn(
            '"read_unpublished_ticket_lifecycle_events_for_run"',
            self.publisher,
        )

        self.assertIn(
            '"read_unpublished_ticket_lifecycle_events_for_run"',
            self.common,
        )


if __name__ == "__main__":
    unittest.main()
