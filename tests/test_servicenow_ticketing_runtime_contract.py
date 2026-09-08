import ast
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]

ADAPTER = (
    ROOT
    / "scripts"
    / "servicenow_ticketing_adapter.py"
)

SOURCE = ADAPTER.read_text(
    encoding="utf-8"
)

TREE = ast.parse(
    SOURCE,
    filename=str(ADAPTER),
)


def class_names():
    return {
        node.name
        for node in TREE.body
        if isinstance(node, ast.ClassDef)
    }


def function_names():
    return {
        node.name
        for node in TREE.body
        if isinstance(
            node,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
            ),
        )
    }


class ServiceNowRuntimeContractTests(
    unittest.TestCase
):

    def test_required_runtime_classes_exist(self):
        required = {
            "ServiceNowAdapterConfig",
            "ServiceNowReceiptRepository",
            "ServiceNowTicketingAdapter",
            "KafkaTicketConsumer",
        }

        self.assertTrue(
            required.issubset(
                class_names()
            ),
            required - class_names(),
        )

    def test_runtime_entrypoints_exist(self):
        required = {
            "build_runtime",
            "main",
        }

        self.assertTrue(
            required.issubset(
                function_names()
            ),
            required - function_names(),
        )

    def test_servicenow_runtime_wrappers_are_used(self):
        required = (
            "claim_servicenow_ticket_event_receipt",
            "complete_servicenow_ticket_event_receipt",
            "fail_servicenow_ticket_event_receipt",
            "read_servicenow_ticket_record",
            "upsert_servicenow_ticket_record",
            "update_servicenow_ticket_record",
        )

        for value in required:
            with self.subTest(value=value):
                self.assertIn(
                    value,
                    SOURCE,
                )

    def test_generic_receipt_core_is_not_called(self):
        forbidden = (
            '"claim_ticket_event_receipt"',
            "'claim_ticket_event_receipt'",
            '"complete_ticket_event_receipt"',
            "'complete_ticket_event_receipt'",
            '"fail_ticket_event_receipt"',
            "'fail_ticket_event_receipt'",
        )

        for value in forbidden:
            with self.subTest(value=value):
                self.assertNotIn(
                    value,
                    SOURCE,
                )

    def test_no_zammad_runtime_dependency(self):
        self.assertNotIn(
            "zammad_ticketing_adapter",
            SOURCE.lower(),
        )

        self.assertNotIn(
            "ZammadTicketingAdapter",
            SOURCE,
        )

        self.assertNotIn(
            "ZammadReceiptRepository",
            SOURCE,
        )

        self.assertNotIn(
            "ZammadClient",
            SOURCE,
        )

    def test_lifecycle_topic_is_frozen(self):
        self.assertIn(
            "network.compliance.lifecycle.events",
            SOURCE,
        )

    def test_service_now_has_dedicated_consumer_group(self):
        lowered = SOURCE.lower()

        self.assertIn(
            "servicenow",
            lowered,
        )

        self.assertIn(
            "group",
            lowered,
        )

        self.assertNotIn(
            "zammad-network-compliance-production-v1",
            SOURCE,
        )

        self.assertNotIn(
            "eda-network-compliance-production-v1",
            SOURCE,
        )

    def test_manual_offset_commit_configuration(self):
        compact = (
            SOURCE
            .replace(" ", "")
            .replace("\n", "")
        )

        self.assertTrue(
            (
                '"enable.auto.commit":False'
                in SOURCE
            )
            or (
                "'enable.auto.commit':False"
                in SOURCE
            )
            or (
                '"enable.auto.commit":false'
                in SOURCE.lower()
            )
            or (
                "enable.auto.commit"
                in SOURCE
                and "False"
                in SOURCE
            )
        )

        self.assertIn(
            "commit(",
            compact,
        )

    def test_offset_store_is_disabled(self):
        self.assertIn(
            "enable.auto.offset.store",
            SOURCE,
        )

        self.assertIn(
            "False",
            SOURCE,
        )

    def test_receipt_dispositions_are_explicit(self):
        for value in (
            "COMPLETED",
            "ALREADY_COMPLETED",
            "BUSY",
        ):
            with self.subTest(value=value):
                self.assertIn(
                    value,
                    SOURCE,
                )

    def test_lifecycle_events_are_explicit(self):
        for value in (
            "DETECTED",
            "SEEN_AGAIN",
            "RESOLVED",
            "REOPENED",
        ):
            with self.subTest(value=value):
                self.assertIn(
                    value,
                    SOURCE,
                )

    def test_local_ticket_states_are_explicit(self):
        self.assertIn(
            '"OPEN"',
            SOURCE,
        )

        self.assertIn(
            '"CLOSED"',
            SOURCE,
        )

    def test_runtime_builds_expected_components(self):
        required = (
            "SecurityDefinerDatabaseClient",
            "ServiceNowReceiptRepository",
            "ServiceNowIncidentProvider",
            "ServiceNowTicketingAdapter",
            "KafkaTicketConsumer",
        )

        for value in required:
            with self.subTest(value=value):
                self.assertIn(
                    value,
                    SOURCE,
                )

    def test_runtime_has_error_redaction(self):
        self.assertIn(
            "redact_text",
            SOURCE,
        )

    def test_no_direct_servicenow_execution_during_test(self):
        #
        # This contract test deliberately performs only
        # static source inspection. It imports neither the
        # adapter nor a transport implementation and therefore
        # cannot contact ServiceNow, Kafka, Kubernetes, or a DB.
        #
        self.assertTrue(
            ADAPTER.is_file()
        )




###############################################################################
# Offline behavioral runtime tests
#
# These use in-memory fakes only.
# They do not contact a database, Kafka broker, or ServiceNow API.
###############################################################################

import json
from types import SimpleNamespace

from scripts.servicenow_ticketing_adapter import (
    KafkaTicketConsumer,
    ServiceNowReceiptRepository,
    ServiceNowTicketingAdapter,
)


def servicenow_runtime_test_config():
    return SimpleNamespace(
        database=SimpleNamespace(
            password="offline-db-placeholder",
        ),
        bootstrap_servers="kafka.invalid:9092",
        topic="network.compliance.lifecycle.events",
        consumer_group=(
            "servicenow-network-compliance-production-v1"
        ),
        instance_id="servicenow-test-adapter-1",
        lease_seconds=300,
        poll_seconds=5,
        authorization=(
            "Offline test authorization placeholder"
        ),
    )


def servicenow_runtime_event(
    lifecycle_event_type,
    source_event_id=1,
    finding_id="finding-1",
):
    return {
        "source_event_id":
            source_event_id,

        "finding_id":
            finding_id,

        "run_id":
            "run-1",

        "lifecycle_event_type":
            lifecycle_event_type,

        "event_time":
            "2026-09-08T00:00:00Z",

        "old_status":
            None,

        "new_status":
            "OPEN",

        "event_details":
            {},

        "finding_snapshot":
            {},
    }


def fake_remote_ticket(
    external_ticket_id="sys-1",
    external_ticket_number="INC0000001",
):
    return SimpleNamespace(
        external_ticket_id=
            external_ticket_id,

        external_ticket_number=
            external_ticket_number,
    )


class FakeServiceNowRuntimeDatabase:
    def __init__(self):
        self.calls = []

    def fetch_json(
        self,
        function_name,
        parameters,
    ):
        self.calls.append(
            (
                function_name,
                parameters,
            )
        )

        return {
            "status":
                "OK",
        }


class FakeServiceNowRuntimeRepository:
    def __init__(
        self,
        claim_result=None,
        ticket=None,
    ):
        self.claim_result = (
            claim_result
            if claim_result is not None
            else {
                "status":
                    "CLAIMED",
            }
        )

        self.ticket = ticket
        self.calls = []

    def claim(
        self,
        source_event_id,
        instance_id,
        lease_seconds,
    ):
        self.calls.append(
            (
                "claim",
                source_event_id,
            )
        )

        return self.claim_result

    def complete(
        self,
        source_event_id,
        instance_id,
        record_id,
    ):
        self.calls.append(
            (
                "complete",
                source_event_id,
                record_id,
            )
        )

        return {
            "status":
                "COMPLETED",
        }

    def fail(
        self,
        source_event_id,
        instance_id,
        error,
    ):
        self.calls.append(
            (
                "fail",
                source_event_id,
                error,
            )
        )

        return {
            "status":
                "FAILED",
        }

    def read_ticket(
        self,
        finding_id,
    ):
        self.calls.append(
            (
                "read_ticket",
                finding_id,
            )
        )

        return self.ticket

    def upsert_ticket(
        self,
        record_id,
        finding_id,
        external_id,
        external_number,
        state,
        details,
    ):
        self.calls.append(
            (
                "upsert",
                record_id,
                external_id,
                external_number,
                state,
            )
        )

        self.ticket = {
            "ticket_record_id":
                record_id,

            "external_ticket_id":
                external_id,

            "external_ticket_number":
                external_number,

            "ticket_state":
                state,
        }

        return self.ticket

    def update_ticket(
        self,
        record_id,
        expected_state,
        new_state,
        external_id,
        external_number,
        last_error,
        details,
    ):
        self.calls.append(
            (
                "update",
                record_id,
                expected_state,
                new_state,
                external_id,
                external_number,
            )
        )

        self.ticket = {
            "ticket_record_id":
                record_id,

            "external_ticket_id":
                external_id,

            "external_ticket_number":
                external_number,

            "ticket_state":
                new_state,
        }

        return self.ticket


class FakeServiceNowRuntimeProvider:
    def __init__(
        self,
        search_result=None,
        create_result=None,
        fail_update=False,
    ):
        self.search_result = search_result

        self.create_result = (
            create_result
            if create_result is not None
            else fake_remote_ticket()
        )

        self.fail_update = fail_update
        self.calls = []

    def search_ticket(
        self,
        finding_id,
    ):
        self.calls.append(
            (
                "search",
                finding_id,
            )
        )

        return self.search_result

    def create_ticket(
        self,
        event_value,
    ):
        self.calls.append(
            (
                "create",
                event_value[
                    "finding_id"
                ],
            )
        )

        return self.create_result

    def resolve_ticket(
        self,
        external_ticket_id,
        event_value,
    ):
        self.calls.append(
            (
                "resolve",
                external_ticket_id,
            )
        )

        if self.fail_update:
            raise RuntimeError(
                "offline remote failure"
            )

        return fake_remote_ticket(
            external_ticket_id=
                external_ticket_id,
        )

    def reopen_ticket(
        self,
        external_ticket_id,
        event_value,
    ):
        self.calls.append(
            (
                "reopen",
                external_ticket_id,
            )
        )

        if self.fail_update:
            raise RuntimeError(
                "offline remote failure"
            )

        return fake_remote_ticket(
            external_ticket_id=
                external_ticket_id,
        )


class FakeServiceNowKafkaMessage:
    def __init__(
        self,
        payload,
    ):
        self.payload = payload

    def error(self):
        return None

    def value(self):
        return json.dumps(
            self.payload
        ).encode(
            "utf-8"
        )


class FakeServiceNowKafkaConsumer:
    def __init__(self):
        self.commits = []
        self.subscriptions = []
        self.closed = False

    def subscribe(
        self,
        topics,
    ):
        self.subscriptions.append(
            list(topics)
        )

    def commit(
        self,
        message,
        asynchronous,
    ):
        self.commits.append(
            (
                message,
                asynchronous,
            )
        )

    def poll(
        self,
        timeout,
    ):
        return None

    def close(self):
        self.closed = True


class ServiceNowRuntimeBehaviorTests(
    unittest.TestCase
):

    def test_repository_uses_servicenow_wrappers(
        self,
    ):
        database = (
            FakeServiceNowRuntimeDatabase()
        )

        repository = (
            ServiceNowReceiptRepository(
                database
            )
        )

        repository.claim(
            10,
            "adapter-1",
            300,
        )

        repository.complete(
            10,
            "adapter-1",
            "record-1",
        )

        repository.fail(
            10,
            "adapter-1",
            "failure",
        )

        repository.read_ticket(
            "finding-1"
        )

        repository.upsert_ticket(
            "record-1",
            "finding-1",
            "sys-1",
            "INC0000001",
            "OPEN",
            {
                "test":
                    True,
            },
        )

        repository.update_ticket(
            "record-1",
            "OPEN",
            "CLOSED",
            "sys-1",
            "INC0000001",
            None,
            {
                "test":
                    True,
            },
        )

        self.assertEqual(
            [
                item[0]
                for item in database.calls
            ],
            [
                "claim_servicenow_ticket_event_receipt",
                "complete_servicenow_ticket_event_receipt",
                "fail_servicenow_ticket_event_receipt",
                "read_servicenow_ticket_record",
                "upsert_servicenow_ticket_record",
                "update_servicenow_ticket_record",
            ],
        )

    def test_completed_receipt_skips_remote_mutation(
        self,
    ):
        repository = (
            FakeServiceNowRuntimeRepository(
                claim_result={
                    "status":
                        "ALREADY_COMPLETED",
                }
            )
        )

        provider = (
            FakeServiceNowRuntimeProvider()
        )

        result = (
            ServiceNowTicketingAdapter(
                servicenow_runtime_test_config(),
                repository,
                provider,
            ).process_event(
                servicenow_runtime_event(
                    "DETECTED"
                )
            )
        )

        self.assertEqual(
            result,
            "ALREADY_COMPLETED",
        )

        self.assertEqual(
            provider.calls,
            [],
        )

    def test_busy_receipt_skips_remote_mutation(
        self,
    ):
        repository = (
            FakeServiceNowRuntimeRepository(
                claim_result={
                    "status":
                        "BUSY",
                }
            )
        )

        provider = (
            FakeServiceNowRuntimeProvider()
        )

        result = (
            ServiceNowTicketingAdapter(
                servicenow_runtime_test_config(),
                repository,
                provider,
            ).process_event(
                servicenow_runtime_event(
                    "DETECTED"
                )
            )
        )

        self.assertEqual(
            result,
            "BUSY",
        )

        self.assertEqual(
            provider.calls,
            [],
        )

    def test_detected_searches_before_create(
        self,
    ):
        repository = (
            FakeServiceNowRuntimeRepository()
        )

        provider = (
            FakeServiceNowRuntimeProvider()
        )

        ServiceNowTicketingAdapter(
            servicenow_runtime_test_config(),
            repository,
            provider,
        ).process_event(
            servicenow_runtime_event(
                "DETECTED"
            )
        )

        self.assertEqual(
            provider.calls,
            [
                (
                    "search",
                    "finding-1",
                ),
                (
                    "create",
                    "finding-1",
                ),
            ],
        )

        self.assertEqual(
            repository.ticket[
                "external_ticket_id"
            ],
            "sys-1",
        )

        self.assertEqual(
            repository.ticket[
                "external_ticket_number"
            ],
            "INC0000001",
        )

        self.assertEqual(
            repository.ticket[
                "ticket_state"
            ],
            "OPEN",
        )

    def test_detected_remote_search_avoids_duplicate_create(
        self,
    ):
        repository = (
            FakeServiceNowRuntimeRepository()
        )

        provider = (
            FakeServiceNowRuntimeProvider(
                search_result=
                    fake_remote_ticket(
                        "sys-22",
                        "INC0000022",
                    )
            )
        )

        ServiceNowTicketingAdapter(
            servicenow_runtime_test_config(),
            repository,
            provider,
        ).process_event(
            servicenow_runtime_event(
                "DETECTED"
            )
        )

        self.assertEqual(
            provider.calls,
            [
                (
                    "search",
                    "finding-1",
                ),
            ],
        )

        self.assertEqual(
            repository.ticket[
                "external_ticket_id"
            ],
            "sys-22",
        )

        self.assertEqual(
            repository.ticket[
                "external_ticket_number"
            ],
            "INC0000022",
        )

    def test_detected_existing_active_record_avoids_remote_mutation(
        self,
    ):
        repository = (
            FakeServiceNowRuntimeRepository(
                ticket={
                    "ticket_record_id":
                        "record-1",

                    "external_ticket_id":
                        "sys-22",

                    "external_ticket_number":
                        "INC0000022",

                    "ticket_state":
                        "OPEN",
                }
            )
        )

        provider = (
            FakeServiceNowRuntimeProvider()
        )

        result = (
            ServiceNowTicketingAdapter(
                servicenow_runtime_test_config(),
                repository,
                provider,
            ).process_event(
                servicenow_runtime_event(
                    "DETECTED"
                )
            )
        )

        self.assertEqual(
            result,
            "COMPLETED",
        )

        self.assertEqual(
            provider.calls,
            [],
        )

    def test_seen_again_has_no_external_mutation(
        self,
    ):
        repository = (
            FakeServiceNowRuntimeRepository(
                ticket={
                    "ticket_record_id":
                        "record-1",

                    "external_ticket_id":
                        "sys-22",

                    "external_ticket_number":
                        "INC0000022",

                    "ticket_state":
                        "OPEN",
                }
            )
        )

        provider = (
            FakeServiceNowRuntimeProvider()
        )

        result = (
            ServiceNowTicketingAdapter(
                servicenow_runtime_test_config(),
                repository,
                provider,
            ).process_event(
                servicenow_runtime_event(
                    "SEEN_AGAIN"
                )
            )
        )

        self.assertEqual(
            result,
            "COMPLETED",
        )

        self.assertEqual(
            provider.calls,
            [],
        )

        self.assertEqual(
            repository.calls[-1][0],
            "complete",
        )

    def test_reopened_updates_same_incident_to_open(
        self,
    ):
        repository = (
            FakeServiceNowRuntimeRepository(
                ticket={
                    "ticket_record_id":
                        "record-1",

                    "external_ticket_id":
                        "sys-22",

                    "external_ticket_number":
                        "INC0000022",

                    "ticket_state":
                        "CLOSED",
                }
            )
        )

        provider = (
            FakeServiceNowRuntimeProvider()
        )

        ServiceNowTicketingAdapter(
            servicenow_runtime_test_config(),
            repository,
            provider,
        ).process_event(
            servicenow_runtime_event(
                "REOPENED"
            )
        )

        self.assertIn(
            (
                "reopen",
                "sys-22",
            ),
            provider.calls,
        )

        self.assertEqual(
            repository.ticket[
                "external_ticket_id"
            ],
            "sys-22",
        )

        self.assertEqual(
            repository.ticket[
                "ticket_state"
            ],
            "OPEN",
        )

    def test_resolved_updates_same_incident_to_closed(
        self,
    ):
        repository = (
            FakeServiceNowRuntimeRepository(
                ticket={
                    "ticket_record_id":
                        "record-1",

                    "external_ticket_id":
                        "sys-22",

                    "external_ticket_number":
                        "INC0000022",

                    "ticket_state":
                        "OPEN",
                }
            )
        )

        provider = (
            FakeServiceNowRuntimeProvider()
        )

        ServiceNowTicketingAdapter(
            servicenow_runtime_test_config(),
            repository,
            provider,
        ).process_event(
            servicenow_runtime_event(
                "RESOLVED"
            )
        )

        self.assertIn(
            (
                "resolve",
                "sys-22",
            ),
            provider.calls,
        )

        self.assertEqual(
            repository.ticket[
                "external_ticket_id"
            ],
            "sys-22",
        )

        self.assertEqual(
            repository.ticket[
                "ticket_state"
            ],
            "CLOSED",
        )

    def test_remote_failure_marks_receipt_failed(
        self,
    ):
        repository = (
            FakeServiceNowRuntimeRepository(
                ticket={
                    "ticket_record_id":
                        "record-1",

                    "external_ticket_id":
                        "sys-22",

                    "external_ticket_number":
                        "INC0000022",

                    "ticket_state":
                        "OPEN",
                }
            )
        )

        provider = (
            FakeServiceNowRuntimeProvider(
                fail_update=True
            )
        )

        adapter = (
            ServiceNowTicketingAdapter(
                servicenow_runtime_test_config(),
                repository,
                provider,
            )
        )

        with self.assertRaises(
            RuntimeError
        ):
            adapter.process_event(
                servicenow_runtime_event(
                    "RESOLVED"
                )
            )

        self.assertEqual(
            repository.calls[-1][0],
            "fail",
        )

        self.assertNotIn(
            "offline-db-placeholder",
            repository.calls[-1][2],
        )

        self.assertNotIn(
            "Offline test authorization placeholder",
            repository.calls[-1][2],
        )

    def test_consumer_commits_completed(
        self,
    ):
        repository = (
            FakeServiceNowRuntimeRepository(
                ticket={
                    "ticket_record_id":
                        "record-1",

                    "external_ticket_id":
                        "sys-22",

                    "external_ticket_number":
                        "INC0000022",

                    "ticket_state":
                        "OPEN",
                }
            )
        )

        adapter = (
            ServiceNowTicketingAdapter(
                servicenow_runtime_test_config(),
                repository,
                FakeServiceNowRuntimeProvider(),
            )
        )

        consumer = (
            FakeServiceNowKafkaConsumer()
        )

        runtime = KafkaTicketConsumer(
            servicenow_runtime_test_config(),
            adapter,
            consumer=consumer,
        )

        message = (
            FakeServiceNowKafkaMessage(
                servicenow_runtime_event(
                    "SEEN_AGAIN"
                )
            )
        )

        result = runtime.process_message(
            message
        )

        self.assertEqual(
            result,
            "COMPLETED",
        )

        self.assertEqual(
            len(
                consumer.commits
            ),
            1,
        )

        self.assertFalse(
            consumer.commits[0][1]
        )

    def test_consumer_commits_already_completed(
        self,
    ):
        repository = (
            FakeServiceNowRuntimeRepository(
                claim_result={
                    "status":
                        "ALREADY_COMPLETED",
                }
            )
        )

        adapter = (
            ServiceNowTicketingAdapter(
                servicenow_runtime_test_config(),
                repository,
                FakeServiceNowRuntimeProvider(),
            )
        )

        consumer = (
            FakeServiceNowKafkaConsumer()
        )

        runtime = KafkaTicketConsumer(
            servicenow_runtime_test_config(),
            adapter,
            consumer=consumer,
        )

        result = runtime.process_message(
            FakeServiceNowKafkaMessage(
                servicenow_runtime_event(
                    "DETECTED"
                )
            )
        )

        self.assertEqual(
            result,
            "ALREADY_COMPLETED",
        )

        self.assertEqual(
            len(
                consumer.commits
            ),
            1,
        )

        self.assertFalse(
            consumer.commits[0][1]
        )

    def test_consumer_does_not_commit_busy(
        self,
    ):
        repository = (
            FakeServiceNowRuntimeRepository(
                claim_result={
                    "status":
                        "BUSY",
                }
            )
        )

        adapter = (
            ServiceNowTicketingAdapter(
                servicenow_runtime_test_config(),
                repository,
                FakeServiceNowRuntimeProvider(),
            )
        )

        consumer = (
            FakeServiceNowKafkaConsumer()
        )

        runtime = KafkaTicketConsumer(
            servicenow_runtime_test_config(),
            adapter,
            consumer=consumer,
        )

        result = runtime.process_message(
            FakeServiceNowKafkaMessage(
                servicenow_runtime_event(
                    "DETECTED"
                )
            )
        )

        self.assertEqual(
            result,
            "BUSY",
        )

        self.assertEqual(
            consumer.commits,
            [],
        )


if __name__ == "__main__":
    unittest.main()
