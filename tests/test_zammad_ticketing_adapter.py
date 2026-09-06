import json
import unittest

from scripts.ticketing_runtime_common import (
    DatabaseConfig,
)
from scripts.zammad_ticketing_adapter import (
    AdapterConfig,
    KafkaTicketConsumer,
    ZammadClient,
    ZammadTicketingAdapter,
    deterministic_ticket_record_id,
)


def config():
    return AdapterConfig(
        database=DatabaseConfig(
            host="db",
            port=5432,
            database="network_compliance",
            user="adapter",
            password="db-secret",
        ),
        bootstrap_servers="kafka:9092",
        topic=
            "network.compliance.lifecycle.events",
        consumer_group=
            "zammad-network-compliance-production-v1",
        instance_id="adapter-1",
        lease_seconds=300,
        poll_seconds=5,
        zammad_base_url=
            "http://zammad-nginx.zammad.svc.cluster.local:8080",
        zammad_token="api-secret",
        zammad_customer=
            "automation@example.invalid",
        target_group_id=2,
        new_state_id=1,
        open_state_id=2,
        closed_state_id=4,
    )


def event(
    event_type,
    event_id=1,
    finding_id="finding-1",
):
    return {
        "source_event_id": event_id,
        "finding_id": finding_id,
        "run_id": "run-1",
        "lifecycle_event_type": event_type,
        "event_time":
            "2026-09-06T00:00:00Z",
        "old_status": None,
        "new_status": "OPEN",
        "event_details": {},
        "finding_snapshot": {},
    }


class FakeRepository:
    def __init__(
        self,
        claim_result=None,
        ticket=None,
    ):
        self.claim_result = (
            claim_result
            if claim_result is not None
            else {"status": "CLAIMED"}
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
                "COMPLETED"
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
            "status": "FAILED"
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


class FakeZammad:
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
            else {
                "id": 101,
                "number": "5101",
            }
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

    def update_state(
        self,
        external_id,
        state_id,
    ):
        self.calls.append(
            (
                "update_state",
                external_id,
                state_id,
            )
        )

        if self.fail_update:
            raise RuntimeError(
                "remote failure"
            )

        return {
            "id": external_id,
            "number": "5101",
            "state_id": state_id,
        }


class FakeMessage:
    def __init__(self, payload):
        self.payload = payload

    def error(self):
        return None

    def value(self):
        return json.dumps(
            self.payload
        ).encode("utf-8")


class FakeConsumer:
    def __init__(self):
        self.commits = []
        self.subscriptions = []

    def subscribe(self, topics):
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

    def close(self):
        pass


class AdapterTests(unittest.TestCase):
    def test_deterministic_record_id(self):
        self.assertEqual(
            deterministic_ticket_record_id(
                "abc"
            ),
            deterministic_ticket_record_id(
                "abc"
            ),
        )

    def test_detected_searches_before_create(self):
        repo = FakeRepository()
        zammad = FakeZammad()

        adapter = ZammadTicketingAdapter(
            config(),
            repo,
            zammad,
        )

        adapter.process_event(
            event("DETECTED")
        )

        self.assertEqual(
            [
                item[0]
                for item in zammad.calls
            ],
            [
                "search",
                "create",
            ],
        )

    def test_detected_remote_search_avoids_duplicate_create(self):
        repo = FakeRepository()

        zammad = FakeZammad(
            search_result={
                "id": 22,
                "number": "5022",
            }
        )

        adapter = ZammadTicketingAdapter(
            config(),
            repo,
            zammad,
        )

        adapter.process_event(
            event("DETECTED")
        )

        self.assertEqual(
            [
                item[0]
                for item in zammad.calls
            ],
            [
                "search",
            ],
        )

    def test_detected_existing_active_record_avoids_remote_mutation(self):
        repo = FakeRepository(
            ticket={
                "ticket_record_id":
                    "record-1",
                "external_ticket_id":
                    "22",
                "external_ticket_number":
                    "5022",
                "ticket_state":
                    "OPEN",
            }
        )

        zammad = FakeZammad()

        adapter = ZammadTicketingAdapter(
            config(),
            repo,
            zammad,
        )

        adapter.process_event(
            event("DETECTED")
        )

        self.assertEqual(
            zammad.calls,
            [],
        )

    def test_seen_again_has_no_external_mutation(self):
        repo = FakeRepository(
            ticket={
                "ticket_record_id":
                    "record-1",
                "external_ticket_id":
                    "22",
                "ticket_state":
                    "OPEN",
            }
        )

        zammad = FakeZammad()

        adapter = ZammadTicketingAdapter(
            config(),
            repo,
            zammad,
        )

        adapter.process_event(
            event("SEEN_AGAIN")
        )

        self.assertEqual(
            zammad.calls,
            [],
        )

    def test_reopened_updates_same_ticket_to_open(self):
        repo = FakeRepository(
            ticket={
                "ticket_record_id":
                    "record-1",
                "external_ticket_id":
                    "22",
                "external_ticket_number":
                    "5022",
                "ticket_state":
                    "CLOSED",
            }
        )

        zammad = FakeZammad()

        adapter = ZammadTicketingAdapter(
            config(),
            repo,
            zammad,
        )

        adapter.process_event(
            event("REOPENED")
        )

        self.assertIn(
            (
                "update_state",
                "22",
                2,
            ),
            zammad.calls,
        )

    def test_resolved_updates_same_ticket_to_closed(self):
        repo = FakeRepository(
            ticket={
                "ticket_record_id":
                    "record-1",
                "external_ticket_id":
                    "22",
                "external_ticket_number":
                    "5022",
                "ticket_state":
                    "OPEN",
            }
        )

        zammad = FakeZammad()

        adapter = ZammadTicketingAdapter(
            config(),
            repo,
            zammad,
        )

        adapter.process_event(
            event("RESOLVED")
        )

        self.assertIn(
            (
                "update_state",
                "22",
                4,
            ),
            zammad.calls,
        )

    def test_completed_receipt_skips_remote_mutation(self):
        repo = FakeRepository(
            claim_result={
                "status":
                    "ALREADY_COMPLETED"
            }
        )

        zammad = FakeZammad()

        result = ZammadTicketingAdapter(
            config(),
            repo,
            zammad,
        ).process_event(
            event("DETECTED")
        )

        self.assertEqual(
            result,
            "ALREADY_COMPLETED",
        )

        self.assertEqual(
            zammad.calls,
            [],
        )

    def test_remote_failure_marks_receipt_failed(self):
        repo = FakeRepository(
            ticket={
                "ticket_record_id":
                    "record-1",
                "external_ticket_id":
                    "22",
                "ticket_state":
                    "OPEN",
            }
        )

        zammad = FakeZammad(
            fail_update=True
        )

        adapter = ZammadTicketingAdapter(
            config(),
            repo,
            zammad,
        )

        with self.assertRaises(
            RuntimeError
        ):
            adapter.process_event(
                event("RESOLVED")
            )

        self.assertEqual(
            repo.calls[-1][0],
            "fail",
        )

    def test_consumer_commits_only_completed(self):
        repo = FakeRepository(
            ticket={
                "ticket_record_id":
                    "record-1",
                "external_ticket_id":
                    "22",
                "ticket_state":
                    "OPEN",
            }
        )

        adapter = ZammadTicketingAdapter(
            config(),
            repo,
            FakeZammad(),
        )

        consumer = FakeConsumer()

        runtime = KafkaTicketConsumer(
            config(),
            adapter,
            consumer=consumer,
        )

        message = FakeMessage(
            event("SEEN_AGAIN")
        )

        runtime.process_message(
            message
        )

        self.assertEqual(
            len(consumer.commits),
            1,
        )

        self.assertFalse(
            consumer.commits[0][1]
        )

    def test_consumer_does_not_commit_busy_receipt(self):
        repo = FakeRepository(
            claim_result={
                "status": "BUSY"
            }
        )

        adapter = ZammadTicketingAdapter(
            config(),
            repo,
            FakeZammad(),
        )

        consumer = FakeConsumer()

        runtime = KafkaTicketConsumer(
            config(),
            adapter,
            consumer=consumer,
        )

        result = runtime.process_message(
            FakeMessage(
                event("DETECTED")
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

    def test_zammad_authorization_header(self):
        client = ZammadClient(
            "http://zammad",
            "secret-token",
            "customer",
            2,
            1,
            2,
            4,
            transport=object(),
        )

        self.assertEqual(
            client._headers()[
                "Authorization"
            ],
            "Token token=secret-token",
        )


if __name__ == "__main__":
    unittest.main()
