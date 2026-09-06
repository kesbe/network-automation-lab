import unittest

from scripts.ticketing_lifecycle_publisher import (
    LifecyclePublisher,
    PublisherConfig,
)
from scripts.ticketing_runtime_common import (
    DatabaseConfig,
    RuntimeContractError,
)


def event(
    event_type="DETECTED",
    event_id=10,
    finding_id="finding-10",
):
    return {
        "source_event_id": event_id,
        "source_finding_id": finding_id,
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
        rows=None,
    ):
        self.claim_result = (
            claim_result
            if claim_result is not None
            else {"status": "CLAIMED"}
        )

        self.rows = list(
            rows or []
        )

        self.calls = []

    def read_unpublished(
        self,
        topic,
        limit,
    ):
        self.calls.append(
            (
                "read",
                topic,
                limit,
            )
        )

        return list(self.rows)

    def claim(
        self,
        topic,
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
        topic,
        source_event_id,
        instance_id,
    ):
        self.calls.append(
            (
                "complete",
                source_event_id,
            )
        )

        return {
            "status":
                "COMPLETED"
        }

    def fail(
        self,
        topic,
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


class FakeTransport:
    def __init__(
        self,
        fail=False,
    ):
        self.fail = fail
        self.messages = []

    def publish(
        self,
        topic,
        key,
        value,
    ):
        if self.fail:
            raise RuntimeError(
                "delivery failure"
            )

        self.messages.append(
            (
                topic,
                key,
                value,
            )
        )


def config():
    return PublisherConfig(
        database=DatabaseConfig(
            host="db",
            port=5432,
            database="network_compliance",
            user="publisher",
            password="secret",
        ),
        bootstrap_servers="kafka:9092",
        topic=
            "network.compliance.lifecycle.events",
        instance_id="publisher-1",
        batch_limit=100,
        lease_seconds=300,
        delivery_timeout_seconds=30,
    )


class PublisherTests(unittest.TestCase):
    def test_message_key_is_finding_id(self):
        repo = FakeRepository()
        transport = FakeTransport()

        runtime = LifecyclePublisher(
            config(),
            repo,
            transport,
        )

        runtime.process_event(
            event()
        )

        self.assertEqual(
            transport.messages[0][1],
            "finding-10",
        )

    def test_message_contains_source_event_id(self):
        repo = FakeRepository()
        transport = FakeTransport()

        LifecyclePublisher(
            config(),
            repo,
            transport,
        ).process_event(
            event()
        )

        self.assertEqual(
            transport.messages[0][2][
                "source_event_id"
            ],
            10,
        )

    def test_claim_happens_before_publish_complete(self):
        repo = FakeRepository()

        class OrderedTransport:
            def publish(
                self,
                topic,
                key,
                value,
            ):
                repo.calls.append(
                    (
                        "publish",
                        value[
                            "source_event_id"
                        ],
                    )
                )

        LifecyclePublisher(
            config(),
            repo,
            OrderedTransport(),
        ).process_event(
            event()
        )

        self.assertEqual(
            [
                item[0]
                for item in repo.calls
            ],
            [
                "claim",
                "publish",
                "complete",
            ],
        )

    def test_completed_claim_does_not_republish(self):
        repo = FakeRepository(
            claim_result={
                "status":
                    "ALREADY_COMPLETED"
            }
        )

        transport = FakeTransport()

        result = LifecyclePublisher(
            config(),
            repo,
            transport,
        ).process_event(
            event()
        )

        self.assertEqual(
            result,
            "ALREADY_COMPLETED",
        )

        self.assertEqual(
            transport.messages,
            [],
        )

    def test_busy_claim_does_not_publish(self):
        repo = FakeRepository(
            claim_result={
                "status": "BUSY"
            }
        )

        transport = FakeTransport()

        result = LifecyclePublisher(
            config(),
            repo,
            transport,
        ).process_event(
            event()
        )

        self.assertEqual(
            result,
            "BUSY",
        )

        self.assertEqual(
            transport.messages,
            [],
        )

    def test_publish_failure_marks_publication_failed(self):
        repo = FakeRepository()

        runtime = LifecyclePublisher(
            config(),
            repo,
            FakeTransport(
                fail=True
            ),
        )

        with self.assertRaises(
            RuntimeError
        ):
            runtime.process_event(
                event()
            )

        self.assertEqual(
            [
                item[0]
                for item in repo.calls
            ],
            [
                "claim",
                "fail",
            ],
        )

    def test_unknown_event_rejected_before_claim(self):
        repo = FakeRepository()

        runtime = LifecyclePublisher(
            config(),
            repo,
            FakeTransport(),
        )

        with self.assertRaises(
            RuntimeContractError
        ):
            runtime.process_event(
                event(
                    event_type="DUPLICATE"
                )
            )

        self.assertEqual(
            repo.calls,
            [],
        )

    def test_run_once_counts_completed(self):
        repo = FakeRepository(
            rows=[
                event(
                    event_id=1,
                    finding_id="f1",
                ),
                event(
                    event_id=2,
                    finding_id="f2",
                ),
            ]
        )

        result = LifecyclePublisher(
            config(),
            repo,
            FakeTransport(),
        ).run_once()

        self.assertEqual(
            result["completed"],
            2,
        )


if __name__ == "__main__":
    unittest.main()
