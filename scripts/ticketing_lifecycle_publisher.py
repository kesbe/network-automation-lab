#!/usr/bin/env python3

"""
Independent lifecycle-event publisher.

Reads ticket-required lifecycle events through migration-016 APIs and
publishes them to network.compliance.lifecycle.events.

No direct compliance-table DML is permitted.
"""

from __future__ import annotations

import argparse
import os
import socket
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from scripts.ticketing_runtime_common import (
    DatabaseConfig,
    RuntimeConfigurationError,
    SecurityDefinerDatabaseClient,
    canonical_json_bytes,
    normalize_event_row,
    redact_text,
    require_claim_disposition,
    require_positive_int,
    require_value,
)


DEFAULT_TOPIC = "network.compliance.lifecycle.events"


@dataclass(frozen=True)
class PublisherConfig:
    database: DatabaseConfig
    bootstrap_servers: str
    topic: str
    instance_id: str
    batch_limit: int
    lease_seconds: int
    delivery_timeout_seconds: int

    @classmethod
    def from_environment(
        cls,
        env: Optional[Mapping[str, str]] = None,
    ) -> "PublisherConfig":
        source = os.environ if env is None else env

        topic = require_value(
            source,
            "TICKETING_LIFECYCLE_TOPIC",
            DEFAULT_TOPIC,
        )

        if topic != DEFAULT_TOPIC:
            raise RuntimeConfigurationError(
                "TICKETING_LIFECYCLE_TOPIC must be "
                + DEFAULT_TOPIC
            )

        return cls(
            database=DatabaseConfig.from_environment(
                source
            ),
            bootstrap_servers=require_value(
                source,
                "TICKETING_KAFKA_BOOTSTRAP_SERVERS",
            ),
            topic=topic,
            instance_id=require_value(
                source,
                "TICKETING_PUBLISHER_INSTANCE_ID",
                socket.gethostname(),
            ),
            batch_limit=require_positive_int(
                source,
                "TICKETING_PUBLISH_BATCH_LIMIT",
                default=100,
            ),
            lease_seconds=require_positive_int(
                source,
                "TICKETING_PUBLISH_LEASE_SECONDS",
                default=300,
            ),
            delivery_timeout_seconds=require_positive_int(
                source,
                "TICKETING_KAFKA_DELIVERY_TIMEOUT_SECONDS",
                default=30,
            ),
        )


class LifecyclePublicationRepository:
    def __init__(
        self,
        database: SecurityDefinerDatabaseClient,
    ) -> None:
        self.database = database

    def read_unpublished(
        self,
        topic: str,
        limit: int,
        run_id: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        if run_id is None:
            return self.database.fetch_rows(
                "read_unpublished_ticket_lifecycle_events",
                (
                    topic,
                    limit,
                ),
            )

        return self.database.fetch_rows(
            "read_unpublished_ticket_lifecycle_events_for_run",
            (
                topic,
                run_id,
                limit,
            ),
        )

    def claim(
        self,
        topic: str,
        source_event_id: int,
        instance_id: str,
        lease_seconds: int,
    ) -> Any:
        return self.database.fetch_json(
            "claim_lifecycle_event_publication",
            (
                topic,
                source_event_id,
                instance_id,
                lease_seconds,
                {},
            ),
        )

    def complete(
        self,
        topic: str,
        source_event_id: int,
        instance_id: str,
    ) -> Any:
        return self.database.fetch_json(
            "complete_lifecycle_event_publication",
            (
                topic,
                source_event_id,
                instance_id,
            ),
        )

    def fail(
        self,
        topic: str,
        source_event_id: int,
        instance_id: str,
        error: str,
    ) -> Any:
        return self.database.fetch_json(
            "fail_lifecycle_event_publication",
            (
                topic,
                source_event_id,
                instance_id,
                error,
            ),
        )


class KafkaJsonPublisher:
    def __init__(
        self,
        bootstrap_servers: str,
        delivery_timeout_seconds: int,
        producer: Optional[Any] = None,
    ) -> None:
        self.delivery_timeout_seconds = (
            delivery_timeout_seconds
        )

        if producer is None:
            from confluent_kafka import Producer

            producer = Producer(
                {
                    "bootstrap.servers":
                        bootstrap_servers,
                    "enable.idempotence": True,
                    "acks": "all",
                    "max.in.flight.requests.per.connection":
                        5,
                    "delivery.timeout.ms":
                        delivery_timeout_seconds
                        * 1000,
                }
            )

        self.producer = producer

    def publish(
        self,
        topic: str,
        key: str,
        value: Mapping[str, Any],
    ) -> None:
        delivered = {
            "done": False,
            "error": None,
        }

        def callback(error: Any, _message: Any) -> None:
            delivered["done"] = True
            delivered["error"] = error

        self.producer.produce(
            topic,
            key=key.encode("utf-8"),
            value=canonical_json_bytes(value),
            on_delivery=callback,
        )

        remaining = self.producer.flush(
            self.delivery_timeout_seconds
        )

        if remaining != 0:
            raise RuntimeError(
                "Kafka delivery did not complete "
                "before timeout"
            )

        if not delivered["done"]:
            raise RuntimeError(
                "Kafka delivery callback was not observed"
            )

        if delivered["error"] is not None:
            raise RuntimeError(
                "Kafka delivery failed: "
                + str(delivered["error"])
            )


class LifecyclePublisher:
    def __init__(
        self,
        config: PublisherConfig,
        repository: LifecyclePublicationRepository,
        transport: KafkaJsonPublisher,
    ) -> None:
        self.config = config
        self.repository = repository
        self.transport = transport

    def process_event(
        self,
        source_row: Mapping[str, Any],
    ) -> str:
        event = normalize_event_row(
            source_row
        )

        claim = self.repository.claim(
            self.config.topic,
            event["source_event_id"],
            self.config.instance_id,
            self.config.lease_seconds,
        )

        disposition = require_claim_disposition(
            claim
        )

        if disposition == "SKIPPED":
            return "ALREADY_SKIPPED"

        if disposition == "COMPLETED":
            return "ALREADY_COMPLETED"

        if disposition == "BUSY":
            return "BUSY"

        try:
            self.transport.publish(
                self.config.topic,
                event["finding_id"],
                event,
            )

        except Exception as exc:
            safe_error = redact_text(
                exc,
                (
                    self.config.database.password,
                ),
            )

            self.repository.fail(
                self.config.topic,
                event["source_event_id"],
                self.config.instance_id,
                safe_error,
            )

            raise

        self.repository.complete(
            self.config.topic,
            event["source_event_id"],
            self.config.instance_id,
        )

        return "COMPLETED"

    def run_once(
        self,
        run_id: Optional[str] = None,
    ) -> dict[str, int]:
        counters = {
            "read": 0,
            "completed": 0,
            "already_completed": 0,
            "already_skipped": 0,
            "busy": 0,
            "failed": 0,
        }

        rows = self.repository.read_unpublished(
            self.config.topic,
            self.config.batch_limit,
            run_id,
        )

        counters["read"] = len(rows)

        for row in rows:
            try:
                result = self.process_event(
                    row
                )

                if result == "COMPLETED":
                    counters["completed"] += 1

                elif result == "ALREADY_COMPLETED":
                    counters["already_completed"] += 1

                elif result == "ALREADY_SKIPPED":
                    counters["already_skipped"] += 1

                elif result == "BUSY":
                    counters["busy"] += 1

            except Exception:
                counters["failed"] += 1

        return counters


def build_runtime(
    config: PublisherConfig,
) -> LifecyclePublisher:
    database = SecurityDefinerDatabaseClient(
        config.database
    )

    repository = LifecyclePublicationRepository(
        database
    )

    transport = KafkaJsonPublisher(
        config.bootstrap_servers,
        config.delivery_timeout_seconds,
    )

    return LifecyclePublisher(
        config,
        repository,
        transport,
    )


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--once",
        action="store_true",
        help="process one database batch and exit",
    )

    args = parser.parse_args()

    if not args.once:
        parser.error(
            "only --once execution is supported"
        )

    config = PublisherConfig.from_environment()

    publish_run_id = os.environ.get(
        "TICKETING_PUBLISH_RUN_ID"
    )

    if publish_run_id is not None:
        publish_run_id = require_value(
            os.environ,
            "TICKETING_PUBLISH_RUN_ID",
        )

    result = build_runtime(
        config
    ).run_once(
        run_id=publish_run_id,
    )

    print(
        "publisher_result="
        + ",".join(
            f"{key}:{value}"
            for key, value
            in sorted(
                result.items()
            )
        )
    )

    return (
        0
        if result["failed"] == 0
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
