#!/usr/bin/env python3

"""
Kafka -> Zammad ticketing adapter.

Consumer offsets are committed manually and only after the migration-016
Zammad receipt has been completed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from scripts.ticketing_runtime_common import (
    DatabaseConfig,
    RuntimeConfigurationError,
    RuntimeContractError,
    SecurityDefinerDatabaseClient,
    normalize_event_row,
    redact_text,
    require_claim_disposition,
    require_positive_int,
    require_value,
)


DEFAULT_TOPIC = "network.compliance.lifecycle.events"

DEFAULT_GROUP = "zammad-network-compliance-production-v1"

DEFAULT_ZAMMAD_URL = (
    "http://zammad-nginx.zammad.svc.cluster.local:8080"
)


@dataclass(frozen=True)
class AdapterConfig:
    database: DatabaseConfig
    bootstrap_servers: str
    topic: str
    consumer_group: str
    instance_id: str
    lease_seconds: int
    poll_seconds: int
    zammad_base_url: str
    zammad_token: str
    zammad_customer: str
    target_group_id: int
    new_state_id: int
    open_state_id: int
    closed_state_id: int

    @classmethod
    def from_environment(
        cls,
        env: Optional[Mapping[str, str]] = None,
    ) -> "AdapterConfig":
        source = os.environ if env is None else env

        topic = require_value(
            source,
            "TICKETING_LIFECYCLE_TOPIC",
            DEFAULT_TOPIC,
        )

        group = require_value(
            source,
            "TICKETING_ZAMMAD_CONSUMER_GROUP",
            DEFAULT_GROUP,
        )

        base_url = require_value(
            source,
            "TICKETING_ZAMMAD_BASE_URL",
            DEFAULT_ZAMMAD_URL,
        ).rstrip("/")

        if topic != DEFAULT_TOPIC:
            raise RuntimeConfigurationError(
                "TICKETING_LIFECYCLE_TOPIC must be "
                + DEFAULT_TOPIC
            )

        if group != DEFAULT_GROUP:
            raise RuntimeConfigurationError(
                "TICKETING_ZAMMAD_CONSUMER_GROUP must be "
                + DEFAULT_GROUP
            )

        if base_url != DEFAULT_ZAMMAD_URL:
            raise RuntimeConfigurationError(
                "TICKETING_ZAMMAD_BASE_URL must be "
                + DEFAULT_ZAMMAD_URL
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
            consumer_group=group,
            instance_id=require_value(
                source,
                "TICKETING_ADAPTER_INSTANCE_ID",
                socket.gethostname(),
            ),
            lease_seconds=require_positive_int(
                source,
                "TICKETING_RECEIPT_LEASE_SECONDS",
                default=300,
            ),
            poll_seconds=require_positive_int(
                source,
                "TICKETING_CONSUMER_POLL_SECONDS",
                default=5,
            ),
            zammad_base_url=base_url,
            zammad_token=require_value(
                source,
                "TICKETING_ZAMMAD_TOKEN",
            ),
            zammad_customer=require_value(
                source,
                "TICKETING_ZAMMAD_CUSTOMER",
            ),
            target_group_id=2,
            new_state_id=1,
            open_state_id=2,
            closed_state_id=4,
        )


class ZammadReceiptRepository:
    def __init__(
        self,
        database: SecurityDefinerDatabaseClient,
    ) -> None:
        self.database = database

    def claim(
        self,
        source_event_id: int,
        instance_id: str,
        lease_seconds: int,
    ) -> Any:
        return self.database.fetch_json(
            "claim_zammad_ticket_event_receipt",
            (
                source_event_id,
                instance_id,
                lease_seconds,
                {},
            ),
        )

    def complete(
        self,
        source_event_id: int,
        instance_id: str,
        ticket_record_id: Optional[str],
    ) -> Any:
        return self.database.fetch_json(
            "complete_zammad_ticket_event_receipt",
            (
                source_event_id,
                instance_id,
                ticket_record_id,
                {},
            ),
        )

    def fail(
        self,
        source_event_id: int,
        instance_id: str,
        error: str,
    ) -> Any:
        return self.database.fetch_json(
            "fail_zammad_ticket_event_receipt",
            (
                source_event_id,
                instance_id,
                error,
                {},
            ),
        )

    def read_ticket(
        self,
        finding_id: str,
    ) -> Any:
        return self.database.fetch_json(
            "read_zammad_ticket_record",
            (
                finding_id,
            ),
        )

    def upsert_ticket(
        self,
        ticket_record_id: str,
        finding_id: str,
        external_ticket_id: Optional[str],
        external_ticket_number: Optional[str],
        ticket_state: str,
        details: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        return self.database.fetch_json(
            "upsert_zammad_ticket_record",
            (
                ticket_record_id,
                finding_id,
                external_ticket_id,
                external_ticket_number,
                ticket_state,
                dict(details or {}),
            ),
        )

    def update_ticket(
        self,
        ticket_record_id: str,
        expected_state: str,
        new_state: str,
        external_ticket_id: Optional[str],
        external_ticket_number: Optional[str],
        last_error: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        return self.database.fetch_json(
            "update_zammad_ticket_record",
            (
                ticket_record_id,
                expected_state,
                new_state,
                external_ticket_id,
                external_ticket_number,
                last_error,
                dict(details or {}),
            ),
        )


class UrllibJsonTransport:
    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        body = None

        if payload is not None:
            body = json.dumps(
                payload,
                separators=(",", ":"),
            ).encode("utf-8")

        request = urllib.request.Request(
            url,
            data=body,
            headers=dict(headers),
            method=method,
        )

        with urllib.request.urlopen(
            request,
            timeout=30,
        ) as response:
            raw = response.read()

        if not raw:
            return None

        return json.loads(
            raw.decode("utf-8")
        )


class ZammadClient:
    def __init__(
        self,
        base_url: str,
        token: str,
        customer: str,
        target_group_id: int,
        new_state_id: int,
        open_state_id: int,
        closed_state_id: int,
        transport: Optional[Any] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.customer = customer
        self.target_group_id = target_group_id
        self.new_state_id = new_state_id
        self.open_state_id = open_state_id
        self.closed_state_id = closed_state_id
        self.transport = (
            transport
            if transport is not None
            else UrllibJsonTransport()
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization":
                "Token token=" + self.token,
            "Content-Type":
                "application/json",
            "Accept":
                "application/json",
        }

    @staticmethod
    def correlation_marker(
        finding_id: str,
    ) -> str:
        return (
            "[network-compliance:"
            + finding_id
            + "]"
        )

    def search_ticket(
        self,
        finding_id: str,
    ) -> Optional[dict[str, Any]]:
        marker = self.correlation_marker(
            finding_id
        )

        query = urllib.parse.urlencode(
            {
                "query": marker,
            }
        )

        result = self.transport.request(
            "GET",
            self.base_url
            + "/api/v1/tickets/search?"
            + query,
            self._headers(),
        )

        candidates: list[Any]

        if isinstance(result, list):
            candidates = result

        elif isinstance(result, Mapping):
            if isinstance(
                result.get("tickets"),
                list,
            ):
                candidates = list(
                    result["tickets"]
                )

            elif isinstance(
                result.get("assets"),
                Mapping,
            ):
                assets = result["assets"]

                candidates = list(
                    (
                        assets.get(
                            "Ticket",
                            {},
                        )
                        or {}
                    ).values()
                )

            else:
                candidates = []

        else:
            candidates = []

        for candidate in candidates:
            if not isinstance(
                candidate,
                Mapping,
            ):
                continue

            title = str(
                candidate.get(
                    "title",
                    "",
                )
            )

            if marker in title:
                return dict(candidate)

        return None

    def create_ticket(
        self,
        event: Mapping[str, Any],
    ) -> dict[str, Any]:
        marker = self.correlation_marker(
            event["finding_id"]
        )

        title = (
            marker
            + " compliance finding"
        )

        body = json.dumps(
            {
                "source_event_id":
                    event["source_event_id"],
                "finding_id":
                    event["finding_id"],
                "run_id":
                    event.get("run_id"),
                "lifecycle_event_type":
                    event["lifecycle_event_type"],
                "event_time":
                    str(event.get("event_time")),
                "finding_snapshot":
                    event.get(
                        "finding_snapshot",
                        {},
                    ),
            },
            sort_keys=True,
            default=str,
        )

        payload = {
            "title": title,
            "group_id": self.target_group_id,
            "state_id": self.new_state_id,
            "customer": self.customer,
            "article": {
                "subject": title,
                "body": body,
                "type": "note",
                "internal": True,
            },
        }

        result = self.transport.request(
            "POST",
            self.base_url
            + "/api/v1/tickets",
            self._headers(),
            payload,
        )

        if not isinstance(
            result,
            Mapping,
        ):
            raise RuntimeContractError(
                "Zammad create returned invalid payload"
            )

        return dict(result)

    def update_state(
        self,
        external_ticket_id: str,
        state_id: int,
    ) -> dict[str, Any]:
        result = self.transport.request(
            "PUT",
            self.base_url
            + "/api/v1/tickets/"
            + str(external_ticket_id),
            self._headers(),
            {
                "state_id": state_id,
            },
        )

        if not isinstance(
            result,
            Mapping,
        ):
            raise RuntimeContractError(
                "Zammad update returned invalid payload"
            )

        return dict(result)


def deterministic_ticket_record_id(
    finding_id: str,
) -> str:
    digest = hashlib.sha256(
        (
            "zammad|INCIDENT|"
            + finding_id
        ).encode("utf-8")
    ).hexdigest()

    return "zammad-incident-" + digest[:32]


def _field(
    value: Any,
    *names: str,
) -> Optional[Any]:
    if not isinstance(
        value,
        Mapping,
    ):
        return None

    for name in names:
        if name in value:
            return value[name]

    return None


def ticket_record_id(
    record: Any,
) -> Optional[str]:
    value = _field(
        record,
        "ticket_record_id",
        "id",
    )

    return (
        str(value)
        if value not in (None, "")
        else None
    )


def external_ticket_id(
    record: Any,
) -> Optional[str]:
    value = _field(
        record,
        "external_ticket_id",
        "external_id",
    )

    return (
        str(value)
        if value not in (None, "")
        else None
    )


def external_ticket_number(
    record: Any,
) -> Optional[str]:
    value = _field(
        record,
        "external_ticket_number",
        "external_number",
        "number",
    )

    return (
        str(value)
        if value not in (None, "")
        else None
    )


def ticket_state(
    record: Any,
) -> Optional[str]:
    value = _field(
        record,
        "ticket_state",
        "state",
    )

    return (
        str(value).upper()
        if value not in (None, "")
        else None
    )


class ZammadTicketingAdapter:
    def __init__(
        self,
        config: AdapterConfig,
        repository: ZammadReceiptRepository,
        zammad: ZammadClient,
    ) -> None:
        self.config = config
        self.repository = repository
        self.zammad = zammad

    def _ensure_detected_ticket(
        self,
        event: Mapping[str, Any],
    ) -> str:
        existing = self.repository.read_ticket(
            event["finding_id"]
        )

        existing_id = external_ticket_id(
            existing
        )

        existing_record_id = ticket_record_id(
            existing
        )

        existing_state = ticket_state(
            existing
        )

        if (
            existing_id
            and existing_record_id
            and existing_state
            not in {"CLOSED", "RESOLVED"}
        ):
            return existing_record_id

        remote = self.zammad.search_ticket(
            event["finding_id"]
        )

        if remote is None:
            remote = self.zammad.create_ticket(
                event
            )

        remote_id = _field(
            remote,
            "id",
            "ticket_id",
        )

        remote_number = _field(
            remote,
            "number",
            "ticket_number",
        )

        if remote_id in (None, ""):
            raise RuntimeContractError(
                "Zammad ticket has no id"
            )

        record_id = (
            existing_record_id
            or deterministic_ticket_record_id(
                event["finding_id"]
            )
        )

        self.repository.upsert_ticket(
            record_id,
            event["finding_id"],
            str(remote_id),
            (
                str(remote_number)
                if remote_number not in (None, "")
                else None
            ),
            "OPEN",
            {
                "source_event_id":
                    event["source_event_id"],
                "lifecycle_event_type":
                    "DETECTED",
            },
        )

        return record_id

    def _update_existing_ticket(
        self,
        event: Mapping[str, Any],
        remote_state_id: int,
        new_local_state: str,
    ) -> str:
        record = self.repository.read_ticket(
            event["finding_id"]
        )

        record_id = ticket_record_id(
            record
        )

        remote_id = external_ticket_id(
            record
        )

        current_state = ticket_state(
            record
        )

        if not record_id or not remote_id:
            remote = self.zammad.search_ticket(
                event["finding_id"]
            )

            if remote is None:
                raise RuntimeContractError(
                    "existing Zammad ticket is required "
                    "for lifecycle state update"
                )

            remote_id_value = _field(
                remote,
                "id",
                "ticket_id",
            )

            remote_number_value = _field(
                remote,
                "number",
                "ticket_number",
            )

            if remote_id_value in (None, ""):
                raise RuntimeContractError(
                    "searched Zammad ticket has no id"
                )

            record_id = (
                record_id
                or deterministic_ticket_record_id(
                    event["finding_id"]
                )
            )

            remote_id = str(
                remote_id_value
            )

            self.repository.upsert_ticket(
                record_id,
                event["finding_id"],
                remote_id,
                (
                    str(remote_number_value)
                    if remote_number_value
                    not in (None, "")
                    else None
                ),
                current_state or "OPEN",
                {
                    "recovered_by_search": True,
                },
            )

            record = self.repository.read_ticket(
                event["finding_id"]
            )

            current_state = (
                ticket_state(record)
                or current_state
                or "OPEN"
            )

        result = self.zammad.update_state(
            remote_id,
            remote_state_id,
        )

        number = _field(
            result,
            "number",
            "ticket_number",
        )

        self.repository.update_ticket(
            record_id,
            current_state or "OPEN",
            new_local_state,
            remote_id,
            (
                str(number)
                if number not in (None, "")
                else external_ticket_number(
                    record
                )
            ),
            None,
            {
                "source_event_id":
                    event["source_event_id"],
                "lifecycle_event_type":
                    event["lifecycle_event_type"],
            },
        )

        return record_id

    def process_event(
        self,
        raw_event: Mapping[str, Any],
    ) -> str:
        source_row = {
            "source_event_id":
                raw_event.get(
                    "source_event_id"
                ),
            "source_finding_id":
                raw_event.get(
                    "finding_id"
                ),
            "run_id":
                raw_event.get("run_id"),
            "lifecycle_event_type":
                raw_event.get(
                    "lifecycle_event_type"
                ),
            "event_time":
                raw_event.get("event_time"),
            "old_status":
                raw_event.get("old_status"),
            "new_status":
                raw_event.get("new_status"),
            "event_details":
                raw_event.get(
                    "event_details",
                    {},
                ),
            "finding_snapshot":
                raw_event.get(
                    "finding_snapshot",
                    {},
                ),
        }

        event = normalize_event_row(
            source_row
        )

        claim = self.repository.claim(
            event["source_event_id"],
            self.config.instance_id,
            self.config.lease_seconds,
        )

        disposition = require_claim_disposition(
            claim
        )

        if disposition == "COMPLETED":
            return "ALREADY_COMPLETED"

        if disposition == "BUSY":
            return "BUSY"

        record_id: Optional[str] = None

        try:
            event_type = event[
                "lifecycle_event_type"
            ]

            if event_type == "DETECTED":
                record_id = (
                    self._ensure_detected_ticket(
                        event
                    )
                )

            elif event_type == "SEEN_AGAIN":
                existing = (
                    self.repository.read_ticket(
                        event["finding_id"]
                    )
                )

                record_id = ticket_record_id(
                    existing
                )

            elif event_type == "REOPENED":
                record_id = (
                    self._update_existing_ticket(
                        event,
                        self.config.open_state_id,
                        "OPEN",
                    )
                )

            elif event_type == "RESOLVED":
                record_id = (
                    self._update_existing_ticket(
                        event,
                        self.config.closed_state_id,
                        "CLOSED",
                    )
                )

            else:
                raise RuntimeContractError(
                    "unsupported lifecycle event"
                )

            self.repository.complete(
                event["source_event_id"],
                self.config.instance_id,
                record_id,
            )

            return "COMPLETED"

        except Exception as exc:
            safe_error = redact_text(
                exc,
                (
                    self.config.database.password,
                    self.config.zammad_token,
                ),
            )

            self.repository.fail(
                event["source_event_id"],
                self.config.instance_id,
                safe_error,
            )

            raise


class KafkaTicketConsumer:
    def __init__(
        self,
        config: AdapterConfig,
        adapter: ZammadTicketingAdapter,
        consumer: Optional[Any] = None,
    ) -> None:
        self.config = config
        self.adapter = adapter

        if consumer is None:
            from confluent_kafka import Consumer

            consumer = Consumer(
                {
                    "bootstrap.servers":
                        config.bootstrap_servers,
                    "group.id":
                        config.consumer_group,
                    "enable.auto.commit":
                        False,
                    "enable.auto.offset.store":
                        False,
                    "auto.offset.reset":
                        "earliest",
                }
            )

        self.consumer = consumer

    def start(self) -> None:
        self.consumer.subscribe(
            [
                self.config.topic,
            ]
        )

    def process_message(
        self,
        message: Any,
    ) -> str:
        if message.error():
            raise RuntimeError(
                str(message.error())
            )

        payload = json.loads(
            message.value().decode(
                "utf-8"
            )
        )

        result = self.adapter.process_event(
            payload
        )

        if result in {
            "COMPLETED",
            "ALREADY_COMPLETED",
        }:
            self.consumer.commit(
                message=message,
                asynchronous=False,
            )

        return result

    def poll_once(self) -> Optional[str]:
        message = self.consumer.poll(
            self.config.poll_seconds
        )

        if message is None:
            return None

        return self.process_message(
            message
        )

    def close(self) -> None:
        self.consumer.close()


def build_runtime(
    config: AdapterConfig,
) -> KafkaTicketConsumer:
    database = SecurityDefinerDatabaseClient(
        config.database
    )

    repository = ZammadReceiptRepository(
        database
    )

    zammad = ZammadClient(
        config.zammad_base_url,
        config.zammad_token,
        config.zammad_customer,
        config.target_group_id,
        config.new_state_id,
        config.open_state_id,
        config.closed_state_id,
    )

    adapter = ZammadTicketingAdapter(
        config,
        repository,
        zammad,
    )

    return KafkaTicketConsumer(
        config,
        adapter,
    )


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--max-messages",
        type=int,
        default=0,
        help=(
            "0 means continue until interrupted; "
            "positive values stop after that many polls"
        ),
    )

    args = parser.parse_args()

    config = AdapterConfig.from_environment()

    runtime = build_runtime(
        config
    )

    processed = 0

    runtime.start()

    try:
        while (
            args.max_messages <= 0
            or processed < args.max_messages
        ):
            result = runtime.poll_once()

            if result is not None:
                processed += 1

    except KeyboardInterrupt:
        pass

    except Exception as exc:
        print(
            "adapter_error="
            + redact_text(
                exc,
                (
                    config.database.password,
                    config.zammad_token,
                ),
            )
        )

        return 1

    finally:
        runtime.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
