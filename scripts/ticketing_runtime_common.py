#!/usr/bin/env python3

"""
Shared runtime primitives for the network-compliance ticketing pipeline.

Production database access is restricted to the SECURITY DEFINER APIs
introduced by migration 016.  This module deliberately provides no direct
table-DML interface.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence


ALLOWED_LIFECYCLE_EVENTS = frozenset(
    {
        "DETECTED",
        "SEEN_AGAIN",
        "REOPENED",
        "RESOLVED",
    }
)


ALLOWED_DATABASE_FUNCTIONS = frozenset(
    {
        "read_unpublished_ticket_lifecycle_events",
        "claim_lifecycle_event_publication",
        "complete_lifecycle_event_publication",
        "fail_lifecycle_event_publication",
        "claim_zammad_ticket_event_receipt",
        "complete_zammad_ticket_event_receipt",
        "fail_zammad_ticket_event_receipt",
        "read_zammad_ticket_record",
        "upsert_zammad_ticket_record",
        "update_zammad_ticket_record",
    }
)


ACQUIRED_STATES = frozenset(
    {
        "ACQUIRED",
        "CLAIMED",
        "NEW",
        "RECLAIMED",
        "RETRY",
    }
)


COMPLETED_STATES = frozenset(
    {
        "COMPLETED",
        "ALREADY_COMPLETED",
        "DUPLICATE_COMPLETED",
    }
)


class RuntimeContractError(RuntimeError):
    """Raised when runtime data does not satisfy the frozen contract."""


class RuntimeConfigurationError(RuntimeContractError):
    """Raised for invalid or incomplete runtime configuration."""


@dataclass(frozen=True)
class DatabaseConfig:
    host: str
    port: int
    database: str
    user: str
    password: str

    @classmethod
    def from_environment(
        cls,
        env: Optional[Mapping[str, str]] = None,
    ) -> "DatabaseConfig":
        source = os.environ if env is None else env

        return cls(
            host=require_value(source, "TICKETING_DB_HOST"),
            port=require_positive_int(
                source,
                "TICKETING_DB_PORT",
                default=5432,
            ),
            database=require_value(
                source,
                "TICKETING_DB_NAME",
            ),
            user=require_value(
                source,
                "TICKETING_DB_USER",
            ),
            password=require_value(
                source,
                "TICKETING_DB_PASSWORD",
            ),
        )


def require_value(
    env: Mapping[str, str],
    name: str,
    default: Optional[str] = None,
) -> str:
    value = env.get(name, default)

    if not isinstance(value, str) or not value.strip():
        raise RuntimeConfigurationError(
            f"{name} must be a non-empty string"
        )

    return value.strip()


def require_positive_int(
    env: Mapping[str, str],
    name: str,
    default: Optional[int] = None,
) -> int:
    raw = env.get(name)

    if raw is None and default is not None:
        return default

    try:
        value = int(str(raw))
    except (TypeError, ValueError) as exc:
        raise RuntimeConfigurationError(
            f"{name} must be an integer"
        ) from exc

    if value <= 0:
        raise RuntimeConfigurationError(
            f"{name} must be greater than zero"
        )

    return value


def require_lifecycle_event_type(value: Any) -> str:
    if not isinstance(value, str):
        raise RuntimeContractError(
            "lifecycle_event_type must be a string"
        )

    normalized = value.strip().upper()

    if normalized not in ALLOWED_LIFECYCLE_EVENTS:
        raise RuntimeContractError(
            f"unsupported lifecycle event type: {normalized!r}"
        )

    return normalized


def json_default(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat()

    raise TypeError(
        f"object of type {type(value).__name__} "
        "is not JSON serializable"
    )


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=json_default,
    ).encode("utf-8")


def normalize_event_row(
    row: Mapping[str, Any],
) -> dict[str, Any]:
    required = {
        "source_event_id",
        "source_finding_id",
        "lifecycle_event_type",
    }

    missing = sorted(
        key
        for key in required
        if key not in row
    )

    if missing:
        raise RuntimeContractError(
            "missing lifecycle event fields: "
            + ",".join(missing)
        )

    event_type = require_lifecycle_event_type(
        row["lifecycle_event_type"]
    )

    source_event_id = row["source_event_id"]

    if isinstance(source_event_id, bool):
        raise RuntimeContractError(
            "source_event_id must be an integer"
        )

    try:
        source_event_id = int(source_event_id)
    except (TypeError, ValueError) as exc:
        raise RuntimeContractError(
            "source_event_id must be an integer"
        ) from exc

    finding_id = row["source_finding_id"]

    if not isinstance(finding_id, str) or not finding_id.strip():
        raise RuntimeContractError(
            "source_finding_id must be a non-empty string"
        )

    result = {
        "source_event_id": source_event_id,
        "finding_id": finding_id.strip(),
        "run_id": row.get("run_id"),
        "lifecycle_event_type": event_type,
        "event_time": row.get("event_time"),
        "old_status": row.get("old_status"),
        "new_status": row.get("new_status"),
        "event_details": row.get("event_details") or {},
        "finding_snapshot": row.get("finding_snapshot") or {},
    }

    return result


def _claim_state_value(
    result: Mapping[str, Any],
) -> Optional[str]:
    for key in (
        "state",
        "status",
        "claim_state",
        "claim_status",
        "disposition",
        "result",
        "action",
    ):
        value = result.get(key)

        if isinstance(value, str) and value.strip():
            return value.strip().upper()

    return None


def claim_is_completed(result: Any) -> bool:
    if not isinstance(result, Mapping):
        return False

    if result.get("completed") is True:
        return True

    state = _claim_state_value(result)

    return state in COMPLETED_STATES


def claim_is_acquired(result: Any) -> bool:
    if not isinstance(result, Mapping):
        return False

    if result.get("claimed") is True:
        return True

    if result.get("acquired") is True:
        return True

    state = _claim_state_value(result)

    return state in ACQUIRED_STATES


def require_claim_disposition(
    result: Any,
) -> str:
    if claim_is_completed(result):
        return "COMPLETED"

    if claim_is_acquired(result):
        return "ACQUIRED"

    if isinstance(result, Mapping):
        state = _claim_state_value(result)

        if state in {
            "BUSY",
            "LEASED",
            "NOT_ACQUIRED",
            "SKIP",
        }:
            return "BUSY"

    raise RuntimeContractError(
        "database claim API returned an unknown disposition"
    )


def redact_text(
    value: Any,
    secrets: Iterable[str] = (),
) -> str:
    text = str(value)

    for secret in secrets:
        if isinstance(secret, str) and secret:
            text = text.replace(
                secret,
                "[REDACTED]",
            )

    text = re.sub(
        r"(?i)(password|token|authorization)"
        r"\s*[:=]\s*[^\s,;]+",
        r"\1=[REDACTED]",
        text,
    )

    return text


class SecurityDefinerDatabaseClient:
    """
    Executes only the frozen migration-016 SECURITY DEFINER functions.

    Function names are selected from an immutable allow-list and therefore
    cannot be supplied as arbitrary SQL identifiers.
    """

    def __init__(
        self,
        config: DatabaseConfig,
        connect_factory: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.config = config
        self._connect_factory = connect_factory

    def _connect(self) -> Any:
        factory = self._connect_factory

        if factory is None:
            import psycopg2

            factory = psycopg2.connect

        return factory(
            host=self.config.host,
            port=self.config.port,
            dbname=self.config.database,
            user=self.config.user,
            password=self.config.password,
        )

    @staticmethod
    def _validate_function(function: str) -> str:
        if function not in ALLOWED_DATABASE_FUNCTIONS:
            raise RuntimeContractError(
                f"database function is not allowed: {function}"
            )

        return function

    def fetch_rows(
        self,
        function: str,
        parameters: Sequence[Any],
    ) -> list[dict[str, Any]]:
        function = self._validate_function(function)

        placeholders = ",".join(
            ["%s"] * len(parameters)
        )

        sql = (
            "SELECT * FROM compliance."
            + function
            + "("
            + placeholders
            + ")"
        )

        connection = self._connect()

        try:
            cursor = connection.cursor()

            try:
                cursor.execute(
                    sql,
                    tuple(parameters),
                )

                description = cursor.description or ()

                columns = [
                    column[0]
                    for column in description
                ]

                rows = [
                    dict(zip(columns, row))
                    for row in cursor.fetchall()
                ]

                connection.commit()

                return rows

            finally:
                cursor.close()

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()

    def fetch_json(
        self,
        function: str,
        parameters: Sequence[Any],
    ) -> Any:
        function = self._validate_function(function)

        placeholders = ",".join(
            ["%s"] * len(parameters)
        )

        sql = (
            "SELECT compliance."
            + function
            + "("
            + placeholders
            + ")"
        )

        connection = self._connect()

        try:
            cursor = connection.cursor()

            try:
                cursor.execute(
                    sql,
                    tuple(parameters),
                )

                row = cursor.fetchone()

                if row is None:
                    raise RuntimeContractError(
                        f"{function} returned no row"
                    )

                result = row[0]

                connection.commit()

                return result

            finally:
                cursor.close()

        except Exception:
            connection.rollback()
            raise

        finally:
            connection.close()
