#!/usr/bin/env python3

"""
Build one canonical V3 compliance activation event from one
durable PostgreSQL activation-source record.

This adapter deliberately owns no PostgreSQL, AWX, lifecycle
persistence, or Kafka behavior.

durable activation source
    |
    v
canonical V3 activation event
"""

from __future__ import annotations

import json
import sys
from typing import Any

try:
    from scripts.v3_compliance_event import (
        build_event,
        validate_event,
    )
    from scripts.v3_target_contract import (
        V3ContractError,
    )
except ModuleNotFoundError:
    from v3_compliance_event import (
        build_event,
        validate_event,
    )
    from v3_target_contract import (
        V3ContractError,
    )


SOURCE_FIELDS = frozenset(
    {
        "finding_event_id",
        "run_id",
        "finding_id",
        "lifecycle_event_type",
        "activated_at",
        "finding_snapshot",
        "resolved_target",
    }
)


class ActivationEventAdapterError(
    V3ContractError
):
    pass


def _require_mapping(
    value: Any,
    field: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ActivationEventAdapterError(
            f"{field} must be a mapping"
        )

    return value


def _require_nonempty_string(
    value: Any,
    field: str,
) -> str:
    if not isinstance(value, str):
        raise ActivationEventAdapterError(
            f"{field} must be a string"
        )

    result = value.strip()

    if not result:
        raise ActivationEventAdapterError(
            f"{field} must not be empty"
        )

    return result


def _require_positive_integer(
    value: Any,
    field: str,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value <= 0
    ):
        raise ActivationEventAdapterError(
            f"{field} must be a positive integer"
        )

    return value


def build_activation_event(
    source: dict[str, Any],
) -> dict[str, Any]:
    source = _require_mapping(
        source,
        "activation_source",
    )

    keys = set(source)

    missing = SOURCE_FIELDS - keys

    if missing:
        raise ActivationEventAdapterError(
            "activation_source missing required fields: "
            + ", ".join(sorted(missing))
        )

    unknown = keys - SOURCE_FIELDS

    if unknown:
        raise ActivationEventAdapterError(
            "activation_source contains unsupported fields: "
            + ", ".join(sorted(unknown))
        )

    _require_positive_integer(
        source["finding_event_id"],
        "finding_event_id",
    )

    run_id = _require_nonempty_string(
        source["run_id"],
        "run_id",
    )

    finding_id = _require_nonempty_string(
        source["finding_id"],
        "finding_id",
    )

    lifecycle_event_type = (
        _require_nonempty_string(
            source["lifecycle_event_type"],
            "lifecycle_event_type",
        )
    )

    activated_at = _require_nonempty_string(
        source["activated_at"],
        "activated_at",
    )

    finding_snapshot = _require_mapping(
        source["finding_snapshot"],
        "finding_snapshot",
    )

    resolved_target = _require_mapping(
        source["resolved_target"],
        "resolved_target",
    )

    snapshot_finding_id = (
        finding_snapshot.get("finding_id")
    )

    if snapshot_finding_id != finding_id:
        raise ActivationEventAdapterError(
            "finding_snapshot.finding_id does not "
            "match activation source finding_id"
        )

    event = build_event(
        compliance_run_id=run_id,
        lifecycle_event_type=
            lifecycle_event_type,
        activated_at=activated_at,
        finding=finding_snapshot,
        resolved_target=resolved_target,
    )

    if not isinstance(event, dict):
        raise ActivationEventAdapterError(
            "V3 event builder did not return an event"
        )

    if (
        event["finding"]["finding_id"]
        != finding_id
    ):
        raise ActivationEventAdapterError(
            "canonical event finding identity changed"
        )

    if event["compliance_run_id"] != run_id:
        raise ActivationEventAdapterError(
            "canonical event run identity changed"
        )

    validate_event(event)

    return event


def main() -> int:
    try:
        source = json.load(sys.stdin)

        event = build_activation_event(
            source
        )

    except Exception as exc:
        print(
            "v3_activation_event_adapter_result="
            "FAIL "
            + str(exc),
            file=sys.stderr,
        )

        return 1

    print(
        json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
