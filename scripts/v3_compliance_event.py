#!/usr/bin/env python3

"""
Canonical V3 compliance finding activation event.

This module is intentionally independent of the accepted V2 event
builder and transport contract.

One published V3 event represents one lifecycle activation of one
durable compliance finding.

The resolved V3 target is not re-resolved or narrowed here. Its
identity is validated and preserved unchanged through the event.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

try:
    from scripts.v3_target_contract import (
        V3ContractError,
        build_resolved_target,
        validate_finding,
        validate_resolved_target,
    )
except ModuleNotFoundError:
    from v3_target_contract import (
        V3ContractError,
        build_resolved_target,
        validate_finding,
        validate_resolved_target,
    )


SCHEMA_VERSION = "3.0"

EVENT_TYPE = (
    "NETWORK_COMPLIANCE_FINDING_ACTIVATED"
)

EVENT_ID_PREFIX = "v3-compliance-event-"

PUBLISHABLE_LIFECYCLE_TYPES = {
    "DETECTED",
    "REOPENED",
}

NON_PUBLISHABLE_LIFECYCLE_TYPES = {
    "SEEN_AGAIN",
    "DUPLICATE",
}

KNOWN_LIFECYCLE_TYPES = (
    PUBLISHABLE_LIFECYCLE_TYPES
    | NON_PUBLISHABLE_LIFECYCLE_TYPES
)

EVENT_FIELDS = {
    "schema_version",
    "event_id",
    "event_type",
    "compliance_run_id",
    "lifecycle_event_type",
    "activated_at",
    "finding",
    "target",
}

FINDING_FIELDS = (
    "finding_id",
    "device",
    "vendor",
    "platform",
    "control",
    "severity",
    "status",
    "remediable",
    "remediation_policy",
    "ticket_required",
)


def _require_nonempty_string(
    value: Any,
    field: str,
) -> str:
    if not isinstance(value, str):
        raise V3ContractError(
            f"{field} must be a string"
        )

    result = value.strip()

    if not result:
        raise V3ContractError(
            f"{field} must be non-empty"
        )

    return result


def _normalize_lifecycle_event_type(
    value: Any,
) -> str:
    result = _require_nonempty_string(
        value,
        "lifecycle_event_type",
    ).upper()

    if result not in KNOWN_LIFECYCLE_TYPES:
        raise V3ContractError(
            "unsupported lifecycle_event_type: "
            + result
        )

    return result


def _canonical_timestamp(
    value: Any,
) -> str:
    raw = _require_nonempty_string(
        value,
        "activated_at",
    )

    parse_value = raw

    if raw.endswith("Z"):
        parse_value = (
            raw[:-1]
            + "+00:00"
        )

    try:
        parsed = datetime.fromisoformat(
            parse_value
        )
    except ValueError as exc:
        raise V3ContractError(
            "activated_at must be valid RFC3339"
        ) from exc

    if parsed.tzinfo is None:
        raise V3ContractError(
            "activated_at must include timezone"
        )

    canonical = (
        parsed
        .astimezone(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    return canonical


def _canonical_target(
    resolved_target: dict[str, Any],
) -> dict[str, Any]:
    validate_resolved_target(
        resolved_target
    )

    canonical = build_resolved_target(
        selector=resolved_target["selector"],
        devices=resolved_target["devices"],
    )

    if (
        canonical["target_id"]
        != resolved_target["target_id"]
    ):
        raise V3ContractError(
            "resolved target identity changed "
            "during event canonicalization"
        )

    return canonical


def _canonical_finding(
    finding: dict[str, Any],
) -> dict[str, Any]:
    validated = validate_finding(
        finding
    )

    if validated["status"] != "NON_COMPLIANT":
        raise V3ContractError(
            "activated finding must have "
            "status NON_COMPLIANT"
        )

    return {
        field: validated[field]
        for field in FINDING_FIELDS
    }


def _validate_finding_target_binding(
    finding: dict[str, Any],
    target: dict[str, Any],
) -> None:
    matching_devices = [
        device
        for device in target["devices"]
        if device["name"] == finding["device"]
    ]

    if len(matching_devices) != 1:
        raise V3ContractError(
            "finding device must identify "
            "exactly one resolved target device"
        )

    target_device = matching_devices[0]

    if (
        finding["platform"]
        != target_device["platform"]
    ):
        raise V3ContractError(
            "finding platform does not match "
            "resolved target device"
        )

    if (
        finding["vendor"]
        != target_device["vendor"]
    ):
        raise V3ContractError(
            "finding vendor does not match "
            "resolved target device"
        )


def deterministic_event_id(
    *,
    compliance_run_id: str,
    lifecycle_event_type: str,
    finding_id: str,
    target_id: str,
) -> str:
    run_id = _require_nonempty_string(
        compliance_run_id,
        "compliance_run_id",
    )

    lifecycle_type = (
        _normalize_lifecycle_event_type(
            lifecycle_event_type
        )
    )

    if (
        lifecycle_type
        not in PUBLISHABLE_LIFECYCLE_TYPES
    ):
        raise V3ContractError(
            "event identity requires an "
            "activation lifecycle event"
        )

    canonical_finding_id = (
        _require_nonempty_string(
            finding_id,
            "finding_id",
        )
    )

    canonical_target_id = (
        _require_nonempty_string(
            target_id,
            "target_id",
        )
    )

    if not canonical_target_id.startswith(
        "target-"
    ):
        raise V3ContractError(
            "target_id must start with target-"
        )

    material = {
        "event_type":
            EVENT_TYPE,

        "compliance_run_id":
            run_id,

        "lifecycle_event_type":
            lifecycle_type,

        "finding_id":
            canonical_finding_id,

        "target_id":
            canonical_target_id,
    }

    raw = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
    )

    digest = hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:32]

    return (
        EVENT_ID_PREFIX
        + digest
    )


def build_event(
    *,
    compliance_run_id: str,
    lifecycle_event_type: str,
    activated_at: str,
    finding: dict[str, Any],
    resolved_target: dict[str, Any],
) -> dict[str, Any] | None:
    lifecycle_type = (
        _normalize_lifecycle_event_type(
            lifecycle_event_type
        )
    )

    if (
        lifecycle_type
        in NON_PUBLISHABLE_LIFECYCLE_TYPES
    ):
        raise V3ContractError(
            "lifecycle_event_type does not "
            "represent a finding activation: "
            + lifecycle_type
        )

    run_id = _require_nonempty_string(
        compliance_run_id,
        "compliance_run_id",
    )

    canonical_activated_at = (
        _canonical_timestamp(
            activated_at
        )
    )

    canonical_finding = (
        _canonical_finding(
            finding
        )
    )

    canonical_target = (
        _canonical_target(
            resolved_target
        )
    )

    _validate_finding_target_binding(
        canonical_finding,
        canonical_target,
    )

    event_id = deterministic_event_id(
        compliance_run_id=run_id,
        lifecycle_event_type=lifecycle_type,
        finding_id=canonical_finding[
            "finding_id"
        ],
        target_id=canonical_target[
            "target_id"
        ],
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "event_id":
            event_id,

        "event_type":
            EVENT_TYPE,

        "compliance_run_id":
            run_id,

        "lifecycle_event_type":
            lifecycle_type,

        "activated_at":
            canonical_activated_at,

        "finding":
            canonical_finding,

        "target":
            canonical_target,
    }


def validate_event(
    event: dict[str, Any],
) -> None:
    if not isinstance(event, dict):
        raise V3ContractError(
            "event must be a mapping"
        )

    keys = set(event)

    missing = EVENT_FIELDS - keys

    if missing:
        names = ", ".join(
            sorted(missing)
        )

        raise V3ContractError(
            "event missing required fields: "
            + names
        )

    unknown = keys - EVENT_FIELDS

    if unknown:
        names = ", ".join(
            sorted(unknown)
        )

        raise V3ContractError(
            "event contains unsupported fields: "
            + names
        )

    if (
        event.get("schema_version")
        != SCHEMA_VERSION
    ):
        raise V3ContractError(
            "unsupported event schema_version"
        )

    if (
        event.get("event_type")
        != EVENT_TYPE
    ):
        raise V3ContractError(
            "unsupported event_type"
        )

    supplied_event_id = (
        _require_nonempty_string(
            event.get("event_id"),
            "event_id",
        )
    )

    if not supplied_event_id.startswith(
        EVENT_ID_PREFIX
    ):
        raise V3ContractError(
            "event_id has invalid prefix"
        )

    rebuilt = build_event(
        compliance_run_id=
            event.get("compliance_run_id"),

        lifecycle_event_type=
            event.get("lifecycle_event_type"),

        activated_at=
            event.get("activated_at"),

        finding=
            event.get("finding"),

        resolved_target=
            event.get("target"),
    )

    if rebuilt is None:
        raise V3ContractError(
            "event does not represent "
            "a publishable activation"
        )

    if (
        supplied_event_id
        != rebuilt["event_id"]
    ):
        raise V3ContractError(
            "event_id does not match "
            "canonical event identity"
        )

    if event != rebuilt:
        raise V3ContractError(
            "event does not match "
            "canonical event content"
        )
