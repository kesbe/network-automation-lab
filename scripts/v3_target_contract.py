#!/usr/bin/env python3

"""
Canonical V3 target-production data contract.

This module is intentionally independent of AWX, NetBox, Kafka,
PostgreSQL and any specific network vendor.

The target is resolved once and then treated as immutable throughout:

target
 -> detector
 -> aggregator
 -> persistence
 -> event
 -> EDA
 -> remediation
 -> recheck
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


SCHEMA_VERSION = "3.0"


class V3ContractError(ValueError):
    pass


# Accept legacy aliases while emitting one canonical V3 representation.
_REMEDIATION_POLICY_ALIASES = {
    "auto": "auto",
    "automatic": "auto",
    "approval_required": "approval_required",
    "manual": "manual",
    "observe_only": "observe_only",
    "blocked": "blocked",
}


ALLOWED_REMEDIATION_POLICIES = frozenset(
    _REMEDIATION_POLICY_ALIASES.values()
)


ALLOWED_FINDING_STATUS = frozenset(
    {
        "COMPLIANT",
        "NON_COMPLIANT",
        "ERROR",
        "UNREACHABLE",
    }
)


def _require_nonempty_string(
    value: Any,
    field: str,
) -> str:
    if not isinstance(value, str):
        raise V3ContractError(
            f"{field} must be a string"
        )

    value = value.strip()

    if not value:
        raise V3ContractError(
            f"{field} must not be empty"
        )

    return value


def normalize_remediation_policy(
    value: Any,
) -> str:
    value = _require_nonempty_string(
        value,
        "remediation_policy",
    ).lower()

    canonical = _REMEDIATION_POLICY_ALIASES.get(
        value
    )

    if canonical is None:
        raise V3ContractError(
            "unsupported remediation_policy: "
            f"{value}"
        )

    return canonical


def canonical_device(
    device: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(device, dict):
        raise V3ContractError(
            "device must be a mapping"
        )

    name = _require_nonempty_string(
        device.get("name"),
        "device.name",
    )

    platform = _require_nonempty_string(
        device.get("platform"),
        "device.platform",
    ).lower()

    vendor = _require_nonempty_string(
        device.get("vendor"),
        "device.vendor",
    )

    result = {
        "name": name,
        "platform": platform,
        "vendor": vendor,
    }

    for field in (
        "site",
        "role",
    ):
        value = device.get(field)

        if value is not None:
            result[field] = _require_nonempty_string(
                value,
                f"device.{field}",
            )

    tags = device.get("tags", [])

    if not isinstance(tags, list):
        raise V3ContractError(
            "device.tags must be a list"
        )

    canonical_tags = []

    for tag in tags:
        canonical_tags.append(
            _require_nonempty_string(
                tag,
                "device.tags[]",
            )
        )

    result["tags"] = sorted(
        set(canonical_tags)
    )

    return result


def _canonicalize_selector_for_identity(
    selector: dict[str, Any],
) -> dict[str, Any]:
    """
    Return the selector representation used only for target identity.

    Selector list dimensions are set-like: their ordering must not
    produce a different target_id for the same logical target.
    """
    if not isinstance(selector, dict):
        raise V3ContractError(
            "selector must be a mapping"
        )

    normalized: dict[str, Any] = {}

    for key in sorted(selector):
        value = selector[key]

        if isinstance(value, list):
            if not all(
                isinstance(item, str)
                and item.strip()
                for item in value
            ):
                raise V3ContractError(
                    f"selector.{key} list values "
                    "must be non-empty strings"
                )

            normalized[key] = sorted(
                item.strip()
                for item in value
            )

        elif isinstance(value, str):
            normalized[key] = value.strip()

        else:
            normalized[key] = value

    return normalized


def deterministic_target_id(
    selector: dict[str, Any],
    devices: list[dict[str, Any]],
) -> str:
    material = {
        "selector":
            _canonicalize_selector_for_identity(
                selector
            ),
        "devices": sorted(
            device["name"]
            for device in devices
        ),
    }

    raw = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
    )

    digest = hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:32]

    return f"target-{digest}"


def build_resolved_target(
    *,
    selector: dict[str, Any],
    devices: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(selector, dict):
        raise V3ContractError(
            "selector must be a mapping"
        )

    if not devices:
        raise V3ContractError(
            "resolved target must contain "
            "at least one device"
        )

    canonical_devices = [
        canonical_device(device)
        for device in devices
    ]

    names = [
        device["name"]
        for device in canonical_devices
    ]

    if len(names) != len(set(names)):
        raise V3ContractError(
            "resolved target contains "
            "duplicate device names"
        )

    canonical_devices.sort(
        key=lambda item: item["name"]
    )

    target_id = deterministic_target_id(
        selector,
        canonical_devices,
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "target_id": target_id,
        "selector": selector,
        "devices": canonical_devices,
        "device_names": [
            device["name"]
            for device in canonical_devices
        ],
        "device_count": len(
            canonical_devices
        ),
    }


def validate_resolved_target(
    target: dict[str, Any],
) -> None:
    if not isinstance(target, dict):
        raise V3ContractError(
            "target must be a mapping"
        )

    if target.get("schema_version") != SCHEMA_VERSION:
        raise V3ContractError(
            "unsupported target schema_version"
        )

    target_id = _require_nonempty_string(
        target.get("target_id"),
        "target_id",
    )

    if not target_id.startswith("target-"):
        raise V3ContractError(
            "target_id must start with target-"
        )

    devices = target.get("devices")

    if not isinstance(devices, list):
        raise V3ContractError(
            "target.devices must be a list"
        )

    rebuilt = build_resolved_target(
        selector=target.get("selector"),
        devices=devices,
    )

    if rebuilt["target_id"] != target_id:
        raise V3ContractError(
            "target_id does not match "
            "resolved target content"
        )

    if (
        target.get("device_names")
        != rebuilt["device_names"]
    ):
        raise V3ContractError(
            "device_names does not match "
            "target.devices"
        )

    if (
        target.get("device_count")
        != rebuilt["device_count"]
    ):
        raise V3ContractError(
            "device_count does not match "
            "target.devices"
        )


def validate_finding(
    finding: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(finding, dict):
        raise V3ContractError(
            "finding must be a mapping"
        )

    result = dict(finding)

    for field in (
        "finding_id",
        "device",
        "vendor",
        "platform",
        "control",
        "severity",
    ):
        result[field] = _require_nonempty_string(
            finding.get(field),
            field,
        )

    result["platform"] = (
        result["platform"].lower()
    )

    status = _require_nonempty_string(
        finding.get("status"),
        "status",
    ).upper()

    if status not in ALLOWED_FINDING_STATUS:
        raise V3ContractError(
            f"unsupported finding status: {status}"
        )

    result["status"] = status

    remediable = finding.get("remediable")

    if not isinstance(remediable, bool):
        raise V3ContractError(
            "remediable must be boolean"
        )

    result["remediable"] = remediable

    result["remediation_policy"] = (
        normalize_remediation_policy(
            finding.get(
                "remediation_policy"
            )
        )
    )

    ticket_required = finding.get(
        "ticket_required"
    )

    if not isinstance(
        ticket_required,
        bool,
    ):
        raise V3ContractError(
            "ticket_required must be boolean"
        )

    result["ticket_required"] = (
        ticket_required
    )

    if (
        result["remediation_policy"]
        == "approval_required"
        and not ticket_required
    ):
        raise V3ContractError(
            "approval_required findings "
            "must have ticket_required=true"
        )

    if (
        not remediable
        and result["remediation_policy"]
        in {"auto", "approval_required"}
    ):
        raise V3ContractError(
            "non-remediable finding cannot "
            "use an executable remediation policy"
        )

    return result
