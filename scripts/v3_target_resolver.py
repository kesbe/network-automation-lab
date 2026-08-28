#!/usr/bin/env python3

"""
Resolve an immutable V3 compliance target from canonical inventory data.

Input JSON:

{
  "selector": {
    "devices": ["leaf01", "leaf02"]
  },
  "inventory": [
    {
      "name": "leaf01",
      "platform": "frr",
      "vendor": "FRRouting",
      "site": "syd01",
      "role": "leaf",
      "tags": ["production"]
    }
  ]
}

Supported selector fields:

devices
site
role
platform
vendor
tags

Multiple selector dimensions use AND semantics.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

try:
    from scripts.v3_target_contract import (
        V3ContractError,
        build_resolved_target,
        canonical_device,
    )
except ModuleNotFoundError:
    from v3_target_contract import (
        V3ContractError,
        build_resolved_target,
        canonical_device,
    )


class TargetResolutionError(
    V3ContractError
):
    pass


SUPPORTED_SELECTOR_FIELDS = frozenset(
    {
        "devices",
        "site",
        "role",
        "platform",
        "vendor",
        "tags",
    }
)


def _string_list(
    value: Any,
    field: str,
) -> list[str]:
    if not isinstance(value, list):
        raise TargetResolutionError(
            f"{field} must be a list"
        )

    result = []

    for item in value:
        if (
            not isinstance(item, str)
            or not item.strip()
        ):
            raise TargetResolutionError(
                f"{field} contains invalid value"
            )

        result.append(
            item.strip()
        )

    if not result:
        raise TargetResolutionError(
            f"{field} must not be empty"
        )

    if len(result) != len(set(result)):
        raise TargetResolutionError(
            f"{field} contains duplicates"
        )

    return result


def validate_selector(
    selector: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(selector, dict):
        raise TargetResolutionError(
            "selector must be a mapping"
        )

    if not selector:
        raise TargetResolutionError(
            "selector must not be empty"
        )

    unknown = (
        set(selector)
        - SUPPORTED_SELECTOR_FIELDS
    )

    if unknown:
        raise TargetResolutionError(
            "unsupported selector fields: "
            + ", ".join(sorted(unknown))
        )

    result = {}

    if "devices" in selector:
        result["devices"] = _string_list(
            selector["devices"],
            "selector.devices",
        )

    for field in (
        "site",
        "role",
        "platform",
        "vendor",
    ):
        if field not in selector:
            continue

        value = selector[field]

        if (
            not isinstance(value, str)
            or not value.strip()
        ):
            raise TargetResolutionError(
                f"selector.{field} "
                "must be a non-empty string"
            )

        value = value.strip()

        if field == "platform":
            value = value.lower()

        result[field] = value

    if "tags" in selector:
        result["tags"] = sorted(
            _string_list(
                selector["tags"],
                "selector.tags",
            )
        )

    return result


def device_matches(
    device: dict[str, Any],
    selector: dict[str, Any],
) -> bool:
    name = device["name"]

    if (
        "devices" in selector
        and name not in selector["devices"]
    ):
        return False

    for field in (
        "site",
        "role",
        "platform",
        "vendor",
    ):
        if field not in selector:
            continue

        actual = device.get(field)

        expected = selector[field]

        if field == "platform":
            actual = (
                actual.lower()
                if isinstance(actual, str)
                else actual
            )

        if actual != expected:
            return False

    if "tags" in selector:
        device_tags = set(
            device.get("tags", [])
        )

        required_tags = set(
            selector["tags"]
        )

        if not required_tags.issubset(
            device_tags
        ):
            return False

    return True


def resolve_target(
    *,
    selector: dict[str, Any],
    inventory: list[dict[str, Any]],
) -> dict[str, Any]:
    selector = validate_selector(
        selector
    )

    if not isinstance(inventory, list):
        raise TargetResolutionError(
            "inventory must be a list"
        )

    canonical_inventory = [
        canonical_device(device)
        for device in inventory
    ]

    names = [
        device["name"]
        for device in canonical_inventory
    ]

    if len(names) != len(set(names)):
        raise TargetResolutionError(
            "inventory contains duplicate "
            "device names"
        )

    by_name = {
        device["name"]: device
        for device in canonical_inventory
    }

    if "devices" in selector:
        missing = [
            name
            for name in selector["devices"]
            if name not in by_name
        ]

        if missing:
            raise TargetResolutionError(
                "requested devices not present "
                "in inventory: "
                + ", ".join(sorted(missing))
            )

    matched = [
        device
        for device in canonical_inventory
        if device_matches(
            device,
            selector,
        )
    ]

    if not matched:
        raise TargetResolutionError(
            "selector resolved to zero devices"
        )

    if "devices" in selector:
        requested = set(
            selector["devices"]
        )

        matched_names = {
            device["name"]
            for device in matched
        }

        if matched_names != requested:
            raise TargetResolutionError(
                "explicit device selector was "
                "narrowed by conflicting selector "
                "criteria"
            )

    return build_resolved_target(
        selector=selector,
        devices=matched,
    )


def load_payload(path: str | None):
    if path:
        with open(
            path,
            "r",
            encoding="utf-8",
        ) as handle:
            return json.load(handle)

    return json.load(sys.stdin)


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        help=(
            "JSON input file. "
            "Defaults to stdin."
        ),
    )

    args = parser.parse_args()

    try:
        payload = load_payload(
            args.input
        )

        if not isinstance(
            payload,
            dict,
        ):
            raise TargetResolutionError(
                "input payload must be a mapping"
            )

        result = resolve_target(
            selector=payload.get("selector"),
            inventory=payload.get(
                "inventory"
            ),
        )

    except (
        OSError,
        json.JSONDecodeError,
        V3ContractError,
    ) as exc:
        print(
            f"target_resolution_error={exc}",
            file=sys.stderr,
        )
        return 2

    print(
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
