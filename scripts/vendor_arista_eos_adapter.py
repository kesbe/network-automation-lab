#!/usr/bin/env python3

"""
Arista EOS -> vendor-independent normalized state adapter.

Initial V3 production slice:

- hostname
- BGP local AS
- BGP router ID
- BGP IPv4 maximum paths
"""

from __future__ import annotations

import re

from scripts.normalized_network_state import (
    SCHEMA_VERSION,
    validate_normalized_state,
)


class AristaEosAdapterError(Exception):
    pass


def _require_text(value, field):
    if not isinstance(value, str):
        raise AristaEosAdapterError(
            f"{field} must be a string"
        )

    if not value.strip():
        raise AristaEosAdapterError(
            f"{field} must not be empty"
        )

    return value


def _unique_match(
    pattern,
    text,
    field,
    *,
    required=True,
    flags=re.MULTILINE | re.IGNORECASE,
):
    matches = re.findall(
        pattern,
        text,
        flags,
    )

    values = []

    for match in matches:
        if isinstance(match, tuple):
            value = tuple(
                item.strip()
                for item in match
            )
        else:
            value = match.strip()

        if value not in values:
            values.append(value)

    if not values:
        if required:
            raise AristaEosAdapterError(
                f"{field} not found"
            )

        return None

    if len(values) != 1:
        raise AristaEosAdapterError(
            f"conflicting {field} values"
        )

    return values[0]


def parse_arista_eos_running_config(text):
    text = _require_text(
        text,
        "running_config",
    )

    hostname = _unique_match(
        r"^hostname\s+(\S+)\s*$",
        text,
        "hostname",
    )

    local_as = _unique_match(
        r"^router\s+bgp\s+(\d+)\s*$",
        text,
        "BGP local AS",
    )

    router_id = _unique_match(
        r"^\s*(?:bgp\s+)?router-id\s+"
        r"(\S+)\s*$",
        text,
        "BGP router ID",
        required=False,
    )

    maximum_paths = _unique_match(
        r"^\s*maximum-paths\s+(\d+)\s*$",
        text,
        "BGP maximum paths",
        required=False,
    )

    return {
        "hostname": hostname,
        "bgp": {
            "local_as": int(local_as),
            "router_id": router_id,
            "maximum_paths": (
                int(maximum_paths)
                if maximum_paths is not None
                else None
            ),
        },
    }


def parse_arista_eos_bgp_summary(text):
    text = _require_text(
        text,
        "bgp_summary",
    )

    result = _unique_match(
        r"(?:BGP\s+)?Router\s+identifier\s+"
        r"([^,\s]+)\s*,\s*"
        r"local\s+AS\s+number\s+(\d+)",
        text,
        "BGP summary identity",
    )

    router_id, local_as = result

    return {
        "router_id": router_id,
        "local_as": int(local_as),
    }


def normalize_arista_eos_state(
    running_config,
    bgp_summary,
    *,
    device_name=None,
    role=None,
    site=None,
):
    config = parse_arista_eos_running_config(
        running_config
    )

    summary = parse_arista_eos_bgp_summary(
        bgp_summary
    )

    hostname = config["hostname"]

    if (
        device_name is not None
        and device_name != hostname
    ):
        raise AristaEosAdapterError(
            "requested device name does not "
            "match Arista EOS hostname: "
            f"{device_name!r} != {hostname!r}"
        )

    config_as = config["bgp"]["local_as"]
    summary_as = summary["local_as"]

    if config_as != summary_as:
        raise AristaEosAdapterError(
            "BGP local AS mismatch between "
            f"running-config ({config_as}) "
            f"and summary ({summary_as})"
        )

    config_router_id = (
        config["bgp"]["router_id"]
    )

    summary_router_id = (
        summary["router_id"]
    )

    if (
        config_router_id is not None
        and config_router_id
        != summary_router_id
    ):
        raise AristaEosAdapterError(
            "BGP router-id mismatch between "
            "running-config "
            f"({config_router_id}) and "
            f"summary ({summary_router_id})"
        )

    normalized = {
        "schema_version": SCHEMA_VERSION,
        "device": {
            "name": hostname,
            "platform": "arista_eos",
            "vendor": "Arista",
        },
        "system": {
            "hostname": hostname,
        },
        "bgp": {
            "local_as": config_as,
            "router_id": (
                config_router_id
                or summary_router_id
            ),
            "ipv4_unicast": {},
            "neighbors": [],
        },
        "interfaces": [],
        "loopbacks": [],
    }

    if role is not None:
        normalized["device"]["role"] = role

    if site is not None:
        normalized["device"]["site"] = site

    maximum_paths = (
        config["bgp"]["maximum_paths"]
    )

    if maximum_paths is not None:
        normalized[
            "bgp"
        ][
            "ipv4_unicast"
        ][
            "maximum_paths"
        ] = maximum_paths

    errors = validate_normalized_state(
        normalized
    )

    if errors:
        raise AristaEosAdapterError(
            "normalized Arista EOS state "
            "validation failed: "
            + "; ".join(errors)
        )

    return normalized
