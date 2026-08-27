#!/usr/bin/env python3

import argparse
import ipaddress
import re
from pathlib import Path
import sys

import yaml


if __package__ in (None, ""):
    sys.path.insert(
        0,
        str(
            Path(__file__)
            .resolve()
            .parents[1]
        ),
    )


from scripts.normalized_network_state import (
    SCHEMA_VERSION,
)


class FrrAdapterError(Exception):
    pass


def _address_sort_key(value):
    try:
        return (
            0,
            ipaddress.ip_address(value),
        )
    except ValueError:
        return (
            1,
            value,
        )


def _is_loopback_name(name):
    lowered = name.lower()

    return (
        lowered == "lo"
        or lowered == "loopback"
        or lowered.startswith("loopback")
    )


def parse_frr_running_config(text):
    if not isinstance(text, str):
        raise FrrAdapterError(
            "running configuration must be text"
        )

    state = {
        "hostname": None,
        "interfaces": {},
        "bgp": {
            "local_as": None,
            "router_id": None,
            "maximum_paths": None,
            "neighbors": {},
        },
    }

    current_interface = None
    in_ipv4_unicast = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        if not stripped:
            continue

        match = re.fullmatch(
            r"hostname\s+(\S+)",
            stripped,
        )

        if match:
            state["hostname"] = match.group(1)
            current_interface = None
            continue

        match = re.fullmatch(
            r"interface\s+(\S+)",
            stripped,
        )

        if match:
            current_interface = match.group(1)

            state[
                "interfaces"
            ].setdefault(
                current_interface,
                [],
            )

            continue

        match = re.fullmatch(
            r"ip address\s+(\S+)",
            stripped,
        )

        if (
            match
            and current_interface is not None
        ):
            address = match.group(1)

            state[
                "interfaces"
            ][
                current_interface
            ].append(address)

            continue

        match = re.fullmatch(
            r"router bgp\s+(\d+)",
            stripped,
        )

        if match:
            current_interface = None
            in_ipv4_unicast = False

            state[
                "bgp"
            ][
                "local_as"
            ] = int(match.group(1))

            continue

        match = re.fullmatch(
            r"bgp router-id\s+(\S+)",
            stripped,
        )

        if match:
            state[
                "bgp"
            ][
                "router_id"
            ] = match.group(1)

            continue

        match = re.fullmatch(
            r"neighbor\s+(\S+)\s+"
            r"remote-as\s+(\d+)",
            stripped,
        )

        if match:
            address = match.group(1)

            neighbor = state[
                "bgp"
            ][
                "neighbors"
            ].setdefault(
                address,
                {},
            )

            neighbor[
                "remote_as"
            ] = int(match.group(2))

            continue

        match = re.fullmatch(
            r"neighbor\s+(\S+)\s+"
            r"description\s+(.+)",
            stripped,
        )

        if match:
            address = match.group(1)

            neighbor = state[
                "bgp"
            ][
                "neighbors"
            ].setdefault(
                address,
                {},
            )

            neighbor[
                "description"
            ] = match.group(2).strip()

            continue

        if re.fullmatch(
            r"address-family\s+ipv4\s+unicast",
            stripped,
        ):
            in_ipv4_unicast = True
            continue

        if stripped == "exit-address-family":
            in_ipv4_unicast = False
            continue

        match = re.fullmatch(
            r"maximum-paths\s+(\d+)",
            stripped,
        )

        if match and in_ipv4_unicast:
            state[
                "bgp"
            ][
                "maximum_paths"
            ] = int(match.group(1))

    if not state["hostname"]:
        raise FrrAdapterError(
            "FRR hostname not found"
        )

    if state["bgp"]["local_as"] is None:
        raise FrrAdapterError(
            "FRR BGP local AS not found"
        )

    return state


def parse_frr_bgp_summary(text):
    if not isinstance(text, str):
        raise FrrAdapterError(
            "BGP summary must be text"
        )

    result = {
        "router_id": None,
        "local_as": None,
        "neighbors": {},
    }

    header_re = re.compile(
        r"^BGP router identifier\s+"
        r"(\S+),\s+local AS number\s+"
        r"(\d+)\b"
    )

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        header = header_re.match(line)

        if header:
            result["router_id"] = (
                header.group(1)
            )

            result["local_as"] = int(
                header.group(2)
            )

            continue

        if not re.match(
            r"^(?:\d{1,3}\.){3}\d{1,3}\s+",
            line,
        ):
            continue

        parts = line.split()

        if len(parts) < 11:
            raise FrrAdapterError(
                "unexpected FRR BGP summary "
                f"neighbor row: {line!r}"
            )

        address = parts[0]

        try:
            remote_as = int(parts[2])
        except ValueError as exc:
            raise FrrAdapterError(
                "invalid remote AS in FRR "
                f"BGP summary: {line!r}"
            ) from exc

        state_or_prefixes = parts[9]

        if state_or_prefixes.isdigit():
            operational_state = "Established"
        else:
            operational_state = state_or_prefixes

        description = (
            " ".join(parts[11:])
            if len(parts) > 11
            else None
        )

        neighbor = {
            "remote_as": remote_as,
            "operational_state": (
                operational_state
            ),
        }

        if description:
            neighbor[
                "description"
            ] = description

        result[
            "neighbors"
        ][
            address
        ] = neighbor

    if result["router_id"] is None:
        raise FrrAdapterError(
            "BGP summary router identifier "
            "not found"
        )

    if result["local_as"] is None:
        raise FrrAdapterError(
            "BGP summary local AS not found"
        )

    return result


def normalize_frr_state(
    running_config,
    bgp_summary,
    device_name=None,
    role=None,
    site=None,
):
    config = parse_frr_running_config(
        running_config
    )

    summary = parse_frr_bgp_summary(
        bgp_summary
    )

    config_as = config[
        "bgp"
    ][
        "local_as"
    ]

    summary_as = summary[
        "local_as"
    ]

    if config_as != summary_as:
        raise FrrAdapterError(
            "BGP local AS mismatch between "
            f"running-config ({config_as}) "
            f"and summary ({summary_as})"
        )

    config_router_id = config[
        "bgp"
    ][
        "router_id"
    ]

    summary_router_id = summary[
        "router_id"
    ]

    if (
        config_router_id is not None
        and config_router_id
        != summary_router_id
    ):
        raise FrrAdapterError(
            "BGP router-id mismatch between "
            f"running-config "
            f"({config_router_id}) and "
            f"summary ({summary_router_id})"
        )

    hostname = config["hostname"]

    if (
        device_name is not None
        and device_name != hostname
    ):
        raise FrrAdapterError(
            "requested device name does not "
            f"match FRR hostname: "
            f"{device_name!r} != {hostname!r}"
        )

    normalized = {
        "schema_version": SCHEMA_VERSION,
        "device": {
            "name": hostname,
            "platform": "frr",
            "vendor": "FRRouting",
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
        normalized[
            "device"
        ][
            "role"
        ] = role

    if site is not None:
        normalized[
            "device"
        ][
            "site"
        ] = site

    maximum_paths = config[
        "bgp"
    ][
        "maximum_paths"
    ]

    if maximum_paths is not None:
        normalized[
            "bgp"
        ][
            "ipv4_unicast"
        ][
            "maximum_paths"
        ] = maximum_paths

    for name in sorted(
        config["interfaces"]
    ):
        addresses = list(
            config[
                "interfaces"
            ][
                name
            ]
        )

        entry = {
            "name": name,
            "ipv4_addresses": addresses,
        }

        if _is_loopback_name(name):
            normalized[
                "loopbacks"
            ].append(entry)
        else:
            normalized[
                "interfaces"
            ].append(entry)

    neighbor_addresses = set(
        config[
            "bgp"
        ][
            "neighbors"
        ]
    )

    neighbor_addresses.update(
        summary[
            "neighbors"
        ]
    )

    for address in sorted(
        neighbor_addresses,
        key=_address_sort_key,
    ):
        configured = config[
            "bgp"
        ][
            "neighbors"
        ].get(
            address,
            {},
        )

        observed = summary[
            "neighbors"
        ].get(
            address,
            {},
        )

        neighbor = {
            "address": address,
        }

        remote_as = configured.get(
            "remote_as",
            observed.get("remote_as"),
        )

        if remote_as is not None:
            neighbor[
                "remote_as"
            ] = remote_as

        description = configured.get(
            "description",
            observed.get("description"),
        )

        if description is not None:
            neighbor[
                "description"
            ] = description

        neighbor[
            "operational_state"
        ] = observed.get(
            "operational_state",
            "Missing",
        )

        normalized[
            "bgp"
        ][
            "neighbors"
        ].append(neighbor)

    return normalized


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Normalize sanitized FRR state "
            "into the vendor-independent "
            "network state model."
        )
    )

    parser.add_argument(
        "--running-config",
        required=True,
    )

    parser.add_argument(
        "--bgp-summary",
        required=True,
    )

    parser.add_argument(
        "--device-name",
    )

    parser.add_argument(
        "--role",
    )

    parser.add_argument(
        "--site",
    )

    args = parser.parse_args()

    running_config = Path(
        args.running_config
    ).read_text()

    bgp_summary = Path(
        args.bgp_summary
    ).read_text()

    normalized = normalize_frr_state(
        running_config,
        bgp_summary,
        device_name=args.device_name,
        role=args.role,
        site=args.site,
    )

    print(
        yaml.safe_dump(
            normalized,
            sort_keys=False,
        ),
        end="",
    )


if __name__ == "__main__":
    main()
