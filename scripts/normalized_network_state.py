#!/usr/bin/env python3

from pathlib import Path
import sys

import yaml


SCHEMA_VERSION = "1.0"


def _nonempty_string(value):
    return (
        isinstance(value, str)
        and bool(value.strip())
    )


def validate_normalized_state(state):
    """
    Validate the vendor-independent network state model.

    Returns a list of validation errors.
    An empty list means PASS.
    """

    errors = []

    if not isinstance(state, dict):
        return [
            "normalized state must be a mapping"
        ]

    if state.get("schema_version") != SCHEMA_VERSION:
        errors.append(
            "schema_version must be "
            f"{SCHEMA_VERSION!r}"
        )

    device = state.get("device")

    if not isinstance(device, dict):
        errors.append(
            "device must be a mapping"
        )
    else:
        if not _nonempty_string(
            device.get("name")
        ):
            errors.append(
                "device.name must be "
                "a non-empty string"
            )

        if not _nonempty_string(
            device.get("platform")
        ):
            errors.append(
                "device.platform must be "
                "a non-empty string"
            )

        for optional_field in (
            "vendor",
            "role",
            "site",
        ):
            value = device.get(
                optional_field
            )

            if (
                value is not None
                and not _nonempty_string(value)
            ):
                errors.append(
                    "device."
                    f"{optional_field} must be "
                    "a non-empty string when present"
                )

    system = state.get("system")

    if not isinstance(system, dict):
        errors.append(
            "system must be a mapping"
        )
    elif not _nonempty_string(
        system.get("hostname")
    ):
        errors.append(
            "system.hostname must be "
            "a non-empty string"
        )

    bgp = state.get("bgp")

    if bgp is not None:
        if not isinstance(bgp, dict):
            errors.append(
                "bgp must be a mapping"
            )
        else:
            local_as = bgp.get("local_as")

            if (
                local_as is not None
                and (
                    not isinstance(local_as, int)
                    or isinstance(local_as, bool)
                    or local_as <= 0
                )
            ):
                errors.append(
                    "bgp.local_as must be "
                    "a positive integer when present"
                )

            router_id = bgp.get("router_id")

            if (
                router_id is not None
                and not _nonempty_string(router_id)
            ):
                errors.append(
                    "bgp.router_id must be "
                    "a non-empty string when present"
                )

            ipv4 = bgp.get(
                "ipv4_unicast"
            )

            if ipv4 is not None:
                if not isinstance(ipv4, dict):
                    errors.append(
                        "bgp.ipv4_unicast "
                        "must be a mapping"
                    )
                else:
                    maximum_paths = ipv4.get(
                        "maximum_paths"
                    )

                    if (
                        maximum_paths is not None
                        and (
                            not isinstance(
                                maximum_paths,
                                int,
                            )
                            or isinstance(
                                maximum_paths,
                                bool,
                            )
                            or maximum_paths <= 0
                        )
                    ):
                        errors.append(
                            "bgp.ipv4_unicast."
                            "maximum_paths must be "
                            "a positive integer "
                            "when present"
                        )

            neighbors = bgp.get(
                "neighbors"
            )

            if neighbors is not None:
                if not isinstance(
                    neighbors,
                    list,
                ):
                    errors.append(
                        "bgp.neighbors must be "
                        "a list when present"
                    )
                elif any(
                    not isinstance(item, dict)
                    for item in neighbors
                ):
                    errors.append(
                        "bgp.neighbors entries "
                        "must be mappings"
                    )

    for collection_name in (
        "interfaces",
        "loopbacks",
    ):
        collection = state.get(
            collection_name
        )

        if collection is None:
            continue

        if not isinstance(
            collection,
            list,
        ):
            errors.append(
                f"{collection_name} must be "
                "a list when present"
            )
            continue

        if any(
            not isinstance(item, dict)
            for item in collection
        ):
            errors.append(
                f"{collection_name} entries "
                "must be mappings"
            )

    return errors


def resolve_dotted_path(
    state,
    path,
):
    """
    Resolve a static dotted path through mappings only.

    Dynamic collections such as neighbors and interfaces
    are intentionally not traversed by array index here.
    They will use policy selectors in a later milestone.
    """

    if not _nonempty_string(path):
        raise ValueError(
            "state path must be "
            "a non-empty string"
        )

    parts = path.split(".")

    if any(
        not part
        for part in parts
    ):
        raise ValueError(
            "state path contains "
            "an empty component"
        )

    current = state

    for part in parts:
        if (
            not isinstance(current, dict)
            or part not in current
        ):
            raise KeyError(path)

        current = current[part]

    return current


def load_normalized_state(path):
    with Path(path).open() as handle:
        return yaml.safe_load(handle)


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: normalized_network_state.py "
            "<state-file>",
            file=sys.stderr,
        )
        return 2

    path = Path(sys.argv[1])

    if not path.exists():
        print(
            f"ERROR: {path} does not exist",
            file=sys.stderr,
        )
        return 1

    state = load_normalized_state(path)

    errors = validate_normalized_state(
        state
    )

    if errors:
        for error in errors:
            print(
                f"ERROR: {error}",
                file=sys.stderr,
            )

        return 1

    print(
        "Normalized network state validation: PASS"
    )
    print(
        f"schema_version={state['schema_version']}"
    )
    print(
        f"device={state['device']['name']}"
    )
    print(
        f"platform={state['device']['platform']}"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
