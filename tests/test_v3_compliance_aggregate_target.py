#!/usr/bin/env python3

from pathlib import Path

import yaml


PLAYBOOK = Path(
    "playbooks/compliance_aggregate.yml"
)

document = yaml.safe_load(
    PLAYBOOK.read_text()
)

assert isinstance(document, list)
assert len(document) == 1

tasks = document[0].get(
    "tasks"
) or []


def task_named(name):
    matches = [
        task
        for task in tasks
        if task.get("name") == name
    ]

    assert len(matches) == 1, (
        f"Expected exactly one task named {name!r}; "
        f"found {len(matches)}"
    )

    return matches[0]


# ---------------------------------------------------------
# 1. Inventory must be sourced from AWX/NetBox hostvars.
# ---------------------------------------------------------

validate_metadata = task_named(
    "Validate authoritative V3 target metadata"
)

validate_text = str(
    validate_metadata
)

assert "hostvars[item]" in validate_text
assert ".platform" in validate_text
assert ".manufacturer" in validate_text

metadata_loop = str(
    validate_metadata.get("loop")
)

assert "network_intent.keys()" in metadata_loop
assert "sort" in metadata_loop


build_inventory = task_named(
    "Build authoritative V3 target inventory"
)

inventory_facts = (
    build_inventory.get(
        "ansible.builtin.set_fact"
    )
    or {}
)

assert (
    "aggregated_v3_target_inventory"
    in inventory_facts
)

inventory_expression = str(
    inventory_facts[
        "aggregated_v3_target_inventory"
    ]
)

for required in (
    "hostvars[item].platform",
    "hostvars[item].manufacturer",
    "'vendor'",
    "'name'",
    "'tags'",
):
    assert required in inventory_expression, (
        f"Missing V3 inventory mapping: {required}"
    )

assert "'site'" in inventory_expression
assert "'role'" in inventory_expression


# ---------------------------------------------------------
# 2. Selector must derive from exact aggregation membership.
# ---------------------------------------------------------

resolver_input = task_named(
    "Build V3 target resolver input"
)

resolver_input_facts = (
    resolver_input.get(
        "ansible.builtin.set_fact"
    )
    or {}
)

assert (
    "aggregated_v3_target_resolver_input"
    in resolver_input_facts
)

resolver_input_expression = str(
    resolver_input_facts[
        "aggregated_v3_target_resolver_input"
    ]
)

assert "network_intent.keys()" in resolver_input_expression
assert "'devices'" in resolver_input_expression
assert "aggregated_v3_target_inventory" in resolver_input_expression


# ---------------------------------------------------------
# 3. Frozen resolver must be invoked, not reimplemented.
# ---------------------------------------------------------

resolve_task = task_named(
    "Resolve canonical V3 target"
)

command = resolve_task.get(
    "ansible.builtin.command"
)

assert isinstance(command, dict)

argv = command.get("argv")

assert isinstance(argv, list)
assert len(argv) == 2

assert "ansible_playbook_python" in str(
    argv[0]
)

assert "v3_target_resolver.py" in str(
    argv[1]
)

stdin_expression = str(
    command.get("stdin")
)

assert (
    "aggregated_v3_target_resolver_input"
    in stdin_expression
)
assert "to_json" in stdin_expression

assert (
    resolve_task.get("changed_when")
    is False
)


# ---------------------------------------------------------
# 4. Resolved target must use isolated internal variable.
# ---------------------------------------------------------

capture_task = task_named(
    "Capture canonical V3 resolved target"
)

capture_facts = (
    capture_task.get(
        "ansible.builtin.set_fact"
    )
    or {}
)

assert (
    "aggregated_v3_resolved_target"
    in capture_facts
)

assert "resolved_target" not in capture_facts
assert "v3_persistence_enabled" not in capture_facts

capture_expression = str(
    capture_facts[
        "aggregated_v3_resolved_target"
    ]
)

assert (
    "aggregated_v3_target_resolver_command.stdout"
    in capture_expression
)

assert "from_json" in capture_expression


# ---------------------------------------------------------
# 5. Exact run/target membership must be asserted.
# ---------------------------------------------------------

membership_task = task_named(
    "Validate resolved target against aggregated run membership"
)

membership_text = str(
    membership_task.get(
        "ansible.builtin.assert"
    )
)

for required in (
    "schema_version",
    "target_id",
    "selector.devices",
    "device_names",
    "device_count",
    "network_intent.keys()",
    "compliance_device_results",
):
    assert required in membership_text, (
        f"Missing membership invariant: {required}"
    )


# ---------------------------------------------------------
# 6. Public V3 artifacts have exactly one publisher.
# ---------------------------------------------------------

publishers = []

for task in tasks:
    stats = task.get(
        "ansible.builtin.set_stats"
    )

    if not isinstance(stats, dict):
        continue

    data = stats.get("data")

    if not isinstance(data, dict):
        continue

    publishers.append(
        {
            "name": task.get("name"),
            "data": data,
        }
    )


def publishers_for(key):
    return [
        item
        for item in publishers
        if key in item["data"]
    ]


resolved_publishers = publishers_for(
    "resolved_target"
)

assert len(resolved_publishers) == 1, (
    "Expected exactly one resolved_target publisher"
)

resolved_expression = str(
    resolved_publishers[0][
        "data"
    ][
        "resolved_target"
    ]
)

assert (
    "aggregated_v3_resolved_target"
    in resolved_expression
)

assert (
    resolved_expression.strip()
    != "resolved_target"
)


flag_publishers = publishers_for(
    "v3_persistence_enabled"
)

assert len(flag_publishers) == 1, (
    "Expected exactly one v3_persistence_enabled publisher"
)

flag_value = flag_publishers[0][
    "data"
][
    "v3_persistence_enabled"
]

assert flag_value is True, (
    "Production V3 activation flag must be literal true"
)


# ---------------------------------------------------------
# 7. Legacy run publication must remain intact.
# ---------------------------------------------------------

run_publishers = publishers_for(
    "compliance_run"
)

assert len(run_publishers) == 1

run_expression = str(
    run_publishers[0][
        "data"
    ][
        "compliance_run"
    ]
)

assert "aggregated_compliance_run" in run_expression


print(
    "authoritative_hostvars_mapping=PASS"
)
print(
    "exact_selector_membership=PASS"
)
print(
    "frozen_target_resolver_invocation=PASS"
)
print(
    "resolved_target_variable_isolated=PASS"
)
print(
    "run_target_membership_asserted=PASS"
)
print(
    "resolved_target_single_publisher=PASS"
)
print(
    "v3_activation_single_publisher=PASS"
)
print(
    "legacy_run_publication_preserved=PASS"
)
print(
    "v3_compliance_aggregate_target_test=PASS"
)
