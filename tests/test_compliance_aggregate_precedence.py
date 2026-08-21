#!/usr/bin/env python3

from pathlib import Path

import yaml


path = Path("playbooks/compliance_aggregate.yml")

document = yaml.safe_load(path.read_text())

assert isinstance(document, list), (
    "Playbook root must be a list"
)

assert len(document) == 1, (
    "Expected exactly one play"
)

play = document[0]

tasks = play.get("tasks") or []


# ---------------------------------------------------------
# 1. Generated run must use an internal variable.
#
# AWX can propagate compliance_run from an earlier workflow
# node as an extra var. Extra vars have higher precedence
# than set_fact, so the internal build variable must not be
# named compliance_run.
# ---------------------------------------------------------

build_tasks = [
    task
    for task in tasks
    if task.get("name") == "Build structured compliance run"
]

assert len(build_tasks) == 1, (
    "Expected exactly one structured compliance-run build task"
)

build_task = build_tasks[0]

facts = (
    build_task.get("ansible.builtin.set_fact")
    or {}
)

assert "aggregated_compliance_run" in facts, (
    "Generated run must use isolated variable "
    "aggregated_compliance_run"
)

assert "compliance_run" not in facts, (
    "Build task must not set_fact compliance_run because "
    "AWX may provide compliance_run as a higher-precedence "
    "workflow extra var"
)


# ---------------------------------------------------------
# 2. Collect every set_stats publisher.
# ---------------------------------------------------------

set_stats_tasks = []

for task in tasks:
    stats = task.get("ansible.builtin.set_stats")

    if not isinstance(stats, dict):
        continue

    data = stats.get("data")

    if not isinstance(data, dict):
        continue

    set_stats_tasks.append(
        {
            "name": task.get("name"),
            "data": data,
        }
    )


assert set_stats_tasks, (
    "No set_stats publishers found"
)


# ---------------------------------------------------------
# 3. compliance_run must have exactly one publisher and
#    must publish aggregated_compliance_run, not the stale
#    inherited compliance_run value.
# ---------------------------------------------------------

run_publishers = [
    item
    for item in set_stats_tasks
    if "compliance_run" in item["data"]
]

assert len(run_publishers) == 1, (
    "Expected exactly one set_stats publisher for "
    f"compliance_run; found {len(run_publishers)}"
)

run_expression = str(
    run_publishers[0]["data"]["compliance_run"]
)

assert "aggregated_compliance_run" in run_expression, (
    "Published compliance_run must come from "
    "aggregated_compliance_run"
)

assert run_expression.strip() != "compliance_run", (
    "Published compliance_run must not resolve back to the "
    "possibly inherited compliance_run variable"
)


# ---------------------------------------------------------
# 4. Validate the PUBLIC workflow contract across ALL
#    set_stats tasks, not only the compliance_run publisher.
# ---------------------------------------------------------

all_published_keys = set()

for item in set_stats_tasks:
    all_published_keys.update(
        item["data"].keys()
    )


required_public_keys = {
    "compliance_run",
    "compliance_job_id",
    "aggregator_job_id",
    "workflow_job_id",
}

missing = (
    required_public_keys
    - all_published_keys
)

assert not missing, (
    "Compliance aggregation workflow contract is missing: "
    + ", ".join(sorted(missing))
)


# ---------------------------------------------------------
# 5. Each correlation artifact should have exactly one
#    publisher.
# ---------------------------------------------------------

for key in [
    "compliance_job_id",
    "aggregator_job_id",
    "workflow_job_id",
]:
    publishers = [
        item
        for item in set_stats_tasks
        if key in item["data"]
    ]

    assert len(publishers) == 1, (
        f"Expected exactly one publisher for {key}; "
        f"found {len(publishers)}"
    )


# ---------------------------------------------------------
# 6. Validate correlation expressions.
# ---------------------------------------------------------

def published_expression(key):
    for item in set_stats_tasks:
        if key in item["data"]:
            return str(item["data"][key])

    raise AssertionError(
        f"No publisher found for {key}"
    )


compliance_expr = published_expression(
    "compliance_job_id"
)

aggregator_expr = published_expression(
    "aggregator_job_id"
)

workflow_expr = published_expression(
    "workflow_job_id"
)


assert "compliance_job_id" in compliance_expr, (
    "Published compliance_job_id must preserve the "
    "inherited compliance/recheck job correlation"
)

assert "awx_job_id" in aggregator_expr, (
    "aggregator_job_id must identify the current "
    "aggregator AWX job"
)

assert "awx_workflow_job_id" in workflow_expr, (
    "workflow_job_id must identify the current "
    "AWX workflow"
)


print("build_variable_isolated=PASS")
print("single_compliance_run_publisher=PASS")
print("published_from_isolated_variable=PASS")
print("public_contract_preserved=PASS")
print("correlation_publishers_unique=PASS")
print("correlation_expressions_valid=PASS")
print("compliance_aggregate_precedence_test=PASS")
