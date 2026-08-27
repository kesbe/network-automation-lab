#!/usr/bin/env python3

from pathlib import Path
import re
import sys

import yaml


DEFAULT_POLICY_FILE = Path(
    "vars/compliance_policies.yml"
)

VALID_SEVERITIES = {
    "info",
    "low",
    "medium",
    "high",
    "critical",
}

VALID_REMEDIATION_MODES = {
    "report_only",
    "auto",
    "approval_required",
    "manual",
}

VALID_RISKS = {
    "low",
    "medium",
    "high",
}

# Keep the first generic comparison set intentionally narrow.
# Add more operators only when the generic policy engine implements them.
VALID_COMPARISON_OPERATORS = {
    "equals",
}

# V2.0 currently has one authoritative dynamic intent source.
# Additional sources can be introduced only with explicit implementation.
VALID_INTENT_SOURCES = {
    "netbox",
}

REQUIRED_POLICY_FIELDS = {
    "name",
    "description",
    "control",
    "category",
    "severity",
    "ticket_required",
    "remediation",
    "owner",
    "enabled",
}

V2_TOP_LEVEL_FIELDS = {
    "scope",
    "intent",
    "state",
    "comparison",
    "verification",
}

NORMALIZED_STATE_PATH_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\.[A-Za-z_][A-Za-z0-9_]*)+$"
)

ACTION_RE = re.compile(
    r"^[a-z][a-z0-9_]*$"
)


def fail(message):
    print(
        f"ERROR: {message}",
        file=sys.stderr,
    )
    sys.exit(1)


def require_mapping(
    policy_id,
    field_name,
    value,
):
    if not isinstance(value, dict):
        fail(
            f"{policy_id}: {field_name} "
            f"must be a mapping"
        )


def require_nonempty_string(
    policy_id,
    field_name,
    value,
):
    if (
        not isinstance(value, str)
        or not value.strip()
    ):
        fail(
            f"{policy_id}: {field_name} "
            f"must be a non-empty string"
        )


def require_nonempty_string_list(
    policy_id,
    field_name,
    value,
):
    if (
        not isinstance(value, list)
        or not value
    ):
        fail(
            f"{policy_id}: {field_name} "
            f"must be a non-empty list"
        )

    if any(
        not isinstance(item, str)
        or not item.strip()
        for item in value
    ):
        fail(
            f"{policy_id}: {field_name} "
            f"must contain only non-empty strings"
        )

    if len(value) != len(set(value)):
        fail(
            f"{policy_id}: {field_name} "
            f"contains duplicate values"
        )


def validate_v2_policy(
    policy_id,
    policy,
    remediation,
):
    missing = (
        V2_TOP_LEVEL_FIELDS
        - set(policy)
    )

    if missing:
        fail(
            f"{policy_id}: incomplete v2 policy; "
            f"missing fields: {sorted(missing)}"
        )

    scope = policy["scope"]
    require_mapping(
        policy_id,
        "scope",
        scope,
    )

    require_nonempty_string_list(
        policy_id,
        "scope.roles",
        scope.get("roles"),
    )

    require_nonempty_string_list(
        policy_id,
        "scope.platforms",
        scope.get("platforms"),
    )

    intent = policy["intent"]
    require_mapping(
        policy_id,
        "intent",
        intent,
    )

    source = intent.get("source")

    if source not in VALID_INTENT_SOURCES:
        fail(
            f"{policy_id}: invalid intent source "
            f"{source!r}; allowed="
            f"{sorted(VALID_INTENT_SOURCES)}"
        )

    require_nonempty_string(
        policy_id,
        "intent.field",
        intent.get("field"),
    )

    state = policy["state"]
    require_mapping(
        policy_id,
        "state",
        state,
    )

    state_path = state.get("path")

    require_nonempty_string(
        policy_id,
        "state.path",
        state_path,
    )

    if not NORMALIZED_STATE_PATH_RE.fullmatch(
        state_path
    ):
        fail(
            f"{policy_id}: state.path must be "
            f"a dotted normalized-state path"
        )

    comparison = policy["comparison"]
    require_mapping(
        policy_id,
        "comparison",
        comparison,
    )

    operator = comparison.get("operator")

    if operator not in VALID_COMPARISON_OPERATORS:
        fail(
            f"{policy_id}: invalid comparison "
            f"operator {operator!r}; allowed="
            f"{sorted(VALID_COMPARISON_OPERATORS)}"
        )

    verification = policy["verification"]
    require_mapping(
        policy_id,
        "verification",
        verification,
    )

    required = verification.get("required")

    if not isinstance(required, bool):
        fail(
            f"{policy_id}: "
            f"verification.required must "
            f"be true/false"
        )

    supported = remediation["supported"]
    action = remediation.get("action")

    if supported:
        require_nonempty_string(
            policy_id,
            "remediation.action",
            action,
        )

        if not ACTION_RE.fullmatch(action):
            fail(
                f"{policy_id}: remediation.action "
                f"must be an abstract snake_case action"
            )
    elif action is not None:
        fail(
            f"{policy_id}: remediation.action "
            f"must be absent when "
            f"remediation.supported=false"
        )


def main():
    if len(sys.argv) > 2:
        fail(
            "Usage: "
            "validate_compliance_policies.py "
            "[policy-file]"
        )

    policy_file = (
        Path(sys.argv[1])
        if len(sys.argv) == 2
        else DEFAULT_POLICY_FILE
    )

    if not policy_file.exists():
        fail(
            f"{policy_file} does not exist"
        )

    with policy_file.open() as f:
        document = yaml.safe_load(f)

    if not isinstance(document, dict):
        fail(
            "Top-level YAML must be a mapping"
        )

    policies = document.get(
        "compliance_policies"
    )

    if not isinstance(policies, dict):
        fail(
            "compliance_policies must be a mapping"
        )

    if not policies:
        fail(
            "No compliance policies defined"
        )

    seen_controls = {}

    for policy_id, policy in policies.items():

        if not policy_id.startswith("NET-"):
            fail(
                f"{policy_id}: policy ID must "
                f"start with NET-"
            )

        if not isinstance(policy, dict):
            fail(
                f"{policy_id}: policy must be "
                f"a mapping"
            )

        missing = (
            REQUIRED_POLICY_FIELDS
            - set(policy)
        )

        if missing:
            fail(
                f"{policy_id}: missing fields: "
                f"{sorted(missing)}"
            )

        severity = policy["severity"]

        if severity not in VALID_SEVERITIES:
            fail(
                f"{policy_id}: invalid severity "
                f"{severity!r}"
            )

        ticket_required = policy[
            "ticket_required"
        ]

        if not isinstance(
            ticket_required,
            bool,
        ):
            fail(
                f"{policy_id}: ticket_required "
                f"must be true/false"
            )

        enabled = policy["enabled"]

        if not isinstance(enabled, bool):
            fail(
                f"{policy_id}: enabled must be "
                f"true/false"
            )

        remediation = policy[
            "remediation"
        ]

        require_mapping(
            policy_id,
            "remediation",
            remediation,
        )

        supported = remediation.get(
            "supported"
        )

        if not isinstance(supported, bool):
            fail(
                f"{policy_id}: "
                f"remediation.supported must "
                f"be true/false"
            )

        mode = remediation.get("mode")

        if mode not in VALID_REMEDIATION_MODES:
            fail(
                f"{policy_id}: invalid "
                f"remediation mode {mode!r}"
            )

        risk = remediation.get("risk")

        if risk not in VALID_RISKS:
            fail(
                f"{policy_id}: invalid "
                f"remediation risk {risk!r}"
            )

        if (
            mode in {
                "auto",
                "approval_required",
            }
            and not supported
        ):
            fail(
                f"{policy_id}: remediation "
                f"mode {mode!r} requires "
                f"supported=true"
            )

        control = policy["control"]

        require_nonempty_string(
            policy_id,
            "control",
            control,
        )

        if control in seen_controls:
            fail(
                f"{policy_id}: duplicate control "
                f"{control!r}; already owned by "
                f"{seen_controls[control]}"
            )

        seen_controls[control] = policy_id

        if (
            severity == "critical"
            and not ticket_required
        ):
            fail(
                f"{policy_id}: critical policy "
                f"must have ticket_required=true"
            )

        is_v2 = (
            bool(
                V2_TOP_LEVEL_FIELDS
                & set(policy)
            )
            or "action" in remediation
        )

        if is_v2:
            validate_v2_policy(
                policy_id,
                policy,
                remediation,
            )

    print(
        "Compliance policy validation: PASS"
    )

    print(
        f"Policies validated: {len(policies)}"
    )

    print()

    for policy_id, policy in policies.items():

        remediation = policy["remediation"]

        is_v2 = (
            bool(
                V2_TOP_LEVEL_FIELDS
                & set(policy)
            )
            or "action" in remediation
        )

        model = (
            "v2"
            if is_v2
            else "legacy"
        )

        print(
            f"{policy_id:<12}",
            f"| {policy['control']:<30}",
            f"| severity={policy['severity']:<8}",
            f"| ticket="
            f"{str(policy['ticket_required']):<5}",
            f"| remediation="
            f"{remediation['mode']:<17}",
            f"| model={model}",
        )


if __name__ == "__main__":
    main()
