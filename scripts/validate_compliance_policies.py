#!/usr/bin/env python3

from pathlib import Path
import sys
import yaml


POLICY_FILE = Path(
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


def fail(message):
    print(
        f"ERROR: {message}",
        file=sys.stderr,
    )
    sys.exit(1)


if not POLICY_FILE.exists():
    fail(
        f"{POLICY_FILE} does not exist"
    )


with POLICY_FILE.open() as f:
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

    if not isinstance(
        remediation,
        dict,
    ):
        fail(
            f"{policy_id}: remediation must "
            f"be a mapping"
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

    control = policy["control"]

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


print(
    "Compliance policy validation: PASS"
)

print(
    f"Policies validated: {len(policies)}"
)

print()

for policy_id, policy in policies.items():

    remediation = policy["remediation"]

    print(
        f"{policy_id:<12}",
        f"| {policy['control']:<30}",
        f"| severity={policy['severity']:<8}",
        f"| ticket={str(policy['ticket_required']):<5}",
        f"| remediation={remediation['mode']}"
    )
