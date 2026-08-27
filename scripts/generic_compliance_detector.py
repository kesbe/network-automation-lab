#!/usr/bin/env python3

import argparse
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


from scripts.compliance_policy_engine import (
    PolicyEvaluationError,
    evaluate_policy,
)

from scripts.normalized_network_state import (
    validate_normalized_state,
)


V2_POLICY_FIELDS = (
    "scope",
    "intent",
    "state",
    "comparison",
    "verification",
)


class GenericDetectorError(Exception):
    pass


def _is_v2_policy(policy):
    return (
        isinstance(policy, dict)
        and all(
            field in policy
            for field in V2_POLICY_FIELDS
        )
    )


def _require_device_context(state):
    device = state.get("device")

    if not isinstance(device, dict):
        raise GenericDetectorError(
            "normalized state device must be a mapping"
        )

    name = device.get("name")
    platform = device.get("platform")
    role = device.get("role")

    if not isinstance(name, str) or not name:
        raise GenericDetectorError(
            "device.name is required"
        )

    if not isinstance(platform, str) or not platform:
        raise GenericDetectorError(
            "device.platform is required"
        )

    if not isinstance(role, str) or not role:
        raise GenericDetectorError(
            "device.role is required for "
            "policy scope evaluation"
        )

    return device


def policy_applies(policy, device):
    scope = policy.get("scope")

    if not isinstance(scope, dict):
        raise GenericDetectorError(
            "v2 policy scope must be a mapping"
        )

    roles = scope.get("roles")
    platforms = scope.get("platforms")

    if (
        not isinstance(roles, list)
        or not roles
    ):
        raise GenericDetectorError(
            "v2 policy scope.roles must be "
            "a non-empty list"
        )

    if (
        not isinstance(platforms, list)
        or not platforms
    ):
        raise GenericDetectorError(
            "v2 policy scope.platforms must be "
            "a non-empty list"
        )

    return (
        device["role"] in roles
        and device["platform"] in platforms
    )


def _current_remediation_contract(policy):
    remediation = policy.get("remediation")

    if not isinstance(remediation, dict):
        raise GenericDetectorError(
            "policy remediation must be a mapping"
        )

    required = (
        "supported",
        "mode",
        "risk",
    )

    missing = [
        key
        for key in required
        if key not in remediation
    ]

    if missing:
        raise GenericDetectorError(
            "policy remediation missing fields: "
            + ",".join(missing)
        )

    return {
        "supported": remediation["supported"],
        "mode": remediation["mode"],
        "risk": remediation["risk"],
    }


def _build_violation(
    policy_id,
    policy,
    evaluation,
):
    required_metadata = (
        "name",
        "control",
        "category",
        "severity",
        "ticket_required",
        "owner",
    )

    missing = [
        field
        for field in required_metadata
        if field not in policy
    ]

    if missing:
        raise GenericDetectorError(
            "policy metadata missing fields: "
            + ",".join(missing)
        )

    return {
        "control": policy["control"],
        "expected": evaluation["expected"],
        "actual": evaluation["actual"],
        "policy_id": policy_id,
        "policy_name": policy["name"],
        "category": policy["category"],
        "severity": policy["severity"],
        "ticket_required":
            policy["ticket_required"],
        "owner": policy["owner"],
        "remediation":
            _current_remediation_contract(
                policy
            ),
    }


def evaluate_device(
    normalized_state,
    policies,
    intent_values,
):
    validation_errors = (
        validate_normalized_state(
            normalized_state
        )
    )

    if validation_errors:
        raise GenericDetectorError(
            "normalized state validation failed: "
            + "; ".join(validation_errors)
        )

    if not isinstance(policies, dict):
        raise GenericDetectorError(
            "policy catalog must be a mapping"
        )

    if not isinstance(intent_values, dict):
        raise GenericDetectorError(
            "intent values must be a mapping"
        )

    device = _require_device_context(
        normalized_state
    )

    applicable = []

    for policy_id in sorted(policies):
        policy = policies[policy_id]

        if not isinstance(policy, dict):
            continue

        if policy.get("enabled") is not True:
            continue

        if not _is_v2_policy(policy):
            continue

        if policy_applies(
            policy,
            device,
        ):
            applicable.append(
                (
                    policy_id,
                    policy,
                )
            )

    if not applicable:
        raise GenericDetectorError(
            "no applicable enabled v2 policies "
            "for device "
            f"{device['name']}"
        )

    violations = []
    passed = 0

    for policy_id, policy in applicable:
        try:
            result = evaluate_policy(
                policy_id,
                policy,
                normalized_state,
                intent_values,
            )
        except PolicyEvaluationError as exc:
            raise GenericDetectorError(
                f"{policy_id}: {exc}"
            ) from exc

        if result["status"] == "COMPLIANT":
            passed += 1
            continue

        if result["status"] != "NON_COMPLIANT":
            raise GenericDetectorError(
                f"{policy_id}: unexpected "
                f"evaluation status "
                f"{result['status']!r}"
            )

        violations.append(
            _build_violation(
                policy_id,
                policy,
                result,
            )
        )

    total_checks = len(applicable)
    failed = len(violations)

    return {
        "device": device["name"],
        "status": (
            "COMPLIANT"
            if failed == 0
            else "NON_COMPLIANT"
        ),
        "total_checks": total_checks,
        "passed": passed,
        "failed": failed,
        "violations": violations,
    }


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate normalized network state "
            "against applicable v2 compliance "
            "policies and emit the existing "
            "per-device detector artifact."
        )
    )

    parser.add_argument(
        "--normalized-state",
        required=True,
    )

    parser.add_argument(
        "--policy-file",
        default="vars/compliance_policies.yml",
    )

    parser.add_argument(
        "--intent-file",
        required=True,
    )

    args = parser.parse_args()

    try:
        state = yaml.safe_load(
            Path(
                args.normalized_state
            ).read_text()
        )

        policy_document = yaml.safe_load(
            Path(
                args.policy_file
            ).read_text()
        )

        intent_values = yaml.safe_load(
            Path(
                args.intent_file
            ).read_text()
        )

        policies = policy_document.get(
            "compliance_policies"
        )

        result = evaluate_device(
            state,
            policies,
            intent_values,
        )

    except Exception as exc:
        print(
            "generic_detector=FAIL "
            + str(exc),
            file=sys.stderr,
        )
        return 1

    print(
        yaml.safe_dump(
            result,
            sort_keys=False,
        ),
        end="",
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
