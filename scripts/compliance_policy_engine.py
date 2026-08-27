#!/usr/bin/env python3

from scripts.normalized_network_state import (
    resolve_dotted_path,
)


SUPPORTED_OPERATORS = {
    "equals",
}


class PolicyEvaluationError(Exception):
    pass


def resolve_intent_value(
    policy,
    intent_values,
):
    intent = policy.get("intent")

    if not isinstance(intent, dict):
        raise PolicyEvaluationError(
            "policy.intent must be a mapping"
        )

    source = intent.get("source")
    field = intent.get("field")

    if source != "netbox":
        raise PolicyEvaluationError(
            f"unsupported intent source: {source!r}"
        )

    if (
        not isinstance(field, str)
        or not field
    ):
        raise PolicyEvaluationError(
            "policy.intent.field must be "
            "a non-empty string"
        )

    if field not in intent_values:
        raise PolicyEvaluationError(
            f"missing intent field: {field}"
        )

    return intent_values[field]


def evaluate_operator(
    operator,
    actual,
    expected,
):
    if operator not in SUPPORTED_OPERATORS:
        raise PolicyEvaluationError(
            f"unsupported comparison operator: "
            f"{operator!r}"
        )

    if operator == "equals":
        return actual == expected

    raise PolicyEvaluationError(
        f"comparison operator not implemented: "
        f"{operator!r}"
    )


def evaluate_policy(
    policy_id,
    policy,
    normalized_state,
    intent_values,
):
    if not isinstance(policy, dict):
        raise PolicyEvaluationError(
            "policy must be a mapping"
        )

    state_definition = policy.get("state")

    if not isinstance(
        state_definition,
        dict,
    ):
        raise PolicyEvaluationError(
            "policy.state must be a mapping"
        )

    state_path = state_definition.get(
        "path"
    )

    if (
        not isinstance(state_path, str)
        or not state_path
    ):
        raise PolicyEvaluationError(
            "policy.state.path must be "
            "a non-empty string"
        )

    comparison = policy.get(
        "comparison"
    )

    if not isinstance(comparison, dict):
        raise PolicyEvaluationError(
            "policy.comparison must be "
            "a mapping"
        )

    operator = comparison.get(
        "operator"
    )

    expected = resolve_intent_value(
        policy,
        intent_values,
    )

    try:
        actual = resolve_dotted_path(
            normalized_state,
            state_path,
        )
    except KeyError as exc:
        raise PolicyEvaluationError(
            f"normalized state path "
            f"not found: {state_path}"
        ) from exc

    compliant = evaluate_operator(
        operator,
        actual,
        expected,
    )

    return {
        "policy_id": policy_id,
        "control": policy.get("control"),
        "state_path": state_path,
        "operator": operator,
        "expected": expected,
        "actual": actual,
        "compliant": compliant,
        "status": (
            "COMPLIANT"
            if compliant
            else "NON_COMPLIANT"
        ),
    }
