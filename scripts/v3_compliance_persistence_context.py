#!/usr/bin/env python3

"""
Build the canonical V3 persistence context used by the future
transactional V3 compliance-run ingestion boundary.

This adapter deliberately separates contracts:

legacy compliance finding
    +
immutable resolved V3 target
    |
    v
canonical V3 finding snapshot

No lifecycle classification and no database writes occur here.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from typing import Any

try:
    from scripts.v3_compliance_event import (
        FINDING_FIELDS,
    )
    from scripts.v3_target_contract import (
        SCHEMA_VERSION,
        V3ContractError,
        build_resolved_target,
        validate_finding,
        validate_resolved_target,
    )
except ModuleNotFoundError:
    from v3_compliance_event import (
        FINDING_FIELDS,
    )
    from v3_target_contract import (
        SCHEMA_VERSION,
        V3ContractError,
        build_resolved_target,
        validate_finding,
        validate_resolved_target,
    )


LEGACY_COMPLIANCE_SCHEMA_VERSION = "1.0"

LEGACY_NONCOMPLIANT_STATUSES = frozenset(
    {
        "NON_COMPLIANT",
        "NON-COMPLIANT",
    }
)

LEGACY_REMEDIATION_POLICY_MAP = {
    "auto": "auto",
    "approval_required": "approval_required",
    "manual": "manual",
    "report_only": "observe_only",
}

PERSISTENCE_CONTEXT_FIELDS = (
    "schema_version",
    "compliance_run_id",
    "resolved_target",
    "findings",
)


REMEDIATION_DETAIL_FIELDS_BY_CONTROL = {
    "maximum_paths": (
        "expected",
    ),
    "bgp_neighbor_configuration": (
        "neighbor",
        "expected_remote_as",
        "expected_description",
    ),
}


class PersistenceContextError(
    V3ContractError
):
    pass


def _require_mapping(
    value: Any,
    field: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PersistenceContextError(
            f"{field} must be a mapping"
        )

    return value


def _require_nonempty_string(
    value: Any,
    field: str,
) -> str:
    if not isinstance(value, str):
        raise PersistenceContextError(
            f"{field} must be a string"
        )

    result = value.strip()

    if not result:
        raise PersistenceContextError(
            f"{field} must not be empty"
        )

    return result


def translate_legacy_remediation_policy(
    value: Any,
) -> str:
    value = _require_nonempty_string(
        value,
        "remediation.mode",
    ).lower()

    canonical = (
        LEGACY_REMEDIATION_POLICY_MAP.get(
            value
        )
    )

    if canonical is None:
        raise PersistenceContextError(
            "unsupported legacy remediation mode: "
            f"{value}"
        )

    return canonical


def _canonical_target(
    resolved_target: dict[str, Any],
) -> dict[str, Any]:
    resolved_target = _require_mapping(
        resolved_target,
        "resolved_target",
    )

    validate_resolved_target(
        resolved_target
    )

    canonical = build_resolved_target(
        selector=copy.deepcopy(
            resolved_target["selector"]
        ),
        devices=copy.deepcopy(
            resolved_target["devices"]
        ),
    )

    if (
        canonical["target_id"]
        != resolved_target["target_id"]
    ):
        raise PersistenceContextError(
            "resolved target identity changed "
            "during canonicalization"
        )

    return canonical


def _target_device(
    *,
    target: dict[str, Any],
    device_name: str,
) -> dict[str, Any]:
    matches = [
        device
        for device in target["devices"]
        if device["name"] == device_name
    ]

    if len(matches) != 1:
        raise PersistenceContextError(
            "finding device must identify "
            "exactly one resolved target device"
        )

    return matches[0]


def _validate_optional_source_identity(
    *,
    finding: dict[str, Any],
    target_device: dict[str, Any],
) -> None:
    if "vendor" in finding:
        source_vendor = (
            _require_nonempty_string(
                finding["vendor"],
                "finding.vendor",
            )
        )

        if (
            source_vendor
            != target_device["vendor"]
        ):
            raise PersistenceContextError(
                "finding.vendor conflicts with "
                "resolved target"
            )

    if "platform" in finding:
        source_platform = (
            _require_nonempty_string(
                finding["platform"],
                "finding.platform",
            ).lower()
        )

        if (
            source_platform
            != target_device["platform"]
        ):
            raise PersistenceContextError(
                "finding.platform conflicts with "
                "resolved target"
            )


def _validate_finding_target_binding(
    *,
    finding: dict[str, Any],
    target: dict[str, Any],
) -> None:
    target_device = _target_device(
        target=target,
        device_name=finding["device"],
    )

    if (
        finding["vendor"]
        != target_device["vendor"]
    ):
        raise PersistenceContextError(
            "finding vendor does not match "
            "resolved target device"
        )

    if (
        finding["platform"]
        != target_device["platform"]
    ):
        raise PersistenceContextError(
            "finding platform does not match "
            "resolved target device"
        )


def _canonical_remediation_detail(
    *,
    field: str,
    value: Any,
) -> Any:
    if field == "expected":
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
        ):
            raise PersistenceContextError(
                "finding.expected must be "
                "a positive integer"
            )

        return value

    if field == "expected_remote_as":
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            or value > 4294967295
        ):
            raise PersistenceContextError(
                "finding.expected_remote_as "
                "must be a valid positive ASN"
            )

        return value

    if field in {
        "neighbor",
        "expected_description",
    }:
        return _require_nonempty_string(
            value,
            f"finding.{field}",
        )

    raise PersistenceContextError(
        "unsupported remediation detail field: "
        f"{field}"
    )


def _canonical_persistence_finding(
    finding: dict[str, Any],
) -> dict[str, Any]:
    validated = validate_finding(
        finding
    )

    if (
        validated["status"]
        != "NON_COMPLIANT"
    ):
        raise PersistenceContextError(
            "persistence finding must "
            "be NON_COMPLIANT"
        )

    detail_fields = (
        REMEDIATION_DETAIL_FIELDS_BY_CONTROL.get(
            validated["control"],
            (),
        )
    )

    allowed_fields = (
        set(FINDING_FIELDS)
        | set(detail_fields)
    )

    unexpected_fields = sorted(
        set(validated)
        - allowed_fields
    )

    if unexpected_fields:
        raise PersistenceContextError(
            "persistence finding contains "
            "unexpected fields: "
            + ", ".join(
                unexpected_fields
            )
        )

    canonical = {
        field: validated[field]
        for field in FINDING_FIELDS
    }

    for field in detail_fields:
        if field in validated:
            canonical[field] = (
                _canonical_remediation_detail(
                    field=field,
                    value=validated[field],
                )
            )

    if (
        validated["remediable"]
        and validated[
            "remediation_policy"
        ] == "auto"
    ):
        missing = [
            field
            for field in detail_fields
            if field not in canonical
        ]

        if missing:
            raise PersistenceContextError(
                "automatic remediation finding "
                "is missing required detail fields: "
                + ", ".join(
                    missing
                )
            )

    return canonical


def _canonical_finding(
    *,
    finding: dict[str, Any],
    target: dict[str, Any],
) -> dict[str, Any]:
    finding = _require_mapping(
        finding,
        "finding",
    )

    finding_id = _require_nonempty_string(
        finding.get("finding_id"),
        "finding.finding_id",
    )

    device_name = _require_nonempty_string(
        finding.get("device"),
        "finding.device",
    )

    device_status = _require_nonempty_string(
        finding.get("device_status"),
        "finding.device_status",
    ).upper()

    if (
        device_status
        not in LEGACY_NONCOMPLIANT_STATUSES
    ):
        raise PersistenceContextError(
            "persisted finding must originate "
            "from a non-compliant device status"
        )

    target_device = _target_device(
        target=target,
        device_name=device_name,
    )

    _validate_optional_source_identity(
        finding=finding,
        target_device=target_device,
    )

    remediation = _require_mapping(
        finding.get("remediation"),
        "finding.remediation",
    )

    remediable = remediation.get(
        "supported"
    )

    if not isinstance(
        remediable,
        bool,
    ):
        raise PersistenceContextError(
            "finding.remediation.supported "
            "must be boolean"
        )

    remediation_policy = (
        translate_legacy_remediation_policy(
            remediation.get("mode")
        )
    )

    ticket_required = finding.get(
        "ticket_required"
    )

    if not isinstance(
        ticket_required,
        bool,
    ):
        raise PersistenceContextError(
            "finding.ticket_required "
            "must be boolean"
        )

    raw_target_providers = finding.get(
        "target_providers"
    )

    if ticket_required:

        if (
            not isinstance(
                raw_target_providers,
                list,
            )
            or not raw_target_providers
        ):
            raise PersistenceContextError(
                "finding.target_providers "
                "must be a non-empty array "
                "when ticket_required=true"
            )

        target_providers = []

        for provider in raw_target_providers:

            if (
                not isinstance(
                    provider,
                    str,
                )
                or not provider.strip()
            ):
                raise PersistenceContextError(
                    "finding.target_providers "
                    "members must be "
                    "non-empty strings"
                )

            canonical = (
                provider
                .strip()
                .lower()
            )

            if canonical not in {
                "servicenow",
                "zammad",
            }:
                raise PersistenceContextError(
                    "unsupported target provider: "
                    + canonical
                )

            target_providers.append(
                canonical
            )

        if (
            len(
                set(
                    target_providers
                )
            )
            != len(
                target_providers
            )
        ):
            raise PersistenceContextError(
                "finding.target_providers "
                "must not contain duplicates"
            )

        target_providers = sorted(
            target_providers
        )

    elif (
        "target_providers"
        in finding
    ):

        raise PersistenceContextError(
            "finding.target_providers "
            "must be absent when "
            "ticket_required=false"
        )

    candidate = {
        "finding_id":
            finding_id,

        "device":
            device_name,

        "vendor":
            target_device["vendor"],

        "platform":
            target_device["platform"],

        "control":
            _require_nonempty_string(
                finding.get("control"),
                "finding.control",
            ),

        "severity":
            _require_nonempty_string(
                finding.get("severity"),
                "finding.severity",
            ),

        "status":
            "NON_COMPLIANT",

        "remediable":
            remediable,

        "remediation_policy":
            remediation_policy,

        "ticket_required":
            ticket_required,
    }

    if ticket_required:
        candidate["target_providers"] = (
            target_providers
        )

    for field in (
        REMEDIATION_DETAIL_FIELDS_BY_CONTROL.get(
            candidate["control"],
            (),
        )
    ):
        if field in finding:
            candidate[field] = copy.deepcopy(
                finding[field]
            )

    canonical = (
        _canonical_persistence_finding(
            candidate
        )
    )

    _validate_finding_target_binding(
        finding=canonical,
        target=target,
    )

    return canonical


def build_persistence_context(
    *,
    compliance_run: dict[str, Any],
    resolved_target: dict[str, Any],
) -> dict[str, Any]:
    compliance_run = _require_mapping(
        compliance_run,
        "compliance_run",
    )

    if (
        compliance_run.get("schema_version")
        != LEGACY_COMPLIANCE_SCHEMA_VERSION
    ):
        raise PersistenceContextError(
            "unsupported legacy "
            "compliance_run.schema_version"
        )

    run_id = _require_nonempty_string(
        compliance_run.get("run_id"),
        "compliance_run.run_id",
    )

    findings = compliance_run.get(
        "findings"
    )

    if not isinstance(findings, list):
        raise PersistenceContextError(
            "compliance_run.findings "
            "must be a list"
        )

    canonical_target = _canonical_target(
        resolved_target
    )

    canonical_findings = []
    seen_finding_ids = set()

    for finding in findings:
        canonical = _canonical_finding(
            finding=finding,
            target=canonical_target,
        )

        finding_id = canonical[
            "finding_id"
        ]

        if finding_id in seen_finding_ids:
            raise PersistenceContextError(
                "compliance_run contains "
                "duplicate finding_id: "
                f"{finding_id}"
            )

        seen_finding_ids.add(
            finding_id
        )

        canonical_findings.append(
            canonical
        )

    canonical_findings.sort(
        key=lambda item: item[
            "finding_id"
        ]
    )

    context = {
        "schema_version":
            SCHEMA_VERSION,

        "compliance_run_id":
            run_id,

        "resolved_target":
            canonical_target,

        "findings":
            canonical_findings,
    }

    validate_persistence_context(
        context
    )

    return context


def validate_persistence_context(
    context: dict[str, Any],
) -> None:
    context = _require_mapping(
        context,
        "persistence_context",
    )

    if set(context) != set(
        PERSISTENCE_CONTEXT_FIELDS
    ):
        raise PersistenceContextError(
            "persistence context fields "
            "are not canonical"
        )

    if (
        context.get("schema_version")
        != SCHEMA_VERSION
    ):
        raise PersistenceContextError(
            "unsupported persistence "
            "context schema_version"
        )

    _require_nonempty_string(
        context.get("compliance_run_id"),
        "compliance_run_id",
    )

    canonical_target = _canonical_target(
        context.get("resolved_target")
    )

    if (
        context["resolved_target"]
        != canonical_target
    ):
        raise PersistenceContextError(
            "resolved_target is not canonical"
        )

    findings = context.get(
        "findings"
    )

    if not isinstance(findings, list):
        raise PersistenceContextError(
            "persistence context findings "
            "must be a list"
        )

    canonical_findings = []
    seen_finding_ids = set()

    for finding in findings:
        finding = _require_mapping(
            finding,
            "persistence finding",
        )

        canonical = (
            _canonical_persistence_finding(
                finding
            )
        )

        _validate_finding_target_binding(
            finding=canonical,
            target=canonical_target,
        )

        finding_id = canonical[
            "finding_id"
        ]

        if finding_id in seen_finding_ids:
            raise PersistenceContextError(
                "persistence context contains "
                "duplicate finding_id: "
                f"{finding_id}"
            )

        seen_finding_ids.add(
            finding_id
        )

        canonical_findings.append(
            canonical
        )

    canonical_findings.sort(
        key=lambda item: item[
            "finding_id"
        ]
    )

    if findings != canonical_findings:
        raise PersistenceContextError(
            "persistence findings are "
            "not in canonical order"
        )


def load_payload(
    path: str | None,
):
    if path:
        with open(
            path,
            "r",
            encoding="utf-8",
        ) as handle:
            return json.load(
                handle
            )

    return json.load(
        sys.stdin
    )


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        help=(
            "JSON document containing "
            "compliance_run and resolved_target. "
            "Defaults to stdin."
        ),
    )

    args = parser.parse_args()

    try:
        payload = load_payload(
            args.input
        )

        payload = _require_mapping(
            payload,
            "input payload",
        )

        context = build_persistence_context(
            compliance_run=payload.get(
                "compliance_run"
            ),
            resolved_target=payload.get(
                "resolved_target"
            ),
        )

    except (
        OSError,
        json.JSONDecodeError,
        V3ContractError,
    ) as exc:
        print(
            "persistence_context_error="
            + str(exc),
            file=sys.stderr,
        )

        return 2

    print(
        json.dumps(
            context,
            indent=2,
            sort_keys=True,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
