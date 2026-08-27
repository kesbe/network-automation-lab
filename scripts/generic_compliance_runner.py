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


from scripts.generic_compliance_detector import (
    GenericDetectorError,
    evaluate_device,
)

from scripts.vendor_frr_adapter import (
    FrrAdapterError,
    normalize_frr_state,
)


class GenericComplianceRunnerError(Exception):
    pass


def normalize_platform_state(
    platform,
    raw_inputs,
    device_name,
    role,
    site=None,
):
    if not isinstance(platform, str):
        raise GenericComplianceRunnerError(
            "platform must be a string"
        )

    platform_key = platform.strip().lower()

    if not platform_key:
        raise GenericComplianceRunnerError(
            "platform must not be empty"
        )

    if not isinstance(raw_inputs, dict):
        raise GenericComplianceRunnerError(
            "raw_inputs must be a mapping"
        )

    if platform_key == "frr":
        running_config = raw_inputs.get(
            "running_config"
        )

        bgp_summary = raw_inputs.get(
            "bgp_summary"
        )

        if not isinstance(
            running_config,
            str,
        ):
            raise GenericComplianceRunnerError(
                "FRR running_config is required"
            )

        if not isinstance(
            bgp_summary,
            str,
        ):
            raise GenericComplianceRunnerError(
                "FRR bgp_summary is required"
            )

        try:
            return normalize_frr_state(
                running_config,
                bgp_summary,
                device_name=device_name,
                role=role,
                site=site,
            )

        except FrrAdapterError as exc:
            raise GenericComplianceRunnerError(
                f"FRR normalization failed: {exc}"
            ) from exc

    raise GenericComplianceRunnerError(
        "unsupported platform: "
        f"{platform_key}"
    )


def run_compliance(
    platform,
    raw_inputs,
    policies,
    intent_values,
    device_name,
    role,
    site=None,
):
    normalized_state = (
        normalize_platform_state(
            platform,
            raw_inputs,
            device_name,
            role,
            site=site,
        )
    )

    try:
        return evaluate_device(
            normalized_state,
            policies,
            intent_values,
        )

    except GenericDetectorError as exc:
        raise GenericComplianceRunnerError(
            f"compliance evaluation failed: {exc}"
        ) from exc


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Normalize vendor state and run "
            "the generic compliance detector."
        )
    )

    parser.add_argument(
        "--platform",
        required=True,
    )

    parser.add_argument(
        "--device-name",
        required=True,
    )

    parser.add_argument(
        "--role",
        required=True,
    )

    parser.add_argument(
        "--site",
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
        "--policy-file",
        default="vars/compliance_policies.yml",
    )

    parser.add_argument(
        "--intent-file",
        required=True,
    )

    args = parser.parse_args()

    try:
        policy_document = yaml.safe_load(
            Path(
                args.policy_file
            ).read_text()
        )

        policies = policy_document.get(
            "compliance_policies"
        )

        intent_values = yaml.safe_load(
            Path(
                args.intent_file
            ).read_text()
        )

        raw_inputs = {
            "running_config":
                Path(
                    args.running_config
                ).read_text(),

            "bgp_summary":
                Path(
                    args.bgp_summary
                ).read_text(),
        }

        result = run_compliance(
            args.platform,
            raw_inputs,
            policies,
            intent_values,
            device_name=args.device_name,
            role=args.role,
            site=args.site,
        )

    except Exception as exc:
        print(
            "generic_compliance_runner=FAIL "
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
