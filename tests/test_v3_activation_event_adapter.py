#!/usr/bin/env python3

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts.v3_activation_event_adapter import (
    ActivationEventAdapterError,
    build_activation_event,
)

from scripts.v3_compliance_event import (
    validate_event,
)

from tests.test_v3_compliance_event import (
    make_finding,
    make_target,
)


ROOT = Path(__file__).resolve().parents[1]

ADAPTER = (
    ROOT
    / "scripts"
    / "v3_activation_event_adapter.py"
)


def make_source(
    lifecycle_event_type="DETECTED",
):
    finding = make_finding()

    return {
        "finding_event_id": 101,
        "run_id":
            "compliance-v3-activation-adapter",
        "finding_id":
            finding["finding_id"],
        "lifecycle_event_type":
            lifecycle_event_type,
        "activated_at":
            "2026-08-31T01:30:00+10:00",
        "finding_snapshot":
            finding,
        "resolved_target":
            make_target(),
    }


class V3ActivationEventAdapterTests(
    unittest.TestCase
):

    def test_detected_builds_canonical_event(
        self,
    ):
        source = make_source()

        event = build_activation_event(
            source
        )

        validate_event(event)

        self.assertEqual(
            event["compliance_run_id"],
            source["run_id"],
        )

        self.assertEqual(
            event["lifecycle_event_type"],
            "DETECTED",
        )

        self.assertEqual(
            event["finding"]["finding_id"],
            source["finding_id"],
        )

        self.assertEqual(
            event["target"],
            source["resolved_target"],
        )

        self.assertTrue(
            event["event_id"].startswith(
                "v3-compliance-event-"
            )
        )

    def test_reopened_builds_activation_event(
        self,
    ):
        source = make_source(
            "REOPENED"
        )

        event = build_activation_event(
            source
        )

        self.assertEqual(
            event["lifecycle_event_type"],
            "REOPENED",
        )

        validate_event(event)

    def test_durable_detail_is_not_transport_field(
        self,
    ):
        source = make_source()

        self.assertIn(
            "expected",
            source["finding_snapshot"],
        )

        event = build_activation_event(
            source
        )

        self.assertNotIn(
            "expected",
            event["finding"],
        )

        self.assertNotIn(
            "actual",
            event["finding"],
        )

        self.assertNotIn(
            "policy_id",
            event["finding"],
        )

    def test_source_finding_identity_must_match(
        self,
    ):
        source = make_source()

        source["finding_id"] = (
            "finding-different"
        )

        with self.assertRaises(
            ActivationEventAdapterError
        ):
            build_activation_event(
                source
            )

    def test_missing_source_field_is_rejected(
        self,
    ):
        source = make_source()

        del source["resolved_target"]

        with self.assertRaises(
            ActivationEventAdapterError
        ):
            build_activation_event(
                source
            )

    def test_unknown_source_field_is_rejected(
        self,
    ):
        source = make_source()

        source["unexpected"] = True

        with self.assertRaises(
            ActivationEventAdapterError
        ):
            build_activation_event(
                source
            )

    def test_invalid_finding_event_id_is_rejected(
        self,
    ):
        source = make_source()

        source["finding_event_id"] = 0

        with self.assertRaises(
            ActivationEventAdapterError
        ):
            build_activation_event(
                source
            )

    def test_seen_again_is_rejected(
        self,
    ):
        with self.assertRaises(
            ValueError
        ):
            build_activation_event(
                make_source(
                    "SEEN_AGAIN"
                )
            )

    def test_target_binding_remains_enforced(
        self,
    ):
        source = make_source()

        source["finding_snapshot"] = (
            copy.deepcopy(
                source["finding_snapshot"]
            )
        )

        source["finding_snapshot"][
            "device"
        ] = "edge99"

        with self.assertRaises(
            ValueError
        ):
            build_activation_event(
                source
            )

    def test_cli_stdout_is_only_event_json(
        self,
    ):
        source = make_source()

        proc = subprocess.run(
            [
                sys.executable,
                str(ADAPTER),
            ],
            input=json.dumps(source),
            text=True,
            capture_output=True,
            cwd=ROOT,
        )

        self.assertEqual(
            proc.returncode,
            0,
            msg=proc.stderr,
        )

        event = json.loads(
            proc.stdout
        )

        validate_event(event)

        self.assertEqual(
            proc.stderr,
            "",
        )

    def test_adapter_has_no_transport_or_db_role(
        self,
    ):
        source = ADAPTER.read_text()

        self.assertNotIn(
            "publish_event(",
            source,
        )

        self.assertNotIn(
            "psycopg",
            source,
        )

        self.assertNotIn(
            "postgresql_query",
            source,
        )

        self.assertNotIn(
            "kafka_event_transport",
            source,
        )


if __name__ == "__main__":
    unittest.main()
