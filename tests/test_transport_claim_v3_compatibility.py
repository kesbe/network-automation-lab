import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

PLAYBOOK = (
    ROOT
    / "playbooks"
    / "transport_claim.yml"
)


class TransportClaimV3CompatibilityTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.text = PLAYBOOK.read_text()

    def test_exact_v2_and_v3_transport_types_are_allowed(self):
        self.assertIn(
            "transport_event_type | string in",
            self.text,
        )

        self.assertIn(
            "'NETWORK_COMPLIANCE_DRIFT_DETECTED'",
            self.text,
        )

        self.assertIn(
            "'NETWORK_COMPLIANCE_FINDING_ACTIVATED'",
            self.text,
        )

    def test_old_v2_only_assertion_is_removed(self):
        self.assertNotIn(
            (
                "transport_event_type | string == "
                "'NETWORK_COMPLIANCE_DRIFT_DETECTED'"
            ),
            self.text,
        )

    def test_claim_api_remains_unchanged(self):
        self.assertIn(
            "SELECT compliance.claim_transport_event(",
            self.text,
        )

        for value in (
            "%(event_id)s::text",
            "%(event_type)s::text",
            "%(compliance_run_id)s::text",
            "%(workflow_job_id)s::bigint",
        ):
            self.assertIn(
                value,
                self.text,
            )

    def test_v3_does_not_require_full_event_payload(self):
        forbidden = (
            "finding_id",
            "remediation_policy",
            "ticket_required",
            "resolved_target",
        )

        for value in forbidden:
            self.assertNotIn(
                value,
                self.text,
            )


if __name__ == "__main__":
    unittest.main()
