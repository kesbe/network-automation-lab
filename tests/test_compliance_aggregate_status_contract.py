from pathlib import Path
import unittest


PLAYBOOK = (
    Path(__file__).resolve().parents[1]
    / "playbooks"
    / "compliance_aggregate.yml"
)


class ComplianceAggregateStatusContractTests(
    unittest.TestCase
):

    def test_noncompliant_summary_uses_canonical_status(
        self,
    ):
        text = PLAYBOOK.read_text()

        start = text.find(
            "'devices_noncompliant'"
        )
        end = text.find(
            "'total_findings'",
            start,
        )

        self.assertGreaterEqual(
            start,
            0,
            "devices_noncompliant summary block missing",
        )

        self.assertGreater(
            end,
            start,
            "total_findings boundary missing",
        )

        block = text[start:end]

        self.assertIn(
            "'NON_COMPLIANT'",
            block,
        )

        self.assertNotIn(
            "'NON-COMPLIANT'",
            block,
        )

    def test_canonical_detector_status_is_supported(
        self,
    ):
        text = PLAYBOOK.read_text()

        self.assertIn(
            "'NON_COMPLIANT'",
            text,
        )


if __name__ == "__main__":
    unittest.main()
