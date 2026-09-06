import unittest

from scripts.ticketing_runtime_common import (
    DatabaseConfig,
    RuntimeConfigurationError,
    RuntimeContractError,
    canonical_json_bytes,
    claim_is_acquired,
    claim_is_completed,
    normalize_event_row,
    redact_text,
    require_claim_disposition,
    require_lifecycle_event_type,
)


class RuntimeCommonTests(unittest.TestCase):
    def test_allowed_lifecycle_events(self):
        for event_type in (
            "DETECTED",
            "SEEN_AGAIN",
            "REOPENED",
            "RESOLVED",
        ):
            self.assertEqual(
                require_lifecycle_event_type(
                    event_type
                ),
                event_type,
            )

    def test_unknown_lifecycle_event_rejected(self):
        with self.assertRaises(
            RuntimeContractError
        ):
            require_lifecycle_event_type(
                "DUPLICATE"
            )

    def test_database_config_requires_password(self):
        with self.assertRaises(
            RuntimeConfigurationError
        ):
            DatabaseConfig.from_environment(
                {
                    "TICKETING_DB_HOST": "db",
                    "TICKETING_DB_PORT": "5432",
                    "TICKETING_DB_NAME": "x",
                    "TICKETING_DB_USER": "u",
                }
            )

    def test_event_normalization(self):
        result = normalize_event_row(
            {
                "source_event_id": "7",
                "source_finding_id": "finding-1",
                "lifecycle_event_type":
                    "DETECTED",
            }
        )

        self.assertEqual(
            result["source_event_id"],
            7,
        )

        self.assertEqual(
            result["finding_id"],
            "finding-1",
        )

    def test_event_requires_finding(self):
        with self.assertRaises(
            RuntimeContractError
        ):
            normalize_event_row(
                {
                    "source_event_id": 1,
                    "source_finding_id": "",
                    "lifecycle_event_type":
                        "DETECTED",
                }
            )

    def test_claim_acquired_boolean(self):
        self.assertTrue(
            claim_is_acquired(
                {"claimed": True}
            )
        )

    def test_claim_acquired_state(self):
        self.assertEqual(
            require_claim_disposition(
                {"status": "CLAIMED"}
            ),
            "ACQUIRED",
        )

    def test_claim_completed_state(self):
        self.assertTrue(
            claim_is_completed(
                {
                    "state":
                        "ALREADY_COMPLETED"
                }
            )
        )

    def test_claim_busy_state(self):
        self.assertEqual(
            require_claim_disposition(
                {"status": "BUSY"}
            ),
            "BUSY",
        )

    def test_unknown_claim_rejected(self):
        with self.assertRaises(
            RuntimeContractError
        ):
            require_claim_disposition(
                {"status": "WHAT"}
            )

    def test_canonical_json_is_stable(self):
        self.assertEqual(
            canonical_json_bytes(
                {
                    "b": 2,
                    "a": 1,
                }
            ),
            b'{"a":1,"b":2}',
        )

    def test_redaction_removes_explicit_secrets(self):
        result = redact_text(
            "failure password=abc token=xyz abc xyz",
            (
                "abc",
                "xyz",
            ),
        )

        self.assertNotIn(
            "abc",
            result,
        )

        self.assertNotIn(
            "xyz",
            result,
        )


if __name__ == "__main__":
    unittest.main()
