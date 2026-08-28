from pathlib import Path
import unittest

from scripts.normalized_network_state import (
    validate_normalized_state,
)
from scripts.vendor_arista_eos_adapter import (
    AristaEosAdapterError,
    normalize_arista_eos_state,
)


ROOT = Path(__file__).resolve().parents[1]

RUNNING = (
    ROOT
    / "tests/fixtures/arista_eos"
    / "spine01_running_config.txt"
)

SUMMARY = (
    ROOT
    / "tests/fixtures/arista_eos"
    / "spine01_bgp_summary.txt"
)


class AristaEosAdapterTests(
    unittest.TestCase
):

    def state(
        self,
        running=None,
        summary=None,
    ):
        return normalize_arista_eos_state(
            (
                RUNNING.read_text()
                if running is None
                else running
            ),
            (
                SUMMARY.read_text()
                if summary is None
                else summary
            ),
            device_name="spine01",
            role="spine",
            site="syd01",
        )

    def test_normalized_state_is_valid(self):
        state = self.state()

        self.assertEqual(
            validate_normalized_state(state),
            [],
        )

    def test_identity_is_normalized(self):
        state = self.state()

        self.assertEqual(
            state["device"]["name"],
            "spine01",
        )

        self.assertEqual(
            state["device"]["platform"],
            "arista_eos",
        )

        self.assertEqual(
            state["device"]["vendor"],
            "Arista",
        )

    def test_bgp_values(self):
        state = self.state()

        self.assertEqual(
            state["bgp"]["local_as"],
            65000,
        )

        self.assertEqual(
            state["bgp"]["router_id"],
            "10.255.0.1",
        )

        self.assertEqual(
            state["bgp"][
                "ipv4_unicast"
            ][
                "maximum_paths"
            ],
            2,
        )

    def test_requested_hostname_mismatch_fails(self):
        with self.assertRaises(
            AristaEosAdapterError
        ):
            normalize_arista_eos_state(
                RUNNING.read_text(),
                SUMMARY.read_text(),
                device_name="wrong-device",
                role="spine",
            )

    def test_summary_as_mismatch_fails(self):
        summary = SUMMARY.read_text().replace(
            "65000",
            "65001",
            1,
        )

        with self.assertRaises(
            AristaEosAdapterError
        ):
            self.state(
                summary=summary
            )

    def test_router_id_mismatch_fails(self):
        summary = SUMMARY.read_text().replace(
            "10.255.0.1",
            "10.255.0.99",
            1,
        )

        with self.assertRaises(
            AristaEosAdapterError
        ):
            self.state(
                summary=summary
            )


if __name__ == "__main__":
    unittest.main()
