import unittest

from scripts.v3_target_resolver import (
    TargetResolutionError,
    resolve_target,
)


INVENTORY = [
    {
        "name": "leaf01",
        "platform": "frr",
        "vendor": "FRRouting",
        "site": "syd01",
        "role": "leaf",
        "tags": [
            "production",
            "dc",
        ],
    },
    {
        "name": "leaf02",
        "platform": "frr",
        "vendor": "FRRouting",
        "site": "syd01",
        "role": "leaf",
        "tags": [
            "production",
            "dc",
        ],
    },
    {
        "name": "edge01",
        "platform": "cisco_ios",
        "vendor": "Cisco",
        "site": "syd01",
        "role": "edge",
        "tags": [
            "production",
            "wan",
        ],
    },
    {
        "name": "spine01",
        "platform": "arista_eos",
        "vendor": "Arista",
        "site": "syd01",
        "role": "spine",
        "tags": [
            "production",
            "dc",
        ],
    },
]


class V3TargetResolverTests(
    unittest.TestCase
):

    def test_explicit_devices(
        self,
    ):
        result = resolve_target(
            selector={
                "devices": [
                    "leaf01",
                    "edge01",
                ]
            },
            inventory=INVENTORY,
        )

        self.assertEqual(
            result["device_names"],
            [
                "edge01",
                "leaf01",
            ],
        )

        self.assertEqual(
            result["device_count"],
            2,
        )

    def test_role_selector(
        self,
    ):
        result = resolve_target(
            selector={
                "site": "syd01",
                "role": "leaf",
            },
            inventory=INVENTORY,
        )

        self.assertEqual(
            result["device_names"],
            [
                "leaf01",
                "leaf02",
            ],
        )

    def test_platform_selector(
        self,
    ):
        result = resolve_target(
            selector={
                "platform": "cisco_ios",
            },
            inventory=INVENTORY,
        )

        self.assertEqual(
            result["device_names"],
            [
                "edge01",
            ],
        )

    def test_required_tags_use_and_semantics(
        self,
    ):
        result = resolve_target(
            selector={
                "tags": [
                    "production",
                    "dc",
                ]
            },
            inventory=INVENTORY,
        )

        self.assertEqual(
            result["device_names"],
            [
                "leaf01",
                "leaf02",
                "spine01",
            ],
        )

    def test_missing_explicit_device_fails(
        self,
    ):
        with self.assertRaises(
            TargetResolutionError
        ):
            resolve_target(
                selector={
                    "devices": [
                        "leaf99",
                    ]
                },
                inventory=INVENTORY,
            )

    def test_zero_match_fails_closed(
        self,
    ):
        with self.assertRaises(
            TargetResolutionError
        ):
            resolve_target(
                selector={
                    "site": "mel99",
                },
                inventory=INVENTORY,
            )

    def test_conflicting_explicit_selector_fails(
        self,
    ):
        with self.assertRaises(
            TargetResolutionError
        ):
            resolve_target(
                selector={
                    "devices": [
                        "edge01",
                    ],
                    "role": "leaf",
                },
                inventory=INVENTORY,
            )


if __name__ == "__main__":
    unittest.main()
