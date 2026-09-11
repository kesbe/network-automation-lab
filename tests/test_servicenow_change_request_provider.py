import unittest

from scripts.servicenow_ticketing_adapter import (
    ServiceNowChangeConfig,
    ServiceNowChangeProvider,
)

from scripts.ticketing_runtime_common import (
    RuntimeContractError,
)


class FakeTransport:
    def __init__(
        self,
        responses,
    ):
        self.responses=list(
            responses
        )

        self.calls=[]


    def request(
        self,
        method,
        url,
        headers,
        payload=None,
    ):
        self.calls.append(
            (
                method,
                url,
                dict(headers),
                (
                    dict(payload)
                    if payload is not None
                    else None
                ),
            )
        )

        if not self.responses:

            raise AssertionError(
                "unexpected transport call"
            )

        return self.responses.pop(0)


def config(
    change_type="normal",
    change_model=None,
):
    return ServiceNowChangeConfig(
        base_url=
            "https://example.service-now.com",

        change_type=
            change_type,

        change_model=
            change_model,

        assignment_group=
            "NETWORK_AUTOMATION",
    )


def intent():
    return {
        "device_name":
            "rtr03",

        "management_ip":
            "172.30.30.34/24",

        "role":
            "router",

        "platform":
            "frr",

        "bgp_asn":
            65105,

        "router_id":
            "10.255.3.3",
    }


class ServiceNowChangeProviderTests(
    unittest.TestCase
):

    def test_endpoint_uses_change_management_api(
        self,
    ):
        provider=ServiceNowChangeProvider(
            config(),
            {},
            FakeTransport([]),
        )

        self.assertEqual(
            provider.endpoint,
            (
                "https://example.service-now.com"
                "/api/sn_chg_rest/change"
            ),
        )


    def test_create_normal_change_maps_identity(
        self,
    ):
        transport=FakeTransport(
            [
                {
                    "result": {
                        "sys_id": {
                            "value":
                                "change-sys-100",

                            "display_value":
                                "change-sys-100",
                        },

                        "number": {
                            "value":
                                "CHG0010100",

                            "display_value":
                                "CHG0010100",
                        },

                        "state": {
                            "value":
                                "-5",

                            "display_value":
                                "New",
                        },
                    }
                }
            ]
        )

        provider=ServiceNowChangeProvider(
            config(),
            {
                "Authorization":
                    "REDACTED_TEST_VALUE",
            },
            transport,
        )

        result=provider.create_change(
            intent()
        )

        self.assertEqual(
            result.sys_id,
            "change-sys-100",
        )

        self.assertEqual(
            result.number,
            "CHG0010100",
        )

        self.assertEqual(
            result.state,
            "-5",
        )


        self.assertEqual(
            len(transport.calls),
            1,
        )

        (
            method,
            url,
            headers,
            payload,
        )=transport.calls[0]


        self.assertEqual(
            method,
            "POST",
        )

        self.assertEqual(
            url,
            (
                "https://example.service-now.com"
                "/api/sn_chg_rest/change"
            ),
        )

        self.assertEqual(
            headers["Accept"],
            "application/json",
        )

        self.assertEqual(
            headers["Content-Type"],
            "application/json",
        )

        self.assertEqual(
            headers["Authorization"],
            "REDACTED_TEST_VALUE",
        )

        self.assertEqual(
            payload["type"],
            "normal",
        )

        self.assertEqual(
            payload["assignment_group"],
            "NETWORK_AUTOMATION",
        )

        self.assertEqual(
            payload["short_description"],
            "Provision network device rtr03",
        )

        self.assertIn(
            "rtr03",
            payload["description"],
        )

        self.assertIn(
            "65105",
            payload["description"],
        )

        self.assertIn(
            "implementation_plan",
            payload,
        )

        self.assertIn(
            "test_plan",
            payload,
        )

        self.assertIn(
            "backout_plan",
            payload,
        )


    def test_change_model_can_replace_type(
        self,
    ):
        transport=FakeTransport(
            [
                {
                    "result": {
                        "sys_id":
                            "change-sys-200",

                        "number":
                            "CHG0010200",
                    }
                }
            ]
        )

        provider=ServiceNowChangeProvider(
            config(
                change_type=None,
                change_model=
                    "NETWORK_STANDARD_MODEL",
            ),
            {},
            transport,
        )

        provider.create_change(
            intent()
        )

        payload=transport.calls[0][3]

        self.assertNotIn(
            "type",
            payload,
        )

        self.assertEqual(
            payload["chg_model"],
            "NETWORK_STANDARD_MODEL",
        )


    def test_requires_type_or_model(
        self,
    ):
        with self.assertRaises(
            RuntimeContractError
        ):
            ServiceNowChangeConfig(
                base_url=
                    "https://example.service-now.com",

                change_type=None,
                change_model=None,
            )


    def test_rejects_incomplete_intent_without_transport_call(
        self,
    ):
        transport=FakeTransport([])

        provider=ServiceNowChangeProvider(
            config(),
            {},
            transport,
        )

        bad=intent()

        del bad[
            "router_id"
        ]

        with self.assertRaises(
            RuntimeContractError
        ):
            provider.create_change(
                bad
            )

        self.assertEqual(
            transport.calls,
            [],
        )


    def test_rejects_missing_change_number(
        self,
    ):
        transport=FakeTransport(
            [
                {
                    "result": {
                        "sys_id":
                            "change-sys-300"
                    }
                }
            ]
        )

        provider=ServiceNowChangeProvider(
            config(),
            {},
            transport,
        )

        with self.assertRaises(
            RuntimeContractError
        ):
            provider.create_change(
                intent()
            )


    def test_custom_plans_override_defaults(
        self,
    ):
        transport=FakeTransport(
            [
                {
                    "result": {
                        "sys_id":
                            "change-sys-400",

                        "number":
                            "CHG0010400",
                    }
                }
            ]
        )

        provider=ServiceNowChangeProvider(
            config(),
            {},
            transport,
        )

        custom=intent()

        custom.update(
            {
                "short_description":
                    "Custom network change",

                "implementation_plan":
                    "CUSTOM IMPLEMENTATION",

                "test_plan":
                    "CUSTOM TEST",

                "backout_plan":
                    "CUSTOM BACKOUT",
            }
        )

        provider.create_change(
            custom
        )

        payload=transport.calls[0][3]

        self.assertEqual(
            payload["short_description"],
            "Custom network change",
        )

        self.assertEqual(
            payload["implementation_plan"],
            "CUSTOM IMPLEMENTATION",
        )

        self.assertEqual(
            payload["test_plan"],
            "CUSTOM TEST",
        )

        self.assertEqual(
            payload["backout_plan"],
            "CUSTOM BACKOUT",
        )


    def test_get_change_maps_nested_approved_state(
        self,
    ):
        transport=FakeTransport(
            [
                {
                    "result": {
                        "sys_id": {
                            "value":
                                "change-sys-500",

                            "display_value":
                                "change-sys-500",
                        },

                        "number": {
                            "value":
                                "CHG0010500",

                            "display_value":
                                "CHG0010500",
                        },

                        "state": {
                            "value":
                                "-4",

                            "display_value":
                                "Assess",
                        },

                        "approval": {
                            "value":
                                "approved",

                            "display_value":
                                "Approved",
                        },
                    }
                }
            ]
        )

        provider=ServiceNowChangeProvider(
            config(),
            {},
            transport,
        )

        result=provider.get_change(
            "change/sys 500"
        )

        self.assertEqual(
            result.sys_id,
            "change-sys-500",
        )

        self.assertEqual(
            result.number,
            "CHG0010500",
        )

        self.assertEqual(
            result.approval,
            "approved",
        )

        self.assertEqual(
            provider.approval_state(
                result
            ),
            "approved",
        )

        self.assertEqual(
            len(transport.calls),
            1,
        )

        (
            method,
            url,
            _,
            payload,
        )=transport.calls[0]

        self.assertEqual(
            method,
            "GET",
        )

        self.assertTrue(
            url.endswith(
                "/api/sn_chg_rest/change/"
                "change%2Fsys%20500"
            )
        )

        self.assertIsNone(
            payload
        )


    def test_get_change_rejects_empty_sys_id_without_call(
        self,
    ):
        transport=FakeTransport([])

        provider=ServiceNowChangeProvider(
            config(),
            {},
            transport,
        )

        with self.assertRaises(
            RuntimeContractError
        ):

            provider.get_change(
                "   "
            )

        self.assertEqual(
            transport.calls,
            [],
        )


    def test_approval_state_rejected(
        self,
    ):
        transport=FakeTransport(
            [
                {
                    "result": {
                        "sys_id":
                            "change-sys-600",

                        "number":
                            "CHG0010600",

                        "approval":
                            "rejected",
                    }
                }
            ]
        )

        provider=ServiceNowChangeProvider(
            config(),
            {},
            transport,
        )

        change=provider.get_change(
            "change-sys-600"
        )

        self.assertEqual(
            provider.approval_state(
                change
            ),
            "rejected",
        )


    def test_approval_state_requested_is_nonterminal(
        self,
    ):
        transport=FakeTransport(
            [
                {
                    "result": {
                        "sys_id":
                            "change-sys-700",

                        "number":
                            "CHG0010700",

                        "approval": {
                            "value":
                                "requested",

                            "display_value":
                                "Requested",
                        },
                    }
                }
            ]
        )

        provider=ServiceNowChangeProvider(
            config(),
            {},
            transport,
        )

        change=provider.get_change(
            "change-sys-700"
        )

        self.assertEqual(
            provider.approval_state(
                change
            ),
            "requested",
        )


    def test_approval_state_not_requested_is_nonterminal(
        self,
    ):
        transport=FakeTransport(
            [
                {
                    "result": {
                        "sys_id":
                            "change-sys-800",

                        "number":
                            "CHG0010800",

                        "approval": {
                            "value":
                                "not requested",

                            "display_value":
                                "Not Yet Requested",
                        },
                    }
                }
            ]
        )

        provider=ServiceNowChangeProvider(
            config(),
            {},
            transport,
        )

        change=provider.get_change(
            "change-sys-800"
        )

        self.assertEqual(
            provider.approval_state(
                change
            ),
            "not_requested",
        )


    def test_unknown_approval_state_fails_closed(
        self,
    ):
        transport=FakeTransport(
            [
                {
                    "result": {
                        "sys_id":
                            "change-sys-900",

                        "number":
                            "CHG0010900",

                        "approval":
                            "INSTANCE_SPECIFIC_VALUE",
                    }
                }
            ]
        )

        provider=ServiceNowChangeProvider(
            config(),
            {},
            transport,
        )

        change=provider.get_change(
            "change-sys-900"
        )

        self.assertEqual(
            provider.approval_state(
                change
            ),
            "unknown",
        )


if __name__ == "__main__":
    unittest.main()
