import unittest
import urllib.parse

from scripts.servicenow_ticketing_adapter import (
    ServiceNowConfig,
    ServiceNowIncidentProvider,
    deterministic_ticket_record_id,
)

from scripts.ticketing_runtime_common import (
    RuntimeContractError,
)


def config():
    return ServiceNowConfig(
        base_url=
            "https://example.service-now.com",

        active_state=
            "INSTANCE_ACTIVE",

        resolved_state=
            "INSTANCE_RESOLVED",

        assignment_group=
            "NETWORK_AUTOMATION",

        resolution_code=
            "INSTANCE_RESOLUTION_CODE",
    )


def event(
    lifecycle_event_type="DETECTED",
):
    return {
        "source_event_id": 100,
        "finding_id": "finding-100",
        "run_id": "run-100",
        "lifecycle_event_type":
            lifecycle_event_type,
        "event_time":
            "2026-09-08T00:00:00Z",
        "finding_snapshot": {
            "device": "router-01",
            "policy_id": "POLICY-01",
        },
    }


class FakeTransport:
    def __init__(
        self,
        responses,
    ):
        self.responses = list(
            responses
        )

        self.calls = []


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
                    if payload
                    is not None
                    else None
                ),
            )
        )

        if not self.responses:
            raise AssertionError(
                "unexpected transport call"
            )

        return self.responses.pop(0)


class ServiceNowProviderTests(
    unittest.TestCase
):

    def test_deterministic_record_id(
        self,
    ):
        first = (
            deterministic_ticket_record_id(
                "finding-100"
            )
        )

        second = (
            deterministic_ticket_record_id(
                "finding-100"
            )
        )

        self.assertEqual(
            first,
            second,
        )

        self.assertTrue(
            first.startswith(
                "servicenow-incident-"
            )
        )


    def test_search_uses_exact_correlation_id(
        self,
    ):
        transport = FakeTransport(
            [
                {
                    "result": [
                        {
                            "sys_id":
                                "sys-100",

                            "number":
                                "INC00100",

                            "state":
                                "ACTIVE",

                            "correlation_id":
                                "finding-100",
                        }
                    ]
                }
            ]
        )

        provider = (
            ServiceNowIncidentProvider(
                config(),
                {},
                transport,
            )
        )

        result = provider.search_ticket(
            "finding-100"
        )

        self.assertEqual(
            result.external_ticket_id,
            "sys-100",
        )

        self.assertEqual(
            result.external_ticket_number,
            "INC00100",
        )

        method, url, _, payload = (
            transport.calls[0]
        )

        self.assertEqual(
            method,
            "GET",
        )

        self.assertIsNone(
            payload
        )

        parsed = urllib.parse.urlparse(
            url
        )

        query = urllib.parse.parse_qs(
            parsed.query
        )

        self.assertEqual(
            query["sysparm_query"],
            [
                "correlation_id="
                "finding-100"
            ],
        )


    def test_search_rejects_duplicate_correlation(
        self,
    ):
        transport = FakeTransport(
            [
                {
                    "result": [
                        {
                            "sys_id": "a",
                            "number": "INC1",
                            "correlation_id":
                                "finding-100",
                        },
                        {
                            "sys_id": "b",
                            "number": "INC2",
                            "correlation_id":
                                "finding-100",
                        },
                    ]
                }
            ]
        )

        provider = (
            ServiceNowIncidentProvider(
                config(),
                {},
                transport,
            )
        )

        with self.assertRaises(
            RuntimeContractError
        ):
            provider.search_ticket(
                "finding-100"
            )


    def test_create_maps_servicenow_identity(
        self,
    ):
        transport = FakeTransport(
            [
                {
                    "result": {
                        "sys_id": "sys-100",
                        "number": "INC00100",
                        "state": "NEW",
                        "correlation_id":
                            "finding-100",
                    }
                }
            ]
        )

        provider = (
            ServiceNowIncidentProvider(
                config(),
                {},
                transport,
            )
        )

        result = provider.create_ticket(
            event()
        )

        self.assertEqual(
            result.external_ticket_id,
            "sys-100",
        )

        self.assertEqual(
            result.external_ticket_number,
            "INC00100",
        )

        method, _, _, payload = (
            transport.calls[0]
        )

        self.assertEqual(
            method,
            "POST",
        )

        self.assertEqual(
            payload["correlation_id"],
            "finding-100",
        )

        self.assertEqual(
            payload["assignment_group"],
            "NETWORK_AUTOMATION",
        )

        self.assertIn(
            "[network-compliance:"
            "finding-100]",
            payload[
                "short_description"
            ],
        )


    def test_get_ticket_uses_sys_id(
        self,
    ):
        transport = FakeTransport(
            [
                {
                    "result": {
                        "sys_id": "sys-100",
                        "number": "INC00100",
                        "state": "ACTIVE",
                        "correlation_id":
                            "finding-100",
                    }
                }
            ]
        )

        provider = (
            ServiceNowIncidentProvider(
                config(),
                {},
                transport,
            )
        )

        result = provider.get_ticket(
            "sys-100"
        )

        self.assertEqual(
            result.external_ticket_id,
            "sys-100",
        )

        method, url, _, _ = (
            transport.calls[0]
        )

        self.assertEqual(
            method,
            "GET",
        )

        self.assertIn(
            "/incident/sys-100?",
            url,
        )


    def test_resolve_updates_same_sys_id(
        self,
    ):
        transport = FakeTransport(
            [
                {
                    "result": {
                        "sys_id": "sys-100",
                        "number": "INC00100",
                        "state":
                            "INSTANCE_RESOLVED",
                        "correlation_id":
                            "finding-100",
                    }
                }
            ]
        )

        provider = (
            ServiceNowIncidentProvider(
                config(),
                {},
                transport,
            )
        )

        result = provider.resolve_ticket(
            "sys-100",
            event("RESOLVED"),
        )

        self.assertEqual(
            result.external_ticket_id,
            "sys-100",
        )

        method, url, _, payload = (
            transport.calls[0]
        )

        self.assertEqual(
            method,
            "PATCH",
        )

        self.assertIn(
            "/incident/sys-100",
            url,
        )

        self.assertEqual(
            payload["state"],
            "INSTANCE_RESOLVED",
        )

        self.assertEqual(
            payload["close_code"],
            "INSTANCE_RESOLUTION_CODE",
        )

        self.assertIn(
            "close_notes",
            payload,
        )


    def test_reopen_updates_same_sys_id(
        self,
    ):
        transport = FakeTransport(
            [
                {
                    "result": {
                        "sys_id": "sys-100",
                        "number": "INC00100",
                        "state":
                            "INSTANCE_ACTIVE",
                        "correlation_id":
                            "finding-100",
                    }
                }
            ]
        )

        provider = (
            ServiceNowIncidentProvider(
                config(),
                {},
                transport,
            )
        )

        result = provider.reopen_ticket(
            "sys-100",
            event("REOPENED"),
        )

        self.assertEqual(
            result.external_ticket_id,
            "sys-100",
        )

        _, _, _, payload = (
            transport.calls[0]
        )

        self.assertEqual(
            payload["state"],
            "INSTANCE_ACTIVE",
        )

        self.assertIn(
            "work_notes",
            payload,
        )


    def test_state_mapping_is_explicit_configuration(
        self,
    ):
        with self.assertRaises(
            RuntimeContractError
        ):
            ServiceNowConfig(
                base_url=
                    "https://example.service-now.com",

                active_state=
                    "SAME",

                resolved_state=
                    "SAME",
            )


if __name__ == "__main__":
    unittest.main()
