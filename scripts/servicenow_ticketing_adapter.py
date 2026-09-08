"""
ServiceNow Incident provider scaffold.

Phase-2 constraints:
* no runtime environment credential loading yet
* no database receipt wrapper yet
* no Kafka consumer yet
* no live ServiceNow calls in tests
* ServiceNow state values remain instance configuration
"""

import hashlib
import json
import urllib.parse
import urllib.request

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Protocol

from scripts.ticketing_provider import RemoteTicket
from scripts.ticketing_runtime_common import RuntimeContractError


INCIDENT_TABLE = "incident"


class JsonTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        payload: Optional[
            Mapping[str, Any]
        ] = None,
    ) -> Mapping[str, Any]:
        ...


class UrllibJsonTransport:
    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        payload: Optional[
            Mapping[str, Any]
        ] = None,
    ) -> Mapping[str, Any]:

        data = None

        if payload is not None:
            data = json.dumps(
                dict(payload),
                sort_keys=True,
                default=str,
            ).encode("utf-8")

        request = urllib.request.Request(
            url,
            data=data,
            headers=dict(headers),
            method=method,
        )

        with urllib.request.urlopen(
            request
        ) as response:

            body = response.read()

        if not body:
            return {}

        result = json.loads(
            body.decode("utf-8")
        )

        if not isinstance(
            result,
            Mapping,
        ):
            raise RuntimeContractError(
                "ServiceNow returned "
                "non-object JSON"
            )

        return dict(result)


@dataclass(frozen=True)
class ServiceNowConfig:
    base_url: str
    active_state: str
    resolved_state: str
    assignment_group: Optional[str] = None
    resolution_code: Optional[str] = None
    table: str = INCIDENT_TABLE

    def __post_init__(self) -> None:

        if (
            not isinstance(
                self.base_url,
                str,
            )
            or not self.base_url.strip()
        ):
            raise RuntimeContractError(
                "ServiceNow base_url "
                "must not be empty"
            )

        if self.table != INCIDENT_TABLE:
            raise RuntimeContractError(
                "ServiceNow provider "
                "is restricted to "
                "the incident table"
            )

        for name, value in (
            (
                "active_state",
                self.active_state,
            ),
            (
                "resolved_state",
                self.resolved_state,
            ),
        ):

            if (
                not isinstance(
                    value,
                    str,
                )
                or not value.strip()
            ):
                raise RuntimeContractError(
                    "ServiceNow "
                    + name
                    + " must not be empty"
                )

        if (
            self.active_state
            == self.resolved_state
        ):
            raise RuntimeContractError(
                "ServiceNow active and "
                "resolved states must differ"
            )


def deterministic_ticket_record_id(
    finding_id: str,
) -> str:

    digest = hashlib.sha256(
        (
            "servicenow|INCIDENT|"
            + finding_id
        ).encode("utf-8")
    ).hexdigest()

    return (
        "servicenow-incident-"
        + digest[:32]
    )


class ServiceNowIncidentProvider:
    def __init__(
        self,
        config: ServiceNowConfig,
        headers: Mapping[str, str],
        transport: Optional[
            JsonTransport
        ] = None,
    ) -> None:

        self.config = config

        self.headers = dict(
            headers
        )

        self.transport = (
            transport
            if transport is not None
            else UrllibJsonTransport()
        )


    @property
    def endpoint(self) -> str:

        return (
            self.config.base_url.rstrip("/")
            + "/api/now/table/"
            + self.config.table
        )


    def _headers(
        self,
    ) -> dict[str, str]:

        result = {
            "Accept":
                "application/json",
            "Content-Type":
                "application/json",
        }

        result.update(
            self.headers
        )

        return result


    @staticmethod
    def _result_mapping(
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:

        value = payload.get(
            "result"
        )

        if not isinstance(
            value,
            Mapping,
        ):
            raise RuntimeContractError(
                "ServiceNow response "
                "does not contain "
                "a result object"
            )

        return dict(value)


    @staticmethod
    def _remote_ticket(
        value: Mapping[str, Any],
    ) -> RemoteTicket:

        sys_id = value.get(
            "sys_id"
        )

        if (
            sys_id is None
            or str(sys_id).strip() == ""
        ):
            raise RuntimeContractError(
                "ServiceNow incident "
                "has no sys_id"
            )

        number = value.get(
            "number"
        )

        state = value.get(
            "state"
        )

        return RemoteTicket(
            external_ticket_id=
                str(sys_id),

            external_ticket_number=(
                str(number)
                if number not in (
                    None,
                    "",
                )
                else None
            ),

            state=(
                str(state)
                if state not in (
                    None,
                    "",
                )
                else None
            ),

            raw=dict(value),
        )


    @staticmethod
    def _event_summary(
        event: Mapping[str, Any],
    ) -> str:

        return json.dumps(
            {
                "source_event_id":
                    event.get(
                        "source_event_id"
                    ),

                "finding_id":
                    event.get(
                        "finding_id"
                    ),

                "run_id":
                    event.get(
                        "run_id"
                    ),

                "lifecycle_event_type":
                    event.get(
                        "lifecycle_event_type"
                    ),

                "event_time":
                    str(
                        event.get(
                            "event_time"
                        )
                    ),

                "finding_snapshot":
                    event.get(
                        "finding_snapshot",
                        {},
                    ),
            },
            sort_keys=True,
            default=str,
        )


    def search_ticket(
        self,
        finding_id: str,
    ) -> Optional[RemoteTicket]:

        encoded_query = (
            "correlation_id="
            + finding_id
        )

        query = urllib.parse.urlencode(
            {
                "sysparm_query":
                    encoded_query,

                "sysparm_fields":
                    (
                        "sys_id,"
                        "number,"
                        "state,"
                        "correlation_id"
                    ),

                "sysparm_limit":
                    "2",
            }
        )

        payload = self.transport.request(
            "GET",
            self.endpoint
            + "?"
            + query,
            self._headers(),
        )

        rows = payload.get(
            "result"
        )

        if not isinstance(
            rows,
            list,
        ):
            raise RuntimeContractError(
                "ServiceNow search "
                "does not contain "
                "a result list"
            )

        matches = [
            dict(row)
            for row in rows
            if (
                isinstance(
                    row,
                    Mapping,
                )
                and str(
                    row.get(
                        "correlation_id",
                        "",
                    )
                )
                == finding_id
            )
        ]

        if len(matches) > 1:
            raise RuntimeContractError(
                "multiple ServiceNow "
                "incidents have the "
                "same correlation_id"
            )

        if not matches:
            return None

        return self._remote_ticket(
            matches[0]
        )


    def get_ticket(
        self,
        external_ticket_id: str,
    ) -> RemoteTicket:

        query = urllib.parse.urlencode(
            {
                "sysparm_fields":
                    (
                        "sys_id,"
                        "number,"
                        "state,"
                        "correlation_id"
                    )
            }
        )

        payload = self.transport.request(
            "GET",
            self.endpoint
            + "/"
            + urllib.parse.quote(
                external_ticket_id,
                safe="",
            )
            + "?"
            + query,
            self._headers(),
        )

        return self._remote_ticket(
            self._result_mapping(
                payload
            )
        )


    def create_ticket(
        self,
        event: Mapping[str, Any],
    ) -> RemoteTicket:

        finding_id = event.get(
            "finding_id"
        )

        if (
            not isinstance(
                finding_id,
                str,
            )
            or not finding_id
        ):
            raise RuntimeContractError(
                "finding_id "
                "must not be empty"
            )

        short_description = (
            "[network-compliance:"
            + finding_id
            + "] compliance finding"
        )

        payload: dict[str, Any] = {
            "correlation_id":
                finding_id,

            "short_description":
                short_description,

            "description":
                self._event_summary(
                    event
                ),
        }

        if self.config.assignment_group:
            payload[
                "assignment_group"
            ] = (
                self.config
                    .assignment_group
            )

        result = self.transport.request(
            "POST",
            self.endpoint,
            self._headers(),
            payload,
        )

        return self._remote_ticket(
            self._result_mapping(
                result
            )
        )


    def update_ticket(
        self,
        external_ticket_id: str,
        fields: Mapping[str, Any],
    ) -> RemoteTicket:

        if not fields:
            raise RuntimeContractError(
                "ServiceNow update fields "
                "must not be empty"
            )

        result = self.transport.request(
            "PATCH",
            self.endpoint
            + "/"
            + urllib.parse.quote(
                external_ticket_id,
                safe="",
            ),
            self._headers(),
            dict(fields),
        )

        return self._remote_ticket(
            self._result_mapping(
                result
            )
        )


    def resolve_ticket(
        self,
        external_ticket_id: str,
        event: Mapping[str, Any],
    ) -> RemoteTicket:

        fields: dict[str, Any] = {
            "state":
                self.config
                    .resolved_state,

            "close_notes":
                self._event_summary(
                    event
                ),
        }

        if self.config.resolution_code:
            fields[
                "close_code"
            ] = (
                self.config
                    .resolution_code
            )

        return self.update_ticket(
            external_ticket_id,
            fields,
        )


    def reopen_ticket(
        self,
        external_ticket_id: str,
        event: Mapping[str, Any],
    ) -> RemoteTicket:

        return self.update_ticket(
            external_ticket_id,
            {
                "state":
                    self.config
                        .active_state,

                "work_notes":
                    self._event_summary(
                        event
                    ),
            },
        )
