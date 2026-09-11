"""
ServiceNow Incident provider scaffold.

Phase-2 constraints:
* no runtime environment credential loading yet
* no database receipt wrapper yet
* no Kafka consumer yet
* no live ServiceNow calls in tests
* ServiceNow state values remain instance configuration
"""

import argparse
import hashlib
import json
import os
import socket
import urllib.parse
import urllib.request

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Protocol

from scripts.ticketing_provider import RemoteTicket
from scripts.ticketing_runtime_common import (
    DatabaseConfig,
    RuntimeConfigurationError,
    RuntimeContractError,
    SecurityDefinerDatabaseClient,
    normalize_event_row,
    redact_text,
    require_claim_disposition,
    require_positive_int,
    require_value,
)


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

# ============================================================================
# ServiceNow network provisioning Change Request provider
# ============================================================================


CHANGE_REQUEST_API_PATH = (
    "/api/sn_chg_rest/change"
)


@dataclass(frozen=True)
class ServiceNowChangeConfig:
    """
    Offline/runtime contract for provisioning Change Requests.

    The Change Management API recommends specifying either a
    change model or a type.  For the provisioning PoC the
    default is a normal change.
    """

    base_url: str

    change_type: Optional[str] = (
        "normal"
    )

    change_model: Optional[str] = None

    assignment_group: Optional[str] = None


    def __post_init__(
        self,
    ) -> None:

        if (
            not isinstance(
                self.base_url,
                str,
            )
            or not self.base_url.strip()
        ):

            raise RuntimeContractError(
                "ServiceNow Change base_url "
                "must not be empty"
            )


        if self.change_type is not None:

            if (
                not isinstance(
                    self.change_type,
                    str,
                )
                or not self.change_type.strip()
            ):

                raise RuntimeContractError(
                    "ServiceNow Change type "
                    "must be a non-empty string "
                    "or None"
                )


        if self.change_model is not None:

            if (
                not isinstance(
                    self.change_model,
                    str,
                )
                or not self.change_model.strip()
            ):

                raise RuntimeContractError(
                    "ServiceNow Change model "
                    "must be a non-empty string "
                    "or None"
                )


        if (
            self.change_type is None
            and self.change_model is None
        ):

            raise RuntimeContractError(
                "ServiceNow Change requires "
                "change_type or change_model"
            )


@dataclass(frozen=True)
class ServiceNowChangeRequest:
    """
    Minimal identity returned after Change creation.
    """

    sys_id: str
    number: str
    state: Optional[str]
    approval: Optional[str]
    raw: dict[str, Any]


class ServiceNowChangeProvider:
    """
    ServiceNow Change Management API provider.

    This provider is intentionally independent from the
    existing incident provider.  SN-PROV-2 only introduces
    offline Change creation capability.
    """

    def __init__(
        self,
        config: ServiceNowChangeConfig,
        headers: Mapping[str, str],
        transport: Optional[
            JsonTransport
        ] = None,
    ) -> None:

        self.config=config

        self.headers=dict(
            headers
        )

        self.transport=(
            transport
            if transport is not None
            else UrllibJsonTransport()
        )


    @property
    def endpoint(
        self,
    ) -> str:

        return (
            self.config.base_url.rstrip("/")
            + CHANGE_REQUEST_API_PATH
        )


    def _headers(
        self,
    ) -> dict[str,str]:

        result={
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
        payload: Mapping[str,Any],
    ) -> dict[str,Any]:

        value=payload.get(
            "result"
        )

        if not isinstance(
            value,
            Mapping,
        ):

            raise RuntimeContractError(
                "ServiceNow Change response "
                "does not contain a result object"
            )

        return dict(value)


    @staticmethod
    def _field_value(
        value: Any,
    ) -> Any:
        """
        Change Management API fields can be returned either
        as plain values or as objects containing value and
        display_value.
        """

        if isinstance(
            value,
            Mapping,
        ):

            if "value" in value:

                return value.get(
                    "value"
                )

        return value


    @classmethod
    def _required_result_text(
        cls,
        result: Mapping[str,Any],
        field: str,
    ) -> str:

        value=cls._field_value(
            result.get(field)
        )

        if (
            value is None
            or str(value).strip()==""
        ):

            raise RuntimeContractError(
                "ServiceNow Change has no "
                +field
            )

        return str(value)


    @classmethod
    def _optional_result_text(
        cls,
        result: Mapping[str,Any],
        field: str,
    ) -> Optional[str]:

        value=cls._field_value(
            result.get(field)
        )

        if (
            value is None
            or str(value).strip()==""
        ):

            return None

        return str(value)


    @classmethod
    def _change_request(
        cls,
        result: Mapping[str,Any],
    ) -> ServiceNowChangeRequest:

        return ServiceNowChangeRequest(
            sys_id=
                cls._required_result_text(
                    result,
                    "sys_id",
                ),

            number=
                cls._required_result_text(
                    result,
                    "number",
                ),

            state=
                cls._optional_result_text(
                    result,
                    "state",
                ),

            approval=
                cls._optional_result_text(
                    result,
                    "approval",
                ),

            raw=dict(result),
        )


    def get_change(
        self,
        sys_id: str,
    ) -> ServiceNowChangeRequest:
        """
        Retrieve one Change Request by ServiceNow sys_id.

        This is a read-only operation and performs no
        approval action or NetBox writeback.
        """

        if (
            not isinstance(
                sys_id,
                str,
            )
            or not sys_id.strip()
        ):

            raise RuntimeContractError(
                "ServiceNow Change sys_id "
                "must not be empty"
            )


        result=self.transport.request(
            "GET",

            self.endpoint
            +"/"
            +urllib.parse.quote(
                sys_id.strip(),
                safe="",
            ),

            self._headers(),
        )


        return self._change_request(
            self._result_mapping(
                result
            )
        )


    @classmethod
    def approval_state(
        cls,
        change: ServiceNowChangeRequest,
    ) -> str:
        """
        Normalize ServiceNow Change approval state.

        Fail-closed contract:

        approved
            terminal approval

        rejected
            terminal rejection

        requested
            non-terminal

        not_requested
            non-terminal

        unknown
            non-terminal and never authorizes provisioning
        """

        if not isinstance(
            change,
            ServiceNowChangeRequest,
        ):

            raise RuntimeContractError(
                "change must be a "
                "ServiceNowChangeRequest"
            )


        value=change.approval


        if value is None:

            return "unknown"


        normalized=(
            str(value)
            .strip()
            .lower()
            .replace("_"," ")
            .replace("-"," ")
        )


        normalized=" ".join(
            normalized.split()
        )


        if normalized=="approved":

            return "approved"


        if normalized=="rejected":

            return "rejected"


        if normalized=="requested":

            return "requested"


        if normalized in {
            "not requested",
            "not yet requested",
        }:

            return "not_requested"


        return "unknown"


    @staticmethod
    def _required_text(
        intent: Mapping[str,Any],
        name: str,
    ) -> str:

        value=intent.get(
            name
        )

        if (
            not isinstance(
                value,
                str,
            )
            or not value.strip()
        ):

            raise RuntimeContractError(
                name
                +" must not be empty"
            )

        return value.strip()


    @staticmethod
    def _required_positive_int(
        intent: Mapping[str,Any],
        name: str,
    ) -> int:

        value=intent.get(
            name
        )

        if (
            isinstance(
                value,
                bool,
            )
            or not isinstance(
                value,
                int,
            )
            or value <= 0
        ):

            raise RuntimeContractError(
                name
                +" must be a positive integer"
            )

        return value


    @staticmethod
    def _optional_text(
        intent: Mapping[str,Any],
        name: str,
    ) -> Optional[str]:

        value=intent.get(
            name
        )

        if value is None:

            return None

        if not isinstance(
            value,
            str,
        ):

            raise RuntimeContractError(
                name
                +" must be a string"
            )

        value=value.strip()

        return value or None


    def create_change(
        self,
        intent: Mapping[str,Any],
    ) -> ServiceNowChangeRequest:
        """
        Create one network provisioning Change Request.

        This method performs no NetBox writeback and no
        approval processing.  Those are later SN-PROV
        phases.
        """

        device_name=(
            self._required_text(
                intent,
                "device_name",
            )
        )

        management_ip=(
            self._required_text(
                intent,
                "management_ip",
            )
        )

        role=(
            self._required_text(
                intent,
                "role",
            )
        )

        platform=(
            self._required_text(
                intent,
                "platform",
            )
        )

        bgp_asn=(
            self._required_positive_int(
                intent,
                "bgp_asn",
            )
        )

        router_id=(
            self._required_text(
                intent,
                "router_id",
            )
        )


        short_description=(
            self._optional_text(
                intent,
                "short_description",
            )
            or (
                "Provision network device "
                +device_name
            )
        )


        description=(
            self._optional_text(
                intent,
                "description",
            )
        )

        if description is None:

            description=json.dumps(
                {
                    "automation":
                        "netbox-eda-awx",

                    "device_name":
                        device_name,

                    "management_ip":
                        management_ip,

                    "role":
                        role,

                    "platform":
                        platform,

                    "bgp_asn":
                        bgp_asn,

                    "router_id":
                        router_id,
                },
                sort_keys=True,
            )


        implementation_plan=(
            self._optional_text(
                intent,
                "implementation_plan",
            )
            or (
                "Provision "
                +device_name
                +" using the approved "
                "NetBox -> EDA -> AWX "
                "network automation workflow."
            )
        )


        test_plan=(
            self._optional_text(
                intent,
                "test_plan",
            )
            or (
                "Verify management reachability, "
                "BGP ASN "
                +str(bgp_asn)
                +", and router ID "
                +router_id
                +" after provisioning."
            )
        )


        backout_plan=(
            self._optional_text(
                intent,
                "backout_plan",
            )
            or (
                "Return "
                +device_name
                +" to its pre-provisioning "
                "configuration if automated "
                "verification fails."
            )
        )


        payload: dict[str,Any]={

            "short_description":
                short_description,

            "description":
                description,

            "implementation_plan":
                implementation_plan,

            "test_plan":
                test_plan,

            "backout_plan":
                backout_plan,
        }


        if self.config.change_type:

            payload[
                "type"
            ]=self.config.change_type


        if self.config.change_model:

            payload[
                "chg_model"
            ]=self.config.change_model


        if self.config.assignment_group:

            payload[
                "assignment_group"
            ]=(
                self.config
                    .assignment_group
            )


        result=self.transport.request(
            "POST",
            self.endpoint,
            self._headers(),
            payload,
        )


        return self._change_request(
            self._result_mapping(
                result
            )
        )


    def update_change_result(
        self,
        sys_id,
        work_notes,
        state=None,
    ):
        if not isinstance(sys_id, str) or not sys_id.strip():
            raise RuntimeContractError(
                "ServiceNow Change sys_id must not be empty"
            )

        if (
            not isinstance(work_notes, str)
            or not work_notes.strip()
        ):
            raise RuntimeContractError(
                "ServiceNow Change work_notes must not be empty"
            )

        payload = {
            "work_notes": work_notes.strip(),
        }

        if state is not None:
            payload["state"] = state

        endpoint = (
            self.endpoint
            + "/"
            + urllib.parse.quote(
                sys_id.strip(),
                safe="",
            )
        )

        response = self.transport.request(
            "PATCH",
            endpoint,
            self._headers(),
            json.dumps(payload).encode("utf-8"),
        )

        result = self._result_mapping(
            response
        )

        return self._change_request(
            result
        )


# ============================================================================
# ServiceNow runtime orchestration
# ============================================================================


DEFAULT_TOPIC = "network.compliance.lifecycle.events"

DEFAULT_SERVICENOW_GROUP = (
    "servicenow-network-compliance-production-v1"
)


@dataclass(frozen=True)
class ServiceNowAdapterConfig:
    database: DatabaseConfig
    bootstrap_servers: str
    topic: str
    consumer_group: str
    instance_id: str
    lease_seconds: int
    poll_seconds: int
    servicenow: ServiceNowConfig
    authorization: str

    @classmethod
    def from_environment(
        cls,
        env: Optional[Mapping[str, str]] = None,
    ) -> "ServiceNowAdapterConfig":

        source = (
            os.environ
            if env is None
            else env
        )

        topic = require_value(
            source,
            "TICKETING_LIFECYCLE_TOPIC",
            DEFAULT_TOPIC,
        )

        group = require_value(
            source,
            "TICKETING_SERVICENOW_CONSUMER_GROUP",
            DEFAULT_SERVICENOW_GROUP,
        )

        if topic != DEFAULT_TOPIC:
            raise RuntimeConfigurationError(
                "TICKETING_LIFECYCLE_TOPIC must be "
                + DEFAULT_TOPIC
            )

        if group != DEFAULT_SERVICENOW_GROUP:
            raise RuntimeConfigurationError(
                "TICKETING_SERVICENOW_CONSUMER_GROUP "
                "must be "
                + DEFAULT_SERVICENOW_GROUP
            )

        def optional_value(
            name: str,
        ) -> Optional[str]:

            value = source.get(name)

            if value is None:
                return None

            if not isinstance(
                value,
                str,
            ):
                raise RuntimeConfigurationError(
                    name
                    + " must be a string"
                )

            value = value.strip()

            return value or None

        provider_config = ServiceNowConfig(
            base_url=require_value(
                source,
                "TICKETING_SERVICENOW_BASE_URL",
            ).rstrip("/"),

            active_state=require_value(
                source,
                "TICKETING_SERVICENOW_ACTIVE_STATE",
            ),

            resolved_state=require_value(
                source,
                "TICKETING_SERVICENOW_RESOLVED_STATE",
            ),

            assignment_group=optional_value(
                "TICKETING_SERVICENOW_ASSIGNMENT_GROUP"
            ),

            resolution_code=optional_value(
                "TICKETING_SERVICENOW_RESOLUTION_CODE"
            ),
        )

        return cls(
            database=DatabaseConfig.from_environment(
                source
            ),

            bootstrap_servers=require_value(
                source,
                "TICKETING_KAFKA_BOOTSTRAP_SERVERS",
            ),

            topic=topic,

            consumer_group=group,

            instance_id=require_value(
                source,
                "TICKETING_ADAPTER_INSTANCE_ID",
                socket.gethostname(),
            ),

            lease_seconds=require_positive_int(
                source,
                "TICKETING_RECEIPT_LEASE_SECONDS",
                default=300,
            ),

            poll_seconds=require_positive_int(
                source,
                "TICKETING_CONSUMER_POLL_SECONDS",
                default=5,
            ),

            servicenow=provider_config,

            authorization=require_value(
                source,
                "TICKETING_SERVICENOW_AUTHORIZATION",
            ),
        )


class ServiceNowReceiptRepository:
    def __init__(
        self,
        database: SecurityDefinerDatabaseClient,
    ) -> None:
        self.database = database

    def claim(
        self,
        source_event_id: int,
        instance_id: str,
        lease_seconds: int,
    ) -> Any:

        return self.database.fetch_json(
            "claim_servicenow_ticket_event_receipt",
            (
                source_event_id,
                instance_id,
                lease_seconds,
                {},
            ),
        )

    def complete(
        self,
        source_event_id: int,
        instance_id: str,
        ticket_record_id: Optional[str],
    ) -> Any:

        return self.database.fetch_json(
            "complete_servicenow_ticket_event_receipt",
            (
                source_event_id,
                instance_id,
                ticket_record_id,
                {},
            ),
        )

    def fail(
        self,
        source_event_id: int,
        instance_id: str,
        error: str,
    ) -> Any:

        return self.database.fetch_json(
            "fail_servicenow_ticket_event_receipt",
            (
                source_event_id,
                instance_id,
                error,
                {},
            ),
        )

    def read_ticket(
        self,
        finding_id: str,
    ) -> Any:

        return self.database.fetch_json(
            "read_servicenow_ticket_record",
            (
                finding_id,
            ),
        )

    def upsert_ticket(
        self,
        ticket_record_id: str,
        finding_id: str,
        external_ticket_id: Optional[str],
        external_ticket_number: Optional[str],
        ticket_state: str,
        details: Optional[
            Mapping[str, Any]
        ] = None,
    ) -> Any:

        return self.database.fetch_json(
            "upsert_servicenow_ticket_record",
            (
                ticket_record_id,
                finding_id,
                external_ticket_id,
                external_ticket_number,
                ticket_state,
                dict(details or {}),
            ),
        )

    def update_ticket(
        self,
        ticket_record_id: str,
        expected_state: str,
        new_state: str,
        external_ticket_id: Optional[str],
        external_ticket_number: Optional[str],
        last_error: Optional[str] = None,
        details: Optional[
            Mapping[str, Any]
        ] = None,
    ) -> Any:

        return self.database.fetch_json(
            "update_servicenow_ticket_record",
            (
                ticket_record_id,
                expected_state,
                new_state,
                external_ticket_id,
                external_ticket_number,
                last_error,
                dict(details or {}),
            ),
        )


def _record_field(
    value: Any,
    *names: str,
) -> Any:

    if isinstance(
        value,
        Mapping,
    ):
        for name in names:
            if name in value:
                return value[name]

    for name in names:
        if hasattr(
            value,
            name,
        ):
            return getattr(
                value,
                name,
            )

    return None


def ticket_record_id(
    record: Any,
) -> Optional[str]:

    value = _record_field(
        record,
        "ticket_record_id",
        "id",
    )

    return (
        str(value)
        if value not in (
            None,
            "",
        )
        else None
    )


def external_ticket_id(
    record: Any,
) -> Optional[str]:

    value = _record_field(
        record,
        "external_ticket_id",
        "external_id",
    )

    return (
        str(value)
        if value not in (
            None,
            "",
        )
        else None
    )


def external_ticket_number(
    record: Any,
) -> Optional[str]:

    value = _record_field(
        record,
        "external_ticket_number",
        "external_number",
        "number",
    )

    return (
        str(value)
        if value not in (
            None,
            "",
        )
        else None
    )


def ticket_state(
    record: Any,
) -> Optional[str]:

    value = _record_field(
        record,
        "ticket_state",
        "state",
    )

    return (
        str(value).upper()
        if value not in (
            None,
            "",
        )
        else None
    )


class ServiceNowTicketingAdapter:
    def __init__(
        self,
        config: ServiceNowAdapterConfig,
        repository: ServiceNowReceiptRepository,
        servicenow: ServiceNowIncidentProvider,
    ) -> None:

        self.config = config
        self.repository = repository
        self.servicenow = servicenow

    def _ensure_detected_ticket(
        self,
        event: Mapping[str, Any],
    ) -> str:

        existing = (
            self.repository.read_ticket(
                event["finding_id"]
            )
        )

        existing_id = external_ticket_id(
            existing
        )

        existing_record_id = (
            ticket_record_id(
                existing
            )
        )

        existing_state = ticket_state(
            existing
        )

        if (
            existing_id
            and existing_record_id
            and existing_state
            not in {
                "CLOSED",
                "RESOLVED",
            }
        ):
            return existing_record_id

        remote = (
            self.servicenow.search_ticket(
                event["finding_id"]
            )
        )

        if remote is None:
            remote = (
                self.servicenow.create_ticket(
                    event
                )
            )

        if not remote.external_ticket_id:
            raise RuntimeContractError(
                "ServiceNow incident "
                "has no sys_id"
            )

        record_id = (
            existing_record_id
            or deterministic_ticket_record_id(
                event["finding_id"]
            )
        )

        self.repository.upsert_ticket(
            record_id,
            event["finding_id"],
            remote.external_ticket_id,
            remote.external_ticket_number,
            "OPEN",
            {
                "source_event_id":
                    event["source_event_id"],

                "lifecycle_event_type":
                    "DETECTED",
            },
        )

        return record_id

    def _update_existing_ticket(
        self,
        event: Mapping[str, Any],
        new_local_state: str,
    ) -> str:

        if new_local_state not in {
            "OPEN",
            "CLOSED",
        }:
            raise RuntimeContractError(
                "unsupported local ticket state"
            )

        record = (
            self.repository.read_ticket(
                event["finding_id"]
            )
        )

        record_id = ticket_record_id(
            record
        )

        remote_id = external_ticket_id(
            record
        )

        current_state = ticket_state(
            record
        )

        if (
            record_id
            and remote_id
            and current_state
                == new_local_state
        ):
            return record_id

        recovery_state = (
            "CLOSED"
            if new_local_state == "OPEN"
            else "OPEN"
        )

        if not record_id or not remote_id:

            remote = (
                self.servicenow.search_ticket(
                    event["finding_id"]
                )
            )

            if remote is None:
                raise RuntimeContractError(
                    "existing ServiceNow incident "
                    "is required for lifecycle "
                    "state update"
                )

            record_id = (
                record_id
                or deterministic_ticket_record_id(
                    event["finding_id"]
                )
            )

            remote_id = (
                remote.external_ticket_id
            )

            self.repository.upsert_ticket(
                record_id,
                event["finding_id"],
                remote_id,
                remote.external_ticket_number,
                current_state
                or recovery_state,
                {
                    "recovered_by_search":
                        True,
                },
            )

            record = (
                self.repository.read_ticket(
                    event["finding_id"]
                )
            )

            current_state = (
                ticket_state(
                    record
                )
                or current_state
                or recovery_state
            )

        if new_local_state == "CLOSED":

            remote_result = (
                self.servicenow.resolve_ticket(
                    remote_id,
                    event,
                )
            )

        else:

            remote_result = (
                self.servicenow.reopen_ticket(
                    remote_id,
                    event,
                )
            )

        self.repository.update_ticket(
            record_id,
            current_state
            or recovery_state,
            new_local_state,
            remote_result.external_ticket_id,
            (
                remote_result
                    .external_ticket_number
                or external_ticket_number(
                    record
                )
            ),
            None,
            {
                "source_event_id":
                    event["source_event_id"],

                "lifecycle_event_type":
                    event[
                        "lifecycle_event_type"
                    ],
            },
        )

        return record_id

    def process_event(
        self,
        raw_event: Mapping[str, Any],
    ) -> str:

        source_row = {
            "source_event_id":
                raw_event.get(
                    "source_event_id"
                ),

            "source_finding_id":
                raw_event.get(
                    "finding_id"
                ),

            "run_id":
                raw_event.get(
                    "run_id"
                ),

            "lifecycle_event_type":
                raw_event.get(
                    "lifecycle_event_type"
                ),

            "event_time":
                raw_event.get(
                    "event_time"
                ),

            "old_status":
                raw_event.get(
                    "old_status"
                ),

            "new_status":
                raw_event.get(
                    "new_status"
                ),

            "event_details":
                raw_event.get(
                    "event_details",
                    {},
                ),

            "finding_snapshot":
                raw_event.get(
                    "finding_snapshot",
                    {},
                ),
        }

        event = normalize_event_row(
            source_row
        )

        if (
            event["finding_snapshot"].get(
                "ticket_required"
            ) is True
            and "servicenow" not in event["target_providers"]
        ):
            return "SKIPPED_NOT_TARGETED"

        claim = self.repository.claim(
            event["source_event_id"],
            self.config.instance_id,
            self.config.lease_seconds,
        )

        disposition = (
            require_claim_disposition(
                claim
            )
        )

        if disposition == "COMPLETED":
            return "ALREADY_COMPLETED"

        if disposition == "BUSY":
            return "BUSY"

        record_id: Optional[str] = None

        try:
            event_type = event[
                "lifecycle_event_type"
            ]

            if event_type == "DETECTED":

                record_id = (
                    self._ensure_detected_ticket(
                        event
                    )
                )

            elif event_type == "SEEN_AGAIN":

                existing = (
                    self.repository.read_ticket(
                        event["finding_id"]
                    )
                )

                record_id = ticket_record_id(
                    existing
                )

            elif event_type == "RESOLVED":

                record_id = (
                    self._update_existing_ticket(
                        event,
                        "CLOSED",
                    )
                )

            elif event_type == "REOPENED":

                record_id = (
                    self._update_existing_ticket(
                        event,
                        "OPEN",
                    )
                )

            else:
                raise RuntimeContractError(
                    "unsupported lifecycle event"
                )

            self.repository.complete(
                event["source_event_id"],
                self.config.instance_id,
                record_id,
            )

            return "COMPLETED"

        except Exception as exc:

            safe_error = redact_text(
                exc,
                (
                    self.config
                        .database
                        .password,

                    self.config
                        .authorization,
                ),
            )

            self.repository.fail(
                event["source_event_id"],
                self.config.instance_id,
                safe_error,
            )

            raise


class KafkaTicketConsumer:
    def __init__(
        self,
        config: ServiceNowAdapterConfig,
        adapter: ServiceNowTicketingAdapter,
        consumer: Optional[Any] = None,
    ) -> None:

        self.config = config
        self.adapter = adapter

        if consumer is None:

            from confluent_kafka import (
                Consumer,
            )

            consumer = Consumer(
                {
                    "bootstrap.servers":
                        config.bootstrap_servers,

                    "group.id":
                        config.consumer_group,

                    "enable.auto.commit":
                        False,

                    "enable.auto.offset.store":
                        False,

                    "auto.offset.reset":
                        "earliest",
                }
            )

        self.consumer = consumer

    def start(self) -> None:

        self.consumer.subscribe(
            [
                self.config.topic,
            ]
        )

    def process_message(
        self,
        message: Any,
    ) -> str:

        if message.error():
            raise RuntimeError(
                str(
                    message.error()
                )
            )

        payload = json.loads(
            message.value().decode(
                "utf-8"
            )
        )

        result = (
            self.adapter.process_event(
                payload
            )
        )

        if result in {
            "COMPLETED",
            "ALREADY_COMPLETED",
            "SKIPPED_NOT_TARGETED",
        }:

            self.consumer.commit(
                message=message,
                asynchronous=False,
            )

        return result

    def poll_once(
        self,
    ) -> Optional[str]:

        message = self.consumer.poll(
            self.config.poll_seconds
        )

        if message is None:
            return None

        return self.process_message(
            message
        )

    def close(self) -> None:

        self.consumer.close()


def build_runtime(
    config: ServiceNowAdapterConfig,
) -> KafkaTicketConsumer:

    database = (
        SecurityDefinerDatabaseClient(
            config.database
        )
    )

    repository = (
        ServiceNowReceiptRepository(
            database
        )
    )

    servicenow = (
        ServiceNowIncidentProvider(
            config.servicenow,
            {
                "Authorization":
                    config.authorization,
            },
        )
    )

    adapter = (
        ServiceNowTicketingAdapter(
            config,
            repository,
            servicenow,
        )
    )

    return KafkaTicketConsumer(
        config,
        adapter,
    )


def main() -> int:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--max-messages",
        type=int,
        default=0,
        help=(
            "0 means continue until interrupted; "
            "positive values stop after that many polls"
        ),
    )

    args = parser.parse_args()

    config = (
        ServiceNowAdapterConfig
        .from_environment()
    )

    runtime = build_runtime(
        config
    )

    processed = 0

    runtime.start()

    try:

        while (
            args.max_messages <= 0
            or processed
                < args.max_messages
        ):

            result = runtime.poll_once()

            if result is not None:
                processed += 1

    except KeyboardInterrupt:
        pass

    except Exception as exc:

        print(
            "adapter_error="
            + redact_text(
                exc,
                (
                    config
                        .database
                        .password,

                    config
                        .authorization,
                ),
            )
        )

        return 1

    finally:
        runtime.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
