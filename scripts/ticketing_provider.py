"""
Provider-neutral ticketing contract.

This module intentionally contains no provider credentials,
database access, Kafka access, or external network I/O.
"""

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Protocol


@dataclass(frozen=True)
class RemoteTicket:
    external_ticket_id: str
    external_ticket_number: Optional[str]
    state: Optional[str]
    raw: Mapping[str, Any]


class TicketProvider(Protocol):
    def search_ticket(
        self,
        finding_id: str,
    ) -> Optional[RemoteTicket]:
        ...

    def get_ticket(
        self,
        external_ticket_id: str,
    ) -> RemoteTicket:
        ...

    def create_ticket(
        self,
        event: Mapping[str, Any],
    ) -> RemoteTicket:
        ...

    def update_ticket(
        self,
        external_ticket_id: str,
        fields: Mapping[str, Any],
    ) -> RemoteTicket:
        ...

    def resolve_ticket(
        self,
        external_ticket_id: str,
        event: Mapping[str, Any],
    ) -> RemoteTicket:
        ...

    def reopen_ticket(
        self,
        external_ticket_id: str,
        event: Mapping[str, Any],
    ) -> RemoteTicket:
        ...
