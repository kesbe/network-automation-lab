#!/usr/bin/env python3

"""
V3 network compliance Prometheus exporter.

PostgreSQL is authoritative.

This process is read-only and may query only the approved
compliance.exporter_* views.

Prometheus metrics are observability data and never drive
ticket creation, ticket closure, remediation, Kafka, EDA,
or AWX execution.
"""

from __future__ import annotations

import os
import sys
import threading
import time

from http.server import (
    BaseHTTPRequestHandler,
    ThreadingHTTPServer,
)

from dataclasses import dataclass, field
from typing import Callable, Mapping


FINDINGS_SQL = """
SELECT
    status,
    severity,
    remediation_mode,
    finding_count
FROM compliance.exporter_findings_summary
ORDER BY
    status,
    severity,
    remediation_mode;
"""


REMEDIATION_SQL = """
SELECT
    remediation_state,
    remediation_policy,
    failure_class,
    attempt_count
FROM compliance.exporter_remediation_summary
ORDER BY
    remediation_state,
    remediation_policy,
    failure_class;
"""


TICKETS_SQL = """
SELECT
    provider,
    ticket_type,
    ticket_state,
    approval_state,
    ticket_count
FROM compliance.exporter_active_ticket_summary
ORDER BY
    provider,
    ticket_type,
    ticket_state,
    approval_state;
"""


OVERVIEW_SQL = """
SELECT
    devices_noncompliant,
    remediation_waiting_approval,
    active_tickets,
    oldest_open_seconds
FROM compliance.exporter_overview;
"""


READY_SQL = """
SELECT count(*)
FROM compliance.exporter_overview;
"""


APPROVED_VIEW_NAMES = (
    "compliance.exporter_findings_summary",
    "compliance.exporter_remediation_summary",
    "compliance.exporter_active_ticket_summary",
    "compliance.exporter_overview",
)


def _parse_positive_int(
    value: str,
    name: str,
) -> int:

    try:
        parsed = int(value)

    except ValueError as exc:
        raise ValueError(
            f"{name} must be an integer"
        ) from exc

    if parsed <= 0:
        raise ValueError(
            f"{name} must be greater than zero"
        )

    return parsed


def _parse_port(
    value: str,
    name: str,
) -> int:

    parsed = _parse_positive_int(
        value,
        name,
    )

    if parsed > 65535:
        raise ValueError(
            f"{name} must be <= 65535"
        )

    return parsed


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    database: str
    username: str
    password: str = field(repr=False)

    connect_timeout: int = 5
    sslmode: str = "prefer"

    bind_address: str = "0.0.0.0"
    exporter_port: int = 9808

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> "Config":

        env = (
            os.environ
            if environ is None
            else environ
        )

        host = env.get(
            "NETAUTO_PG_HOST",
            "",
        ).strip()

        database = env.get(
            "NETAUTO_PG_DATABASE",
            "",
        ).strip()

        username = env.get(
            "NETAUTO_PG_USERNAME",
            "",
        ).strip()

        password = env.get(
            "NETAUTO_PG_PASSWORD",
            "",
        )

        if not host:
            raise ValueError(
                "NETAUTO_PG_HOST is required"
            )

        if not database:
            raise ValueError(
                "NETAUTO_PG_DATABASE is required"
            )

        if (
            username
            != "compliance_exporter_runtime"
        ):
            raise ValueError(
                "NETAUTO_PG_USERNAME must be "
                "compliance_exporter_runtime"
            )

        if not password:
            raise ValueError(
                "NETAUTO_PG_PASSWORD is required"
            )

        port = _parse_port(
            env.get(
                "NETAUTO_PG_PORT",
                "5432",
            ),
            "NETAUTO_PG_PORT",
        )

        exporter_port = _parse_port(
            env.get(
                "NETAUTO_EXPORTER_PORT",
                "9808",
            ),
            "NETAUTO_EXPORTER_PORT",
        )

        connect_timeout = _parse_positive_int(
            env.get(
                "NETAUTO_PG_CONNECT_TIMEOUT",
                "5",
            ),
            "NETAUTO_PG_CONNECT_TIMEOUT",
        )

        sslmode = env.get(
            "NETAUTO_PG_SSLMODE",
            "prefer",
        ).strip()

        allowed_sslmodes = {
            "disable",
            "allow",
            "prefer",
            "require",
            "verify-ca",
            "verify-full",
        }

        if sslmode not in allowed_sslmodes:
            raise ValueError(
                "NETAUTO_PG_SSLMODE is invalid"
            )

        bind_address = env.get(
            "NETAUTO_EXPORTER_BIND_ADDRESS",
            "0.0.0.0",
        ).strip()

        if not bind_address:
            raise ValueError(
                "NETAUTO_EXPORTER_BIND_ADDRESS "
                "is required"
            )

        return cls(
            host=host,
            port=port,
            database=database,
            username=username,
            password=password,
            connect_timeout=connect_timeout,
            sslmode=sslmode,
            bind_address=bind_address,
            exporter_port=exporter_port,
        )


def connect_db(
    config: Config,
):
    """
    Create a PostgreSQL connection.

    psycopg2 is imported lazily so offline unit tests do not
    require the PostgreSQL client library in the developer venv.
    """

    try:
        import psycopg2

    except ImportError as exc:
        raise RuntimeError(
            "psycopg2 is required at runtime"
        ) from exc

    return psycopg2.connect(
        host=config.host,
        port=config.port,
        dbname=config.database,
        user=config.username,
        password=config.password,
        connect_timeout=config.connect_timeout,
        sslmode=config.sslmode,
        application_name=(
            "network-compliance-exporter"
        ),
    )


def _query_all(
    connection,
    sql: str,
) -> list[tuple]:

    with connection.cursor() as cursor:
        cursor.execute(sql)

        return list(
            cursor.fetchall()
        )


def fetch_findings(
    connection,
) -> list[tuple]:

    return _query_all(
        connection,
        FINDINGS_SQL,
    )


def fetch_remediation(
    connection,
) -> list[tuple]:

    return _query_all(
        connection,
        REMEDIATION_SQL,
    )


def fetch_tickets(
    connection,
) -> list[tuple]:

    return _query_all(
        connection,
        TICKETS_SQL,
    )


def fetch_overview(
    connection,
) -> tuple:

    rows = _query_all(
        connection,
        OVERVIEW_SQL,
    )

    if len(rows) != 1:
        raise RuntimeError(
            "exporter_overview must return "
            "exactly one row"
        )

    row = rows[0]

    if len(row) != 4:
        raise RuntimeError(
            "exporter_overview returned "
            "unexpected column count"
        )

    return row


def collect_snapshot(
    config: Config,
    connector: Callable[[Config], object] = connect_db,
) -> dict:

    connection = connector(
        config
    )

    try:
        connection.set_session(
            readonly=True,
            autocommit=True,
        )

        return {
            "findings":
                fetch_findings(
                    connection
                ),

            "remediation":
                fetch_remediation(
                    connection
                ),

            "tickets":
                fetch_tickets(
                    connection
                ),

            "overview":
                fetch_overview(
                    connection
                ),
        }

    finally:
        connection.close()


def check_ready(
    config: Config,
    connector: Callable[[Config], object] = connect_db,
) -> bool:

    connection = connector(
        config
    )

    try:
        connection.set_session(
            readonly=True,
            autocommit=True,
        )

        rows = _query_all(
            connection,
            READY_SQL,
        )

        return (
            len(rows) == 1
            and len(rows[0]) == 1
            and int(rows[0][0]) == 1
        )

    finally:
        connection.close()


def _escape_label(
    value: object,
) -> str:

    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace('"', '\\"')
    )


def _render_labels(
    values: tuple[tuple[str, object], ...],
) -> str:

    rendered = ",".join(
        (
            f'{name}="'
            f'{_escape_label(value)}'
            f'"'
        )
        for name, value in values
    )

    return "{" + rendered + "}"


def _nonnegative_int(
    value: object,
    name: str,
) -> int:

    parsed = int(value)

    if parsed < 0:
        raise ValueError(
            f"{name} must not be negative"
        )

    return parsed


def _nonnegative_float(
    value: object,
    name: str,
) -> float:

    parsed = float(value)

    if parsed < 0:
        raise ValueError(
            f"{name} must not be negative"
        )

    return parsed


def render_success_metrics(
    snapshot: Mapping[str, object],
    success_timestamp: float,
) -> str:

    lines: list[str] = [
        "# HELP network_compliance_findings "
        "Current durable compliance findings.",
        "# TYPE network_compliance_findings gauge",
    ]

    for row in snapshot["findings"]:
        (
            status,
            severity,
            remediation_mode,
            finding_count,
        ) = row

        labels = _render_labels(
            (
                ("status", status),
                ("severity", severity),
                (
                    "remediation_mode",
                    remediation_mode,
                ),
            )
        )

        count = _nonnegative_int(
            finding_count,
            "finding_count",
        )

        lines.append(
            "network_compliance_findings"
            f"{labels} {count}"
        )

    lines.extend(
        [
            "# HELP "
            "network_compliance_remediation_attempts "
            "Remediation attempts by lifecycle state.",
            "# TYPE "
            "network_compliance_remediation_attempts gauge",
        ]
    )

    for row in snapshot["remediation"]:
        (
            state,
            policy,
            failure_class,
            attempt_count,
        ) = row

        labels = _render_labels(
            (
                ("state", state),
                ("policy", policy),
                (
                    "failure_class",
                    failure_class,
                ),
            )
        )

        count = _nonnegative_int(
            attempt_count,
            "attempt_count",
        )

        lines.append(
            "network_compliance_remediation_attempts"
            f"{labels} {count}"
        )

    lines.extend(
        [
            "# HELP network_compliance_active_tickets "
            "Active operational tickets.",
            "# TYPE network_compliance_active_tickets gauge",
        ]
    )

    for row in snapshot["tickets"]:
        (
            provider,
            ticket_type,
            state,
            approval_state,
            ticket_count,
        ) = row

        labels = _render_labels(
            (
                ("provider", provider),
                (
                    "ticket_type",
                    ticket_type,
                ),
                ("state", state),
                (
                    "approval_state",
                    approval_state,
                ),
            )
        )

        count = _nonnegative_int(
            ticket_count,
            "ticket_count",
        )

        lines.append(
            "network_compliance_active_tickets"
            f"{labels} {count}"
        )

    overview = snapshot["overview"]

    if len(overview) != 4:
        raise ValueError(
            "overview must contain four values"
        )

    (
        devices_noncompliant,
        waiting_approval,
        active_tickets,
        oldest_open_seconds,
    ) = overview

    devices_noncompliant = _nonnegative_int(
        devices_noncompliant,
        "devices_noncompliant",
    )

    waiting_approval = _nonnegative_int(
        waiting_approval,
        "remediation_waiting_approval",
    )

    active_tickets = _nonnegative_int(
        active_tickets,
        "active_tickets",
    )

    oldest_open_seconds = _nonnegative_float(
        oldest_open_seconds,
        "oldest_open_seconds",
    )

    success_timestamp = _nonnegative_float(
        success_timestamp,
        "success_timestamp",
    )

    lines.extend(
        [
            "# HELP network_compliance_devices_noncompliant "
            "Devices with OPEN or REMEDIATING findings.",
            "# TYPE "
            "network_compliance_devices_noncompliant gauge",
            "network_compliance_devices_noncompliant "
            f"{devices_noncompliant}",

            "# HELP "
            "network_compliance_remediation_waiting_approval "
            "Remediation attempts waiting for approval.",
            "# TYPE "
            "network_compliance_remediation_waiting_approval gauge",
            "network_compliance_remediation_waiting_approval "
            f"{waiting_approval}",

            "# HELP network_compliance_active_tickets_total "
            "Total active operational tickets.",
            "# TYPE network_compliance_active_tickets_total gauge",
            "network_compliance_active_tickets_total "
            f"{active_tickets}",

            "# HELP "
            "network_compliance_findings_oldest_open_seconds "
            "Age of oldest OPEN or REMEDIATING finding.",
            "# TYPE "
            "network_compliance_findings_oldest_open_seconds gauge",
            "network_compliance_findings_oldest_open_seconds "
            f"{oldest_open_seconds:.6f}",

            "# HELP network_compliance_exporter_db_up "
            "Whether the latest collection reached PostgreSQL.",
            "# TYPE network_compliance_exporter_db_up gauge",
            "network_compliance_exporter_db_up 1",

            "# HELP "
            "network_compliance_exporter_last_success_timestamp_seconds "
            "Unix timestamp of latest successful DB collection.",
            "# TYPE "
            "network_compliance_exporter_last_success_timestamp_seconds "
            "gauge",
            "network_compliance_exporter_last_success_timestamp_seconds "
            f"{success_timestamp:.6f}",
        ]
    )

    return "\n".join(lines) + "\n"


def render_failure_metrics(
    last_success_timestamp: float,
) -> str:

    timestamp = _nonnegative_float(
        last_success_timestamp,
        "last_success_timestamp",
    )

    lines = [
        "# HELP network_compliance_exporter_db_up "
        "Whether the latest collection reached PostgreSQL.",
        "# TYPE network_compliance_exporter_db_up gauge",
        "network_compliance_exporter_db_up 0",

        "# HELP "
        "network_compliance_exporter_last_success_timestamp_seconds "
        "Unix timestamp of latest successful DB collection.",
        "# TYPE "
        "network_compliance_exporter_last_success_timestamp_seconds "
        "gauge",
        "network_compliance_exporter_last_success_timestamp_seconds "
        f"{timestamp:.6f}",
    ]

    return "\n".join(lines) + "\n"


class ExporterState:

    def __init__(
        self,
    ) -> None:

        self._lock = threading.Lock()

        self._last_success_timestamp = 0.0

    def mark_success(
        self,
        timestamp: float,
    ) -> None:

        timestamp = _nonnegative_float(
            timestamp,
            "success_timestamp",
        )

        with self._lock:
            self._last_success_timestamp = (
                timestamp
            )

    def last_success_timestamp(
        self,
    ) -> float:

        with self._lock:
            return (
                self._last_success_timestamp
            )


class ComplianceExporterHandler(
    BaseHTTPRequestHandler
):

    config: Config
    state: ExporterState

    server_version = (
        "network-compliance-exporter"
    )

    sys_version = ""

    def log_message(
        self,
        format_string: str,
        *args,
    ) -> None:

        print(
            "http_request="
            + (
                format_string
                % args
            ),
            file=sys.stderr,
        )

    def _write_response(
        self,
        status: int,
        body: str,
        content_type: str,
    ) -> None:

        encoded = body.encode(
            "utf-8"
        )

        self.send_response(
            status
        )

        self.send_header(
            "Content-Type",
            content_type,
        )

        self.send_header(
            "Content-Length",
            str(len(encoded)),
        )

        self.send_header(
            "Cache-Control",
            "no-store",
        )

        self.end_headers()

        self.wfile.write(
            encoded
        )

    def do_GET(
        self,
    ) -> None:

        path = self.path.split(
            "?",
            1,
        )[0]

        if path == "/healthz":

            self._write_response(
                200,
                "ok\n",
                "text/plain; charset=utf-8",
            )

            return

        if path == "/readyz":

            try:
                ready = check_ready(
                    self.config
                )

            except Exception as exc:

                print(
                    "readiness_error="
                    + exc.__class__.__name__,
                    file=sys.stderr,
                )

                ready = False

            self._write_response(
                200 if ready else 503,
                (
                    "ready\n"
                    if ready
                    else "not-ready\n"
                ),
                "text/plain; charset=utf-8",
            )

            return

        if path == "/metrics":

            try:
                snapshot = collect_snapshot(
                    self.config
                )

                timestamp = time.time()

                self.state.mark_success(
                    timestamp
                )

                body = (
                    render_success_metrics(
                        snapshot,
                        timestamp,
                    )
                )

            except Exception as exc:

                print(
                    "collection_error="
                    + exc.__class__.__name__,
                    file=sys.stderr,
                )

                body = (
                    render_failure_metrics(
                        self.state
                        .last_success_timestamp()
                    )
                )

            self._write_response(
                200,
                body,
                (
                    "text/plain; "
                    "version=0.0.4; "
                    "charset=utf-8"
                ),
            )

            return

        self._write_response(
            404,
            "not-found\n",
            "text/plain; charset=utf-8",
        )


def main(
) -> int:

    try:
        config = Config.from_env()

    except ValueError as exc:

        print(
            "configuration_error="
            + str(exc),
            file=sys.stderr,
        )

        return 2

    ComplianceExporterHandler.config = (
        config
    )

    ComplianceExporterHandler.state = (
        ExporterState()
    )

    server = ThreadingHTTPServer(
        (
            config.bind_address,
            config.exporter_port,
        ),
        ComplianceExporterHandler,
    )

    print(
        "network_compliance_exporter=STARTED",
        file=sys.stderr,
    )

    print(
        "exporter_port="
        + str(config.exporter_port),
        file=sys.stderr,
    )

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        pass

    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
