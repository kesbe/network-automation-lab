import importlib.util
import sys
import unittest

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SCRIPT = (
    ROOT
    / "scripts"
    / "compliance_exporter.py"
)

MODULE_NAME = "compliance_exporter_unit_test"

SPEC = importlib.util.spec_from_file_location(
    MODULE_NAME,
    SCRIPT,
)

if SPEC is None or SPEC.loader is None:
    raise RuntimeError(
        "unable to load compliance exporter"
    )

EXPORTER = importlib.util.module_from_spec(
    SPEC
)

sys.modules[MODULE_NAME] = EXPORTER

SPEC.loader.exec_module(
    EXPORTER
)


class FakeCursor:

    def __init__(
        self,
        connection,
    ):
        self.connection = connection
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ):
        return False

    def execute(
        self,
        sql,
    ):
        self.connection.queries.append(
            sql
        )

        if (
            "exporter_findings_summary"
            in sql
        ):
            self.rows = [
                (
                    "OPEN",
                    "high",
                    "auto",
                    2,
                )
            ]

        elif (
            "exporter_remediation_summary"
            in sql
        ):
            self.rows = [
                (
                    "RUNNING",
                    "auto",
                    "none",
                    1,
                )
            ]

        elif (
            "exporter_active_ticket_summary"
            in sql
        ):
            self.rows = [
                (
                    "servicenow",
                    "CHANGE",
                    "OPEN",
                    "NOT_REQUIRED",
                    1,
                )
            ]

        elif (
            "count(*)"
            in sql
            and "exporter_overview"
            in sql
        ):
            self.rows = [
                (1,)
            ]

        elif (
            "exporter_overview"
            in sql
        ):
            self.rows = [
                (
                    1,
                    0,
                    1,
                    60.0,
                )
            ]

        else:
            raise AssertionError(
                "unexpected SQL"
            )

    def fetchall(
        self,
    ):
        return list(
            self.rows
        )


class FakeConnection:

    def __init__(
        self,
    ):
        self.queries = []
        self.session_calls = []
        self.closed = False

    def cursor(
        self,
    ):
        return FakeCursor(
            self
        )

    def set_session(
        self,
        **kwargs,
    ):
        self.session_calls.append(
            kwargs
        )

    def close(
        self,
    ):
        self.closed = True


class ComplianceExporterCoreTests(
    unittest.TestCase
):

    def test_valid_configuration(self):

        config = EXPORTER.Config.from_env(
            {
                "NETAUTO_PG_HOST":
                    "postgresql.compliance-db",

                "NETAUTO_PG_DATABASE":
                    "network_compliance",

                "NETAUTO_PG_USERNAME":
                    "compliance_exporter_runtime",

                "NETAUTO_PG_PASSWORD":
                    "test-only",

                "NETAUTO_PG_PORT":
                    "5432",

                "NETAUTO_EXPORTER_PORT":
                    "9808",
            }
        )

        self.assertEqual(
            config.host,
            "postgresql.compliance-db",
        )

        self.assertEqual(
            config.database,
            "network_compliance",
        )

        self.assertEqual(
            config.username,
            "compliance_exporter_runtime",
        )

        self.assertEqual(
            config.port,
            5432,
        )

        self.assertEqual(
            config.exporter_port,
            9808,
        )

    def test_wrong_database_identity_is_rejected(self):

        with self.assertRaises(
            ValueError
        ):
            EXPORTER.Config.from_env(
                {
                    "NETAUTO_PG_HOST":
                        "postgresql",

                    "NETAUTO_PG_DATABASE":
                        "network_compliance",

                    "NETAUTO_PG_USERNAME":
                        "compliance_writer",

                    "NETAUTO_PG_PASSWORD":
                        "test-only",
                }
            )

    def test_snapshot_uses_readonly_session_and_views(self):

        connection = FakeConnection()

        config = EXPORTER.Config(
            host="test",
            port=5432,
            database="test",
            username=(
                "compliance_exporter_runtime"
            ),
            password="test-only",
        )

        snapshot = EXPORTER.collect_snapshot(
            config,
            connector=lambda supplied:
                connection,
        )

        self.assertEqual(
            connection.session_calls,
            [
                {
                    "readonly": True,
                    "autocommit": True,
                }
            ],
        )

        self.assertTrue(
            connection.closed
        )

        self.assertEqual(
            snapshot["overview"],
            (
                1,
                0,
                1,
                60.0,
            ),
        )

        sql = "\n".join(
            connection.queries
        )

        for view in (
            "exporter_findings_summary",
            "exporter_remediation_summary",
            "exporter_active_ticket_summary",
            "exporter_overview",
        ):
            self.assertIn(
                view,
                sql,
            )

        for table in (
            "compliance_findings",
            "remediation_attempts",
            "ticket_records",
        ):
            self.assertNotIn(
                f"compliance.{table}",
                sql,
            )

    def test_readiness_uses_approved_view(self):

        connection = FakeConnection()

        config = EXPORTER.Config(
            host="test",
            port=5432,
            database="test",
            username=(
                "compliance_exporter_runtime"
            ),
            password="test-only",
        )

        ready = EXPORTER.check_ready(
            config,
            connector=lambda supplied:
                connection,
        )

        self.assertTrue(
            ready
        )

        self.assertTrue(
            connection.closed
        )

        self.assertEqual(
            len(connection.queries),
            1,
        )

        self.assertIn(
            "compliance.exporter_overview",
            connection.queries[0],
        )

    def test_success_metrics_are_low_cardinality(self):

        metrics = (
            EXPORTER.render_success_metrics(
                {
                    "findings": [
                        (
                            "OPEN",
                            "high",
                            "auto",
                            2,
                        )
                    ],

                    "remediation": [
                        (
                            "RUNNING",
                            "auto",
                            "none",
                            1,
                        )
                    ],

                    "tickets": [
                        (
                            'service"now',
                            "CHANGE",
                            "OPEN",
                            "NOT_REQUIRED",
                            1,
                        )
                    ],

                    "overview": (
                        1,
                        0,
                        1,
                        60.5,
                    ),
                },
                123.25,
            )
        )

        self.assertIn(
            'status="OPEN"',
            metrics,
        )

        self.assertIn(
            'provider="service\\"now"',
            metrics,
        )

        self.assertIn(
            "network_compliance_devices_noncompliant 1",
            metrics,
        )

        self.assertIn(
            "network_compliance_active_tickets_total 1",
            metrics,
        )

        self.assertIn(
            "network_compliance_exporter_db_up 1",
            metrics,
        )

        for label in (
            "finding_id=",
            "device=",
            "target_id=",
            "event_id=",
            "workflow_job_id=",
            "remediation_job_id=",
            "recheck_job_id=",
        ):
            self.assertNotIn(
                label,
                metrics,
            )

    def test_failure_metrics_do_not_expose_stale_state(self):

        metrics = (
            EXPORTER.render_failure_metrics(
                111.5
            )
        )

        self.assertIn(
            "network_compliance_exporter_db_up 0",
            metrics,
        )

        self.assertIn(
            "111.500000",
            metrics,
        )

        self.assertNotIn(
            "network_compliance_findings{",
            metrics,
        )

        self.assertNotIn(
            "network_compliance_remediation_attempts{",
            metrics,
        )

        self.assertNotIn(
            "network_compliance_active_tickets{",
            metrics,
        )


class ComplianceExporterHttpTests(
    unittest.TestCase
):

    def setUp(
        self,
    ):

        import threading

        self.threading = threading

        self.original_collect = (
            EXPORTER.collect_snapshot
        )

        self.original_ready = (
            EXPORTER.check_ready
        )

        self.snapshot = {
            "findings": [
                (
                    "OPEN",
                    "high",
                    "auto",
                    2,
                )
            ],

            "remediation": [
                (
                    "READY",
                    "auto",
                    "none",
                    1,
                )
            ],

            "tickets": [
                (
                    "servicenow",
                    "CHANGE",
                    "OPEN",
                    "NOT_REQUIRED",
                    1,
                )
            ],

            "overview": (
                1,
                0,
                1,
                60.0,
            ),
        }

        EXPORTER.collect_snapshot = (
            lambda supplied_config:
                self.snapshot
        )

        EXPORTER.check_ready = (
            lambda supplied_config:
                True
        )

        EXPORTER.ComplianceExporterHandler.config = (
            EXPORTER.Config(
                host="test",
                port=5432,
                database="test",
                username=(
                    "compliance_exporter_runtime"
                ),
                password="test-only",
                bind_address="127.0.0.1",
                exporter_port=9808,
            )
        )

        EXPORTER.ComplianceExporterHandler.state = (
            EXPORTER.ExporterState()
        )

        self.server = (
            EXPORTER.ThreadingHTTPServer(
                (
                    "127.0.0.1",
                    0,
                ),
                EXPORTER.ComplianceExporterHandler,
            )
        )

        self.port = (
            self.server.server_address[1]
        )

        self.thread = (
            self.threading.Thread(
                target=self.server.serve_forever,
                daemon=True,
            )
        )

        self.thread.start()

    def tearDown(
        self,
    ):

        self.server.shutdown()

        self.server.server_close()

        self.thread.join(
            timeout=2
        )

        EXPORTER.collect_snapshot = (
            self.original_collect
        )

        EXPORTER.check_ready = (
            self.original_ready
        )

    def request(
        self,
        endpoint,
    ):

        from urllib.error import HTTPError
        from urllib.request import urlopen

        url = (
            "http://127.0.0.1:"
            + str(self.port)
            + endpoint
        )

        try:
            with urlopen(
                url,
                timeout=2,
            ) as response:

                return (
                    response.status,
                    response.headers,
                    response.read()
                    .decode("utf-8"),
                )

        except HTTPError as exc:

            return (
                exc.code,
                exc.headers,
                exc.read()
                .decode("utf-8"),
            )

    def test_health_ready_and_metrics(self):

        health_status, _, health_body = (
            self.request(
                "/healthz"
            )
        )

        self.assertEqual(
            health_status,
            200,
        )

        self.assertEqual(
            health_body,
            "ok\n",
        )

        ready_status, _, ready_body = (
            self.request(
                "/readyz"
            )
        )

        self.assertEqual(
            ready_status,
            200,
        )

        self.assertEqual(
            ready_body,
            "ready\n",
        )

        (
            metrics_status,
            metrics_headers,
            metrics_body,
        ) = self.request(
            "/metrics"
        )

        self.assertEqual(
            metrics_status,
            200,
        )

        self.assertIn(
            "version=0.0.4",
            metrics_headers.get(
                "Content-Type",
                "",
            ),
        )

        self.assertIn(
            "network_compliance_exporter_db_up 1",
            metrics_body,
        )

    def test_database_failure_returns_only_health_metrics(self):

        def fail_collection(
            supplied_config,
        ):
            raise RuntimeError(
                "synthetic failure"
            )

        EXPORTER.collect_snapshot = (
            fail_collection
        )

        status, _, body = (
            self.request(
                "/metrics"
            )
        )

        self.assertEqual(
            status,
            200,
        )

        self.assertIn(
            "network_compliance_exporter_db_up 0",
            body,
        )

        self.assertNotIn(
            "network_compliance_findings{",
            body,
        )

        self.assertNotIn(
            "network_compliance_remediation_attempts{",
            body,
        )

        self.assertNotIn(
            "network_compliance_active_tickets{",
            body,
        )

    def test_readiness_failure_is_503(self):

        EXPORTER.check_ready = (
            lambda supplied_config:
                False
        )

        status, _, body = (
            self.request(
                "/readyz"
            )
        )

        self.assertEqual(
            status,
            503,
        )

        self.assertEqual(
            body,
            "not-ready\n",
        )

    def test_unknown_endpoint_is_404(self):

        status, _, body = (
            self.request(
                "/remediate"
            )
        )

        self.assertEqual(
            status,
            404,
        )

        self.assertEqual(
            body,
            "not-found\n",
        )


if __name__ == "__main__":
    unittest.main()
