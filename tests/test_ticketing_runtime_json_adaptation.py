import unittest

from scripts.ticketing_runtime_common import (
    DatabaseConfig,
    SecurityDefinerDatabaseClient,
)


class FakeJson:
    def __init__(self, value):
        self.value = value


class FakeCursor:
    def __init__(
        self,
        fetchone_result=None,
        fetchall_result=None,
        description=(),
    ):
        self.fetchone_result = fetchone_result
        self.fetchall_result = list(
            fetchall_result or []
        )
        self.description = description
        self.executions = []
        self.closed = False

    def execute(
        self,
        sql,
        parameters,
    ):
        self.executions.append(
            (
                sql,
                parameters,
            )
        )

    def fetchone(self):
        return self.fetchone_result

    def fetchall(self):
        return list(
            self.fetchall_result
        )

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(
        self,
        cursor,
    ):
        self.cursor_object = cursor
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self):
        return self.cursor_object

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


def database_config():
    return DatabaseConfig(
        host="db",
        port=5432,
        database="network_compliance",
        user="runtime",
        password="secret",
    )


class JsonParameterAdaptationTests(
    unittest.TestCase
):
    def test_mapping_parameter_is_json_adapted(
        self,
    ):
        client = SecurityDefinerDatabaseClient(
            database_config(),
            connect_factory=lambda **_kwargs: None,
            json_factory=FakeJson,
        )

        original = {
            "nested": {
                "enabled": True,
            },
            "items": [
                1,
                2,
            ],
        }

        result = client._adapt_parameters(
            (
                "topic",
                21,
                original,
                None,
            )
        )

        self.assertEqual(
            result[0],
            "topic",
        )
        self.assertEqual(
            result[1],
            21,
        )
        self.assertIsInstance(
            result[2],
            FakeJson,
        )
        self.assertEqual(
            result[2].value,
            original,
        )
        self.assertIsNone(
            result[3]
        )

    def test_scalar_parameters_do_not_need_psycopg2_json(
        self,
    ):
        client = SecurityDefinerDatabaseClient(
            database_config(),
            connect_factory=lambda **_kwargs: None,
        )

        parameters = (
            "finding-1",
            21,
            None,
        )

        self.assertEqual(
            client._adapt_parameters(
                parameters
            ),
            parameters,
        )

    def test_fetch_json_adapts_claim_details(
        self,
    ):
        cursor = FakeCursor(
            fetchone_result=(
                {
                    "status":
                        "CLAIMED",
                },
            ),
        )

        connection = FakeConnection(
            cursor
        )

        client = SecurityDefinerDatabaseClient(
            database_config(),
            connect_factory=lambda **_kwargs:
                connection,
            json_factory=FakeJson,
        )

        result = client.fetch_json(
            "claim_lifecycle_event_publication",
            (
                "network.compliance.lifecycle.events",
                21,
                "publisher-1",
                300,
                {},
            ),
        )

        self.assertEqual(
            result,
            {
                "status":
                    "CLAIMED",
            },
        )

        self.assertEqual(
            len(cursor.executions),
            1,
        )

        parameters = (
            cursor.executions[0][1]
        )

        self.assertIsInstance(
            parameters[4],
            FakeJson,
        )
        self.assertEqual(
            parameters[4].value,
            {},
        )

        self.assertEqual(
            connection.commits,
            1,
        )
        self.assertEqual(
            connection.rollbacks,
            0,
        )

    def test_fetch_rows_uses_same_adapter(
        self,
    ):
        cursor = FakeCursor(
            fetchall_result=[
                (
                    21,
                ),
            ],
            description=(
                (
                    "source_event_id",
                ),
            ),
        )

        connection = FakeConnection(
            cursor
        )

        client = SecurityDefinerDatabaseClient(
            database_config(),
            connect_factory=lambda **_kwargs:
                connection,
            json_factory=FakeJson,
        )

        result = client.fetch_rows(
            "read_unpublished_ticket_lifecycle_events",
            (
                "network.compliance.lifecycle.events",
                {
                    "future_json_parameter":
                        True,
                },
            ),
        )

        self.assertEqual(
            result,
            [
                {
                    "source_event_id":
                        21,
                },
            ],
        )

        parameters = (
            cursor.executions[0][1]
        )

        self.assertIsInstance(
            parameters[1],
            FakeJson,
        )

        self.assertEqual(
            parameters[1].value,
            {
                "future_json_parameter":
                    True,
            },
        )


if __name__ == "__main__":
    unittest.main()
