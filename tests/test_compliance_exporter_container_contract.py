import unittest

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

DOCKERFILE = (
    ROOT
    / "containers"
    / "compliance-exporter"
    / "Dockerfile"
)

REQUIREMENTS = (
    ROOT
    / "containers"
    / "compliance-exporter"
    / "requirements.txt"
)


EXPECTED_BASE = (
    "ARG BASE_IMAGE="
    "docker.io/library/python:3.12-alpine"
    "@sha256:"
    "d09d15e60962ca365d1cd544a48773bac"
    "9d33f2fb1b00f2aa0deec78ade7dc31"
)


class ComplianceExporterContainerTests(
    unittest.TestCase
):

    @classmethod
    def setUpClass(cls):

        cls.dockerfile = (
            DOCKERFILE.read_text()
        )

        cls.requirements = [
            line.strip()
            for line
            in REQUIREMENTS.read_text().splitlines()
            if line.strip()
            and not line.strip().startswith("#")
        ]

    def test_base_image_is_digest_pinned(self):

        self.assertIn(
            EXPECTED_BASE,
            self.dockerfile,
        )

        self.assertNotIn(
            (
                "ARG BASE_IMAGE="
                "docker.io/library/python:"
                "3.12-alpine\n"
            ),
            self.dockerfile,
        )

    def test_only_psycopg2_runtime_dependency(self):

        self.assertEqual(
            self.requirements,
            [
                "psycopg2-binary==2.9.12"
            ],
        )

    def test_container_runs_nonroot(self):

        self.assertIn(
            "USER 65532:65532",
            self.dockerfile,
        )

        self.assertNotIn(
            "\nUSER root\n",
            self.dockerfile,
        )

    def test_expected_port_and_entrypoint(self):

        self.assertIn(
            "EXPOSE 9808",
            self.dockerfile,
        )

        self.assertIn(
            (
                'ENTRYPOINT ["python3", '
                '"/app/compliance_exporter.py"]'
            ),
            self.dockerfile,
        )

    def test_build_context_copy_is_narrow(self):

        self.assertIn(
            (
                "COPY scripts/"
                "compliance_exporter.py"
            ),
            self.dockerfile,
        )

        self.assertIn(
            (
                "COPY containers/"
                "compliance-exporter/"
                "requirements.txt"
            ),
            self.dockerfile,
        )

        forbidden = (
            "COPY . ",
            "COPY .\n",
            "ADD . ",
            "ADD .\n",
        )

        for value in forbidden:
            self.assertNotIn(
                value,
                self.dockerfile,
            )

    def test_no_credentials_or_control_plane_tools(self):

        forbidden = (
            "NETAUTO_PG_PASSWORD=",
            "AWX_PASSWORD",
            "AWX_TOKEN",
            "EDA_TOKEN",
            "KAFKA_PASSWORD",
            "ansible-galaxy",
            "kubectl",
            "curl ",
            "wget ",
        )

        for value in forbidden:
            self.assertNotIn(
                value,
                self.dockerfile,
            )


if __name__ == "__main__":
    unittest.main()
