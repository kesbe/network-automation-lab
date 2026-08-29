import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

DOCKERFILE = (
    ROOT
    / "containers"
    / "compliance-exporter"
    / "Dockerfile"
)


class ComplianceExporterAlpineSecurityTests(
    unittest.TestCase
):

    @classmethod
    def setUpClass(cls):
        cls.text = DOCKERFILE.read_text()

    def test_base_is_pinned_alpine_digest(self):
        expected = (
            "docker.io/library/python:"
            "3.12-alpine@"
            "sha256:"
            "d09d15e60962ca365d1cd544a48773bac"
            "9d33f2fb1b00f2aa0deec78ade7dc31"
        )

        self.assertIn(
            expected,
            self.text,
        )

    def test_openssl_security_versions_are_pinned(self):
        self.assertIn(
            "'libssl3=3.5.8-r0'",
            self.text,
        )

        self.assertIn(
            "'libcrypto3=3.5.8-r0'",
            self.text,
        )

    def test_security_upgrade_is_explicit(self):
        self.assertIn(
            "apk add",
            self.text,
        )

        self.assertIn(
            "--upgrade",
            self.text,
        )

        self.assertIn(
            "--no-cache",
            self.text,
        )

    def test_debian_base_is_not_used(self):
        self.assertNotIn(
            "python:3.12-slim",
            self.text,
        )

        self.assertNotIn(
            "apt-get",
            self.text,
        )


if __name__ == "__main__":
    unittest.main()
