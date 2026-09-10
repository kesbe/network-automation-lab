import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]

DOCKERFILE = (
    ROOT
    / "execution-environments"
    / "ticketing-runtime-ee"
    / "Dockerfile"
)


class TicketingRuntimeImageContractTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.text = DOCKERFILE.read_text(
            encoding="utf-8"
        )

    def test_base_image_is_digest_pinned(self):
        self.assertIn(
            "FROM quay.io/ansible/awx-ee:24.6.1@sha256:"
            "89593d2a0268acacdbd1c075d8810ab50d961cf7769e36de19219bb6cb4efcc1",
            self.text,
        )

    def test_build_context_is_repository_root(self):
        self.assertIn(
            "COPY execution-environments/ticketing-runtime-ee/requirements.txt "
            "/tmp/ticketing-runtime-requirements.txt",
            self.text,
        )

        self.assertNotIn(
            "COPY requirements.txt ",
            self.text,
        )

    def test_common_runtime_is_copied(self):
        self.assertIn(
            "COPY scripts/ticketing_runtime_common.py "
            "/opt/network-compliance-ticketing/scripts/"
            "ticketing_runtime_common.py",
            self.text,
        )

    def test_publisher_is_copied(self):
        self.assertIn(
            "COPY scripts/ticketing_lifecycle_publisher.py "
            "/opt/network-compliance-ticketing/scripts/"
            "ticketing_lifecycle_publisher.py",
            self.text,
        )

    def test_adapter_is_copied(self):
        self.assertIn(
            "COPY scripts/zammad_ticketing_adapter.py "
            "/opt/network-compliance-ticketing/scripts/"
            "zammad_ticketing_adapter.py",
            self.text,
        )

    def test_runtime_scripts_are_normalized_readable(self):
        self.assertIn(
            "RUN chmod 0644 \\\n"
            "      /opt/network-compliance-ticketing/scripts/"
            "ticketing_runtime_common.py \\\n"
            "      /opt/network-compliance-ticketing/scripts/"
            "ticketing_lifecycle_publisher.py \\\n"
            "      /opt/network-compliance-ticketing/scripts/"
            "zammad_ticketing_adapter.py",
            self.text,
        )

    def test_workdir_and_pythonpath_are_frozen(self):
        self.assertIn(
            "WORKDIR /opt/network-compliance-ticketing",
            self.text,
        )

        self.assertIn(
            "ENV PYTHONPATH=/opt/network-compliance-ticketing",
            self.text,
        )

    def test_image_has_no_default_runtime_entrypoint(self):
        logical_lines = [
            line.strip()
            for line in self.text.splitlines()
            if line.strip()
        ]

        self.assertFalse(
            any(
                line.startswith("CMD ")
                or line.startswith("ENTRYPOINT ")
                for line in logical_lines
            )
        )

    def test_runtime_returns_to_non_root_user(self):
        logical_lines = [
            line.strip()
            for line in self.text.splitlines()
            if line.strip()
        ]

        self.assertEqual(
            logical_lines[-1],
            "USER 1000",
        )


if __name__ == "__main__":
    unittest.main()
