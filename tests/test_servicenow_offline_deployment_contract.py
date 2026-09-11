from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]

DOCKERFILE = (
    ROOT
    / "execution-environments"
    / "ticketing-runtime-ee"
    / "Dockerfile"
)

REQUIREMENTS = (
    ROOT
    / "execution-environments"
    / "ticketing-runtime-ee"
    / "requirements.txt"
)

ARTIFACT_DIR = (
    ROOT
    / "k8s"
    / "ticketing-servicenow"
)

CONFIGMAP = (
    ARTIFACT_DIR
    / "configmap.yaml"
)

DEPLOYMENT = (
    ARTIFACT_DIR
    / "deployment.yaml"
)

KUSTOMIZATION = (
    ARTIFACT_DIR
    / "kustomization.yaml"
)

SECRET_TEMPLATE = (
    ARTIFACT_DIR
    / "secret-template.yaml"
)

RUNBOOK = (
    ROOT
    / "docs"
    / "servicenow_phase5a_offline_readiness.md"
)


def text(path):
    return path.read_text(
        encoding="utf-8"
    )


class ServiceNowOfflineDeploymentContractTests(
    unittest.TestCase
):

    def test_shared_image_packages_servicenow_adapter(self):
        value = text(DOCKERFILE)

        self.assertIn(
            "COPY scripts/servicenow_ticketing_adapter.py",
            value,
        )

        self.assertIn(
            "import scripts.servicenow_ticketing_adapter",
            value,
        )

    def test_shared_image_packages_ticketing_provider(self):
        value = text(DOCKERFILE)

        self.assertIn(
            "COPY scripts/ticketing_provider.py",
            value,
        )

        self.assertIn(
            "import scripts.ticketing_provider",
            value,
        )

    def test_shared_image_preserves_zammad_runtime(self):
        value = text(DOCKERFILE)

        self.assertIn(
            "scripts/zammad_ticketing_adapter.py",
            value,
        )

        self.assertIn(
            "import scripts.zammad_ticketing_adapter",
            value,
        )

    def test_runtime_dependencies_remain_frozen(self):
        value = text(REQUIREMENTS)

        self.assertEqual(
            value.splitlines(),
            [
                "confluent-kafka==2.15.0",
                "psycopg2-binary==2.9.12",
            ],
        )

    def test_deployment_is_activated(self):
        value = text(DEPLOYMENT)

        self.assertRegex(
            value,
            r"(?m)^\s*replicas:\s*1\s*$",
        )

    def test_deployment_uses_immutable_servicenow_runtime_image(self):
        value = text(DEPLOYMENT)

        self.assertIn(
            (
                "image: "
                "753240965685.dkr.ecr.ap-southeast-2.amazonaws.com/"
                "network-compliance-ticketing-runtime@"
                "sha256:2e0354138c4a1c4da059e62cdbfe351c395a8e7b83fdd8ad974419a4e7e76b5a"
            ),
            value,
        )

    def test_deployment_invokes_servicenow_adapter(self):
        value = text(DEPLOYMENT)

        self.assertIn(
            (
                "/opt/network-compliance-ticketing/"
                "scripts/servicenow_ticketing_adapter.py"
            ),
            value,
        )

    def test_deployment_uses_config_and_secret_refs(self):
        value = text(DEPLOYMENT)

        self.assertIn(
            "name: servicenow-ticketing-runtime-config",
            value,
        )

        self.assertIn(
            "name: servicenow-ticketing-runtime-secret",
            value,
        )

    def test_configmap_contains_frozen_transport_values(self):
        value = text(CONFIGMAP)

        self.assertIn(
            (
                'TICKETING_LIFECYCLE_TOPIC: '
                '"network.compliance.lifecycle.events"'
            ),
            value,
        )

        self.assertIn(
            (
                'TICKETING_SERVICENOW_CONSUMER_GROUP: '
                '"servicenow-network-compliance-production-v1"'
            ),
            value,
        )

    def test_configmap_does_not_contain_secret_values(self):
        value = text(CONFIGMAP)

        forbidden = (
            "TICKETING_DB_USER",
            "TICKETING_DB_PASSWORD",
            "TICKETING_SERVICENOW_AUTHORIZATION",
        )

        for name in forbidden:
            self.assertNotIn(
                name,
                value,
            )

    def test_secret_template_contains_only_expected_runtime_secrets(self):
        value = text(SECRET_TEMPLATE)

        expected = {
            "TICKETING_DB_USER",
            "TICKETING_DB_PASSWORD",
            "TICKETING_SERVICENOW_AUTHORIZATION",
        }

        observed = set(
            re.findall(
                r"(?m)^\s{2}(TICKETING_[A-Z0-9_]+):",
                value,
            )
        )

        self.assertEqual(
            observed,
            expected,
        )

        self.assertNotIn(
            "Bearer ",
            value,
        )

        self.assertNotIn(
            "Basic ",
            value,
        )

    def test_pdi_values_follow_discovered_contract(self):
        value = text(CONFIGMAP)

        self.assertNotIn(
            "TICKETING_SERVICENOW_ASSIGNMENT_GROUP",
            value,
        )

        self.assertIn(
            'TICKETING_SERVICENOW_RESOLUTION_CODE: "Solution provided"',
            value,
        )

    def test_secret_template_is_excluded_from_kustomization(self):
        value = text(KUSTOMIZATION)

        resources_section = (
            value.split(
                "# secret-template.yaml",
                1,
            )[0]
        )

        self.assertNotIn(
            "secret-template.yaml",
            resources_section,
        )

        self.assertIn(
            "- configmap.yaml",
            resources_section,
        )

        self.assertIn(
            "- deployment.yaml",
            resources_section,
        )

    def test_pod_does_not_receive_service_account_token(self):
        value = text(DEPLOYMENT)

        self.assertIn(
            "automountServiceAccountToken: false",
            value,
        )

    def test_container_security_boundary_is_explicit(self):
        value = text(DEPLOYMENT)

        required = (
            "runAsNonRoot: true",
            "runAsUser: 1000",
            "allowPrivilegeEscalation: false",
            "readOnlyRootFilesystem: true",
            "type: RuntimeDefault",
            "- ALL",
        )

        for item in required:
            self.assertIn(
                item,
                value,
            )

    def test_runbook_preserves_phase5a_boundaries(self):
        value = text(RUNBOOK)

        required = (
            "ServiceNow PDI is available but has not yet been contacted or validated",
            "Migration 018 must not be applied",
            "runtime image must not be built or pushed",
            "Kubernetes resources must not be applied",
            "Kafka consumption must not be started",
            "Git push is outside this phase",
            "replicas: 0",
        )

        for item in required:
            self.assertIn(
                item,
                value,
            )


if __name__ == "__main__":
    unittest.main()
