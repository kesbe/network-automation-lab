import unittest

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

WORKLOAD = (
    ROOT
    / "k8s"
    / "compliance-db"
    / "compliance-exporter.yaml"
)

SERVICE_MONITOR = (
    ROOT
    / "k8s"
    / "monitoring"
    / "network-compliance-exporter-servicemonitor.yml"
)

KUSTOMIZATION = (
    ROOT
    / "k8s"
    / "compliance-db"
    / "kustomization.yaml"
)


class ComplianceExporterKubernetesTests(
    unittest.TestCase
):

    @classmethod
    def setUpClass(cls):
        cls.workload = WORKLOAD.read_text()
        cls.service_monitor = SERVICE_MONITOR.read_text()
        cls.kustomization = KUSTOMIZATION.read_text()

    def test_workload_is_in_compliance_db(self):
        self.assertIn(
            "namespace: compliance-db",
            self.workload,
        )

        self.assertIn(
            "kind: Deployment",
            self.workload,
        )

        self.assertIn(
            "kind: Service",
            self.workload,
        )

    def test_image_is_pinned_to_accepted_immutable_digest(self):
        expected = (
            "753240965685.dkr.ecr.ap-southeast-2.amazonaws.com/"
            "network-compliance-exporter"
            "@sha256:"
            "b13c5c6e171aa07d4c7150b254c308b0dfd4e510bd4ff8af7ffca747bd9701d0"
        )

        self.assertEqual(
            self.workload.count(expected),
            1,
        )

        self.assertNotIn(
            "registry.invalid/network-compliance-exporter",
            self.workload,
        )

        self.assertNotIn(
            "v3-phase7e-local",
            self.workload,
        )

        self.assertNotIn(
            "v3-phase7e-pinned-local",
            self.workload,
        )

    def test_pod_runs_nonroot_without_api_token(self):
        for value in (
            "automountServiceAccountToken: false",
            "runAsNonRoot: true",
            "runAsUser: 65532",
            "runAsGroup: 65532",
            "type: RuntimeDefault",
        ):
            self.assertIn(
                value,
                self.workload,
            )

    def test_container_is_hardened(self):
        for value in (
            "allowPrivilegeEscalation: false",
            "readOnlyRootFilesystem: true",
            "capabilities:",
            "drop:",
            "- ALL",
        ):
            self.assertIn(
                value,
                self.workload,
            )

    def test_health_and_readiness_are_separate(self):
        self.assertIn(
            "path: /healthz",
            self.workload,
        )

        self.assertIn(
            "path: /readyz",
            self.workload,
        )

        self.assertIn(
            "containerPort: 9808",
            self.workload,
        )

        self.assertIn(
            "port: 9808",
            self.workload,
        )

    def test_database_identity_is_least_privilege(self):
        for value in (
            "postgresql.compliance-db.svc",
            "network_compliance",
            "compliance_exporter_runtime",
            "name: compliance-exporter-db",
            "key: password",
        ):
            self.assertIn(
                value,
                self.workload,
            )

        self.assertNotIn(
            "postgres-admin",
            self.workload,
        )

    def test_no_control_plane_credentials_or_endpoints(self):
        forbidden = (
            "AWX_PASSWORD",
            "AWX_TOKEN",
            "EDA_TOKEN",
            "KAFKA_PASSWORD",
            "/api/v2/",
            "/remediate",
            "/approve",
            "/ticket",
        )

        for value in forbidden:
            self.assertNotIn(
                value,
                self.workload,
            )

    def test_service_monitor_selects_compliance_db(self):
        for value in (
            "kind: ServiceMonitor",
            "namespace: monitoring",
            "release: monitoring",
            "matchNames:",
            "- compliance-db",
            "port: metrics",
            "path: /metrics",
            "interval: 30s",
            "scrapeTimeout: 10s",
        ):
            self.assertIn(
                value,
                self.service_monitor,
            )

    def test_service_monitor_does_not_honor_pushed_labels(self):
        self.assertNotIn(
            "honorLabels: true",
            self.service_monitor,
        )

        self.assertNotIn(
            'device',
            self.service_monitor,
        )

    def test_workload_is_not_live_in_kustomization_yet(self):
        self.assertNotIn(
            "compliance-exporter.yaml",
            self.kustomization,
        )


if __name__ == "__main__":
    unittest.main()
