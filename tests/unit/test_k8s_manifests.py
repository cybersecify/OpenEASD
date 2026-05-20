"""
Validates K8s manifests in k8s/ without a live cluster.

Checks structural correctness: required fields, cross-file name
consistency, security settings, and health probe configuration.
"""

from pathlib import Path
import yaml
import pytest

K8S_DIR = Path(__file__).resolve().parents[2] / "k8s"


def load(filename: str) -> list[dict]:
    """Load a YAML file and return all documents (handles multi-doc files)."""
    path = K8S_DIR / filename
    with open(path) as f:
        return [doc for doc in yaml.safe_load_all(f) if doc]


def single(filename: str) -> dict:
    """Load a single-document YAML file."""
    docs = load(filename)
    assert len(docs) == 1, f"{filename} should have exactly one document"
    return docs[0]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_container(containers: list[dict], name: str) -> dict:
    for c in containers:
        if c["name"] == name:
            return c
    raise AssertionError(f"Container '{name}' not found in {[c['name'] for c in containers]}")


def find_volume_mount(container: dict, mount_path: str) -> dict:
    for vm in container.get("volumeMounts", []):
        if vm["mountPath"] == mount_path:
            return vm
    raise AssertionError(f"volumeMount '{mount_path}' not found in container '{container['name']}'")


# ---------------------------------------------------------------------------
# Namespace
# ---------------------------------------------------------------------------

class TestNamespace:
    def test_api_version(self):
        doc = single("namespace.yaml")
        assert doc["apiVersion"] == "v1"

    def test_kind(self):
        assert single("namespace.yaml")["kind"] == "Namespace"

    def test_name_is_openeasd(self):
        assert single("namespace.yaml")["metadata"]["name"] == "openeasd"


# ---------------------------------------------------------------------------
# ConfigMap
# ---------------------------------------------------------------------------

class TestConfigMap:
    def setup_method(self):
        self.doc = single("configmap.yaml")
        self.data = self.doc["data"]

    def test_kind(self):
        assert self.doc["kind"] == "ConfigMap"

    def test_namespace(self):
        assert self.doc["metadata"]["namespace"] == "openeasd"

    def test_name(self):
        assert self.doc["metadata"]["name"] == "openeasd-config"

    def test_required_keys_present(self):
        required = ["ALLOWED_HOSTS", "CSRF_TRUSTED_ORIGINS", "DEBUG", "DB_NAME"]
        for key in required:
            assert key in self.data, f"Missing key: {key}"

    def test_debug_is_false(self):
        assert self.data["DEBUG"] == "False"

    def test_db_name_is_in_data_dir(self):
        assert self.data["DB_NAME"].startswith("data/")


# ---------------------------------------------------------------------------
# Secret
# ---------------------------------------------------------------------------

class TestSecret:
    def setup_method(self):
        self.doc = single("secret.yaml")

    def test_kind(self):
        assert self.doc["kind"] == "Secret"

    def test_namespace(self):
        assert self.doc["metadata"]["namespace"] == "openeasd"

    def test_name(self):
        assert self.doc["metadata"]["name"] == "openeasd-secret"

    def test_has_secret_key_field(self):
        assert "SECRET_KEY" in self.doc["stringData"]

    def test_secret_key_is_placeholder(self):
        # Ensure no real key was accidentally committed
        val = self.doc["stringData"]["SECRET_KEY"]
        assert "REPLACE" in val, "SECRET_KEY should be a placeholder, not a real value"


# ---------------------------------------------------------------------------
# PVCs
# ---------------------------------------------------------------------------

class TestPVCs:
    def setup_method(self):
        self.docs = load("pvc.yaml")

    def test_two_pvcs(self):
        assert len(self.docs) == 2

    def test_both_are_pvc_kind(self):
        for doc in self.docs:
            assert doc["kind"] == "PersistentVolumeClaim"

    def test_both_in_openeasd_namespace(self):
        for doc in self.docs:
            assert doc["metadata"]["namespace"] == "openeasd"

    def test_pvc_names(self):
        names = {doc["metadata"]["name"] for doc in self.docs}
        assert "openeasd-data" in names
        assert "openeasd-logs" in names

    def test_access_mode_is_rwo(self):
        for doc in self.docs:
            assert "ReadWriteOnce" in doc["spec"]["accessModes"]

    def test_data_pvc_storage_request(self):
        data_pvc = next(d for d in self.docs if d["metadata"]["name"] == "openeasd-data")
        storage = data_pvc["spec"]["resources"]["requests"]["storage"]
        # Should be at least 1Gi
        assert storage.endswith("Gi") or storage.endswith("Ti")


# ---------------------------------------------------------------------------
# Deployment
# ---------------------------------------------------------------------------

class TestDeployment:
    def setup_method(self):
        self.doc = single("deployment.yaml")
        self.spec = self.doc["spec"]
        self.pod_spec = self.spec["template"]["spec"]

    def test_kind(self):
        assert self.doc["kind"] == "Deployment"

    def test_namespace(self):
        assert self.doc["metadata"]["namespace"] == "openeasd"

    def test_name(self):
        assert self.doc["metadata"]["name"] == "openeasd"

    def test_replicas_is_one(self):
        assert self.spec["replicas"] == 1

    def test_selector_matches_template_labels(self):
        selector = self.spec["selector"]["matchLabels"]
        labels = self.spec["template"]["metadata"]["labels"]
        for key, val in selector.items():
            assert labels.get(key) == val

    # Init container
    def test_has_init_container(self):
        assert "initContainers" in self.pod_spec
        assert len(self.pod_spec["initContainers"]) >= 1

    def test_init_container_uses_correct_image(self):
        init = self.pod_spec["initContainers"][0]
        assert "ghcr.io/cybersecify/openeasd" in init["image"]

    def test_init_container_mounts_data_volume(self):
        init = self.pod_spec["initContainers"][0]
        find_volume_mount(init, "/app/data")

    # Web container
    def test_has_web_container(self):
        find_container(self.pod_spec["containers"], "web")

    def test_web_command_is_gunicorn(self):
        web = find_container(self.pod_spec["containers"], "web")
        assert web["command"][0] == "gunicorn"

    def test_web_exposes_port_8000(self):
        web = find_container(self.pod_spec["containers"], "web")
        ports = [p["containerPort"] for p in web.get("ports", [])]
        assert 8000 in ports

    def test_web_has_readiness_probe(self):
        web = find_container(self.pod_spec["containers"], "web")
        probe = web["readinessProbe"]
        assert probe["httpGet"]["path"] == "/health/"
        assert probe["httpGet"]["port"] == 8000

    def test_web_has_liveness_probe(self):
        web = find_container(self.pod_spec["containers"], "web")
        probe = web["livenessProbe"]
        assert probe["httpGet"]["path"] == "/health/"
        assert probe["httpGet"]["port"] == 8000

    def test_web_mounts_data_and_logs(self):
        web = find_container(self.pod_spec["containers"], "web")
        find_volume_mount(web, "/app/data")
        find_volume_mount(web, "/app/logs")

    def test_web_loads_configmap(self):
        web = find_container(self.pod_spec["containers"], "web")
        sources = [e["configMapRef"]["name"] for e in web.get("envFrom", []) if "configMapRef" in e]
        assert "openeasd-config" in sources

    def test_web_loads_secret(self):
        web = find_container(self.pod_spec["containers"], "web")
        sources = [e["secretRef"]["name"] for e in web.get("envFrom", []) if "secretRef" in e]
        assert "openeasd-secret" in sources

    # Worker container
    def test_has_worker_container(self):
        find_container(self.pod_spec["containers"], "worker")

    def test_worker_command_is_qcluster(self):
        worker = find_container(self.pod_spec["containers"], "worker")
        assert "qcluster" in worker["command"]

    def test_worker_has_net_raw_capability(self):
        worker = find_container(self.pod_spec["containers"], "worker")
        caps = worker["securityContext"]["capabilities"]["add"]
        assert "NET_RAW" in caps

    def test_worker_does_not_have_port_exposed(self):
        worker = find_container(self.pod_spec["containers"], "worker")
        assert not worker.get("ports"), "Worker should not expose ports"

    def test_worker_mounts_data_and_logs(self):
        worker = find_container(self.pod_spec["containers"], "worker")
        find_volume_mount(worker, "/app/data")
        find_volume_mount(worker, "/app/logs")

    # Volumes
    def test_data_volume_references_correct_pvc(self):
        volumes = {v["name"]: v for v in self.pod_spec["volumes"]}
        assert volumes["data"]["persistentVolumeClaim"]["claimName"] == "openeasd-data"

    def test_logs_volume_references_correct_pvc(self):
        volumes = {v["name"]: v for v in self.pod_spec["volumes"]}
        assert volumes["logs"]["persistentVolumeClaim"]["claimName"] == "openeasd-logs"

    # Resources
    def test_web_has_resource_limits(self):
        web = find_container(self.pod_spec["containers"], "web")
        assert "limits" in web["resources"]
        assert "requests" in web["resources"]

    def test_worker_has_resource_limits(self):
        worker = find_container(self.pod_spec["containers"], "worker")
        assert "limits" in worker["resources"]
        assert "requests" in worker["resources"]


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class TestService:
    def setup_method(self):
        self.doc = single("service.yaml")

    def test_kind(self):
        assert self.doc["kind"] == "Service"

    def test_namespace(self):
        assert self.doc["metadata"]["namespace"] == "openeasd"

    def test_selector_matches_deployment_label(self):
        assert self.doc["spec"]["selector"]["app"] == "openeasd"

    def test_port_80_targets_8000(self):
        port = self.doc["spec"]["ports"][0]
        assert port["port"] == 80
        assert port["targetPort"] == 8000

    def test_type_is_cluster_ip(self):
        assert self.doc["spec"]["type"] == "ClusterIP"


# ---------------------------------------------------------------------------
# Ingress
# ---------------------------------------------------------------------------

class TestIngress:
    def setup_method(self):
        self.doc = single("ingress.yaml")

    def test_kind(self):
        assert self.doc["kind"] == "Ingress"

    def test_namespace(self):
        assert self.doc["metadata"]["namespace"] == "openeasd"

    def test_has_rules(self):
        assert len(self.doc["spec"]["rules"]) >= 1

    def test_rule_backend_service_name(self):
        rule = self.doc["spec"]["rules"][0]
        path = rule["http"]["paths"][0]
        assert path["backend"]["service"]["name"] == "openeasd"

    def test_rule_backend_port_is_http(self):
        rule = self.doc["spec"]["rules"][0]
        path = rule["http"]["paths"][0]
        assert path["backend"]["service"]["port"]["name"] == "http"


# ---------------------------------------------------------------------------
# Kustomization
# ---------------------------------------------------------------------------

class TestKustomization:
    def setup_method(self):
        self.doc = single("kustomization.yaml")

    def test_kind(self):
        assert self.doc["kind"] == "Kustomization"

    def test_namespace(self):
        assert self.doc["namespace"] == "openeasd"

    def test_all_manifest_files_listed(self):
        resources = self.doc["resources"]
        expected = [
            "namespace.yaml",
            "configmap.yaml",
            "secret.yaml",
            "pvc.yaml",
            "deployment.yaml",
            "service.yaml",
            "ingress.yaml",
        ]
        for f in expected:
            assert f in resources, f"{f} missing from kustomization resources"

    def test_no_missing_files_on_disk(self):
        for resource in self.doc["resources"]:
            path = K8S_DIR / resource
            assert path.exists(), f"kustomization references {resource} but file does not exist"
