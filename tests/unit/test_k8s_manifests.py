"""
Validates K8s manifests in k8s/ without a live cluster.

Checks structural correctness: required fields, cross-file name
consistency, security settings, and health probe configuration.

Topology: web and worker are SEPARATE Deployments (web-deployment.yaml,
worker-deployment.yaml) so they scale/roll/resource independently; Postgres is
a StatefulSet; logs go to stdout (no PVC).
"""

from pathlib import Path
import yaml

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


def find_container(containers: list[dict], name: str) -> dict:
    for c in containers:
        if c["name"] == name:
            return c
    raise AssertionError(f"Container '{name}' not found in {[c['name'] for c in containers]}")


def assert_secret_after_configmap(container: dict) -> None:
    # "last source wins": the secret's real ALLOWED_HOSTS must override the
    # configmap placeholder, so secretRef MUST come AFTER configMapRef in
    # envFrom. Swapping the order 400s every request on the live host.
    env_from = container.get("envFrom", [])
    cfg_idx = next(i for i, e in enumerate(env_from) if "configMapRef" in e)
    sec_idx = next(i for i, e in enumerate(env_from) if "secretRef" in e)
    assert sec_idx > cfg_idx, (
        f"{container['name']}: secretRef (idx {sec_idx}) must come AFTER "
        f"configMapRef (idx {cfg_idx}) so the secret overrides the placeholder"
    )


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
        assert self.doc["metadata"]["namespace"] == "default"

    def test_name(self):
        assert self.doc["metadata"]["name"] == "openeasd-config"

    def test_required_keys_present(self):
        required = ["ALLOWED_HOSTS", "CSRF_TRUSTED_ORIGINS", "DEBUG", "DB_NAME"]
        for key in required:
            assert key in self.data, f"Missing key: {key}"

    def test_debug_is_false(self):
        assert self.data["DEBUG"] == "False"

    def test_db_points_at_postgres(self):
        assert self.data["DB_HOST"] == "openeasd-postgres"
        assert self.data["DB_NAME"] == "openeasd"


# ---------------------------------------------------------------------------
# Secret
# ---------------------------------------------------------------------------

class TestSecret:
    def setup_method(self):
        self.doc = single("secret.yaml")

    def test_kind(self):
        assert self.doc["kind"] == "Secret"

    def test_namespace(self):
        assert self.doc["metadata"]["namespace"] == "default"

    def test_name(self):
        assert self.doc["metadata"]["name"] == "openeasd-secret"

    def test_has_secret_key_field(self):
        assert "SECRET_KEY" in self.doc["stringData"]

    def test_secret_key_is_placeholder(self):
        # Ensure no real key was accidentally committed
        val = self.doc["stringData"]["SECRET_KEY"]
        assert "REPLACE" in val, "SECRET_KEY should be a placeholder, not a real value"

    def test_allowed_hosts_keeps_probe_host(self):
        # The kubelet probes send Host: openeasd.local and the secret's
        # ALLOWED_HOSTS overrides the configmap's — dropping openeasd.local here
        # makes the probes 400 and the pod never goes Ready (v2.1.1 fix).
        assert "openeasd.local" in self.doc["stringData"]["ALLOWED_HOSTS"]


# ---------------------------------------------------------------------------
# Web Deployment
# ---------------------------------------------------------------------------

class TestWebDeployment:
    def setup_method(self):
        self.doc = single("web-deployment.yaml")
        self.spec = self.doc["spec"]
        self.pod_spec = self.spec["template"]["spec"]

    def test_kind(self):
        assert self.doc["kind"] == "Deployment"

    def test_namespace(self):
        assert self.doc["metadata"]["namespace"] == "default"

    def test_name(self):
        assert self.doc["metadata"]["name"] == "openeasd-web"

    def test_tier_label(self):
        assert self.doc["metadata"]["labels"]["tier"] == "web"

    def test_replicas_is_one(self):
        assert self.spec["replicas"] == 1

    def test_selector_matches_template_labels(self):
        selector = self.spec["selector"]["matchLabels"]
        labels = self.spec["template"]["metadata"]["labels"]
        for key, val in selector.items():
            assert labels.get(key) == val
        assert selector.get("tier") == "web"

    # Init container — only the web tier runs migrations.
    def test_has_init_container(self):
        assert len(self.pod_spec["initContainers"]) >= 1

    def test_init_container_uses_web_image(self):
        init = self.pod_spec["initContainers"][0]
        assert "ghcr.io/cybersecify/openeasd-web" in init["image"]

    def test_init_container_runs_entrypoint(self):
        init = self.pod_spec["initContainers"][0]
        assert "docker-entrypoint.sh" in init["command"][0]

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

    def test_web_probe_sends_allowed_host(self):
        web = find_container(self.pod_spec["containers"], "web")
        headers = web["readinessProbe"]["httpGet"]["httpHeaders"]
        hosts = [h["value"] for h in headers if h["name"] == "Host"]
        assert "openeasd.local" in hosts

    def test_web_loads_configmap(self):
        web = find_container(self.pod_spec["containers"], "web")
        sources = [e["configMapRef"]["name"] for e in web.get("envFrom", []) if "configMapRef" in e]
        assert "openeasd-config" in sources

    def test_web_loads_secret(self):
        web = find_container(self.pod_spec["containers"], "web")
        sources = [e["secretRef"]["name"] for e in web.get("envFrom", []) if "secretRef" in e]
        assert "openeasd-secret" in sources

    def test_web_secret_overrides_configmap_order(self):
        assert_secret_after_configmap(find_container(self.pod_spec["containers"], "web"))

    def test_web_has_resource_limits(self):
        web = find_container(self.pod_spec["containers"], "web")
        assert "limits" in web["resources"]
        assert "requests" in web["resources"]

    def test_web_has_no_net_raw(self):
        # The internet-facing tier must not carry raw-socket capability.
        web = find_container(self.pod_spec["containers"], "web")
        caps = web.get("securityContext", {}).get("capabilities", {}).get("add", [])
        assert "NET_RAW" not in caps

    def test_web_has_no_volumes(self):
        # Logs go to stdout — no PVC.
        assert not self.pod_spec.get("volumes")


# ---------------------------------------------------------------------------
# Worker Deployment
# ---------------------------------------------------------------------------

class TestWorkerDeployment:
    def setup_method(self):
        self.doc = single("worker-deployment.yaml")
        self.spec = self.doc["spec"]
        self.pod_spec = self.spec["template"]["spec"]

    def test_kind(self):
        assert self.doc["kind"] == "Deployment"

    def test_namespace(self):
        assert self.doc["metadata"]["namespace"] == "default"

    def test_name(self):
        assert self.doc["metadata"]["name"] == "openeasd-worker"

    def test_tier_label(self):
        assert self.doc["metadata"]["labels"]["tier"] == "worker"

    def test_replicas_is_one(self):
        assert self.spec["replicas"] == 1

    def test_selector_matches_template_labels(self):
        selector = self.spec["selector"]["matchLabels"]
        labels = self.spec["template"]["metadata"]["labels"]
        for key, val in selector.items():
            assert labels.get(key) == val
        assert selector.get("tier") == "worker"

    def test_has_worker_container(self):
        find_container(self.pod_spec["containers"], "worker")

    def test_worker_uses_worker_image(self):
        worker = find_container(self.pod_spec["containers"], "worker")
        assert "ghcr.io/cybersecify/openeasd-worker" in worker["image"]

    def test_worker_command_runs_dbos_worker(self):
        worker = find_container(self.pod_spec["containers"], "worker")
        assert "dbos_worker" in worker["command"]

    def test_worker_waits_for_migrations_via_entrypoint(self):
        # No shared initContainer anymore — the worker goes through the
        # role-aware entrypoint (OPENEASD_ROLE=worker), which waits for
        # `migrate --check` before launching, so there's no DDL race.
        worker = find_container(self.pod_spec["containers"], "worker")
        assert "docker-entrypoint.sh" in worker["command"][0]
        role = {e["name"]: e["value"] for e in worker.get("env", [])}
        assert role.get("OPENEASD_ROLE") == "worker"

    def test_worker_has_no_init_container(self):
        assert not self.pod_spec.get("initContainers")

    def test_worker_has_net_raw_capability(self):
        worker = find_container(self.pod_spec["containers"], "worker")
        caps = worker["securityContext"]["capabilities"]["add"]
        assert "NET_RAW" in caps

    def test_worker_does_not_expose_ports(self):
        worker = find_container(self.pod_spec["containers"], "worker")
        assert not worker.get("ports"), "Worker should not expose ports"

    def test_worker_loads_configmap_and_secret(self):
        worker = find_container(self.pod_spec["containers"], "worker")
        cfg = [e["configMapRef"]["name"] for e in worker.get("envFrom", []) if "configMapRef" in e]
        sec = [e["secretRef"]["name"] for e in worker.get("envFrom", []) if "secretRef" in e]
        assert "openeasd-config" in cfg
        assert "openeasd-secret" in sec

    def test_worker_secret_overrides_configmap_order(self):
        assert_secret_after_configmap(find_container(self.pod_spec["containers"], "worker"))

    def test_worker_has_resource_limits(self):
        worker = find_container(self.pod_spec["containers"], "worker")
        assert "limits" in worker["resources"]
        assert "requests" in worker["resources"]

    def test_worker_has_no_volumes(self):
        assert not self.pod_spec.get("volumes")


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class TestService:
    def setup_method(self):
        self.doc = single("service.yaml")

    def test_kind(self):
        assert self.doc["kind"] == "Service"

    def test_namespace(self):
        assert self.doc["metadata"]["namespace"] == "default"

    def test_selector_targets_web_tier_only(self):
        # Must pin tier: web — the worker shares app: openeasd but has no :8000.
        selector = self.doc["spec"]["selector"]
        assert selector["app"] == "openeasd"
        assert selector["tier"] == "web"

    def test_port_80_targets_8000(self):
        port = self.doc["spec"]["ports"][0]
        assert port["port"] == 80
        assert port["targetPort"] == 8000

    def test_type_is_nodeport(self):
        assert self.doc["spec"]["type"] == "NodePort"

    def test_nodeport_in_valid_range(self):
        port = self.doc["spec"]["ports"][0]
        assert 30000 <= port["nodePort"] <= 32767


# ---------------------------------------------------------------------------
# Ingress
# ---------------------------------------------------------------------------

class TestIngress:
    def setup_method(self):
        self.doc = single("ingress.yaml")

    def test_kind(self):
        assert self.doc["kind"] == "Ingress"

    def test_namespace(self):
        assert self.doc["metadata"]["namespace"] == "default"

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
        assert self.doc["namespace"] == "default"

    def test_all_manifest_files_listed(self):
        # secret.yaml and ingress.yaml are intentionally omitted from kustomize:
        # secret is applied imperatively with a real SECRET_KEY,
        # ingress is replaced by a host-level reverse proxy (e.g. Caddy → NodePort).
        resources = self.doc["resources"]
        expected = [
            "configmap.yaml",
            "postgres.yaml",
            "web-deployment.yaml",
            "worker-deployment.yaml",
            "service.yaml",
        ]
        for f in expected:
            assert f in resources, f"{f} missing from kustomization resources"

    def test_no_missing_files_on_disk(self):
        for resource in self.doc["resources"]:
            path = K8S_DIR / resource
            assert path.exists(), f"kustomization references {resource} but file does not exist"

    def test_images_pinned_to_release_tag(self):
        images = {img["name"]: img["newTag"] for img in self.doc["images"]}
        assert images["ghcr.io/cybersecify/openeasd-web"].startswith("v")
        assert images["ghcr.io/cybersecify/openeasd-worker"].startswith("v")
