"""
Validates K8s manifests in k8s/ without a live cluster.

Checks structural correctness: required fields, cross-file name
consistency, security settings, and health probe configuration.

Topology (single-image, v3.1): ONE Deployment (`app-deployment.yaml`) runs the
published single image — embedded PostgreSQL + gunicorn + the DBOS worker in one
container — with its Postgres cluster on a ReadWriteOnce PVC (`pvc.yaml`). The
PVC is single-writer, so the Deployment is pinned to one replica with the
Recreate strategy. The former 3-tier web/worker/postgres manifests are gone;
that path lives in docker-compose.yml with locally-built images.
"""

from pathlib import Path
import yaml

K8S_DIR = Path(__file__).resolve().parents[2] / "k8s"

IMAGE = "ghcr.io/cybersecify/openeasd"
PROBE_HOST = "openeasd.local"


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


def mem_to_mib(val: str) -> int:
    if val.endswith("Gi"):
        return int(val[:-2]) * 1024
    if val.endswith("Mi"):
        return int(val[:-2])
    raise AssertionError(f"unexpected memory unit: {val}")


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


def assert_health_probe(probe: dict) -> None:
    assert probe["httpGet"]["path"] == "/health/"
    assert probe["httpGet"]["port"] == 8000
    # kubelet sends the pod IP as Host by default and Django 400s it; the probe
    # must send a Host that is in ALLOWED_HOSTS.
    hosts = [h["value"] for h in probe["httpGet"]["httpHeaders"] if h["name"] == "Host"]
    assert PROBE_HOST in hosts


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

    def test_db_points_at_embedded_postgres(self):
        # The single image runs its own Postgres and forces DB_HOST=127.0.0.1
        # internally (docker/entrypoint-singleimage.sh); the configmap must agree
        # so nothing points at a Postgres Service that no longer exists.
        assert self.data["DB_HOST"] == "127.0.0.1"
        assert self.data["DB_PORT"] == "5432"
        assert self.data["DB_NAME"] == "openeasd"

    def test_db_password_not_in_configmap(self):
        # The DB password is a secret — it belongs in openeasd-secret only.
        assert "DB_PASSWORD" not in self.data


# ---------------------------------------------------------------------------
# Secret
# ---------------------------------------------------------------------------

class TestSecret:
    def setup_method(self):
        self.doc = single("secret.yaml")
        self.data = self.doc["stringData"]

    def test_kind(self):
        assert self.doc["kind"] == "Secret"

    def test_namespace(self):
        assert self.doc["metadata"]["namespace"] == "default"

    def test_name(self):
        assert self.doc["metadata"]["name"] == "openeasd-secret"

    def test_has_secret_key_field(self):
        assert "SECRET_KEY" in self.data

    def test_secret_key_is_placeholder(self):
        # Ensure no real key was accidentally committed
        assert "REPLACE" in self.data["SECRET_KEY"], "SECRET_KEY should be a placeholder"

    def test_has_db_password_placeholder(self):
        # The single image refuses to boot without DB_PASSWORD (entrypoint FATAL)
        # and the production settings guard rejects the default — so the template
        # must carry it, and must not carry a real value.
        assert "DB_PASSWORD" in self.data
        assert "REPLACE" in self.data["DB_PASSWORD"], "DB_PASSWORD should be a placeholder"

    def test_allowed_hosts_keeps_probe_host(self):
        # The kubelet probes send Host: openeasd.local and the secret's
        # ALLOWED_HOSTS overrides the configmap's — dropping openeasd.local here
        # makes the probes 400 and the pod never goes Ready (v2.1.1 fix).
        assert PROBE_HOST in self.data["ALLOWED_HOSTS"]


# ---------------------------------------------------------------------------
# App Deployment (single image)
# ---------------------------------------------------------------------------

class TestAppDeployment:
    def setup_method(self):
        self.doc = single("app-deployment.yaml")
        self.spec = self.doc["spec"]
        self.pod_spec = self.spec["template"]["spec"]
        self.app = find_container(self.pod_spec["containers"], "openeasd")

    def test_kind(self):
        assert self.doc["kind"] == "Deployment"

    def test_namespace(self):
        assert self.doc["metadata"]["namespace"] == "default"

    def test_name(self):
        assert self.doc["metadata"]["name"] == "openeasd"

    def test_selector_matches_template_labels(self):
        selector = self.spec["selector"]["matchLabels"]
        labels = self.spec["template"]["metadata"]["labels"]
        for key, val in selector.items():
            assert labels.get(key) == val
        assert selector.get("app") == "openeasd"

    # --- single-writer invariants -------------------------------------------
    def test_replicas_is_one(self):
        # Embedded Postgres on a RWO PVC: two pods must never share the cluster.
        assert self.spec["replicas"] == 1

    def test_strategy_is_recreate(self):
        # RollingUpdate would start the new pod while the old one still holds
        # the RWO volume / Postgres data dir. Recreate stops the old pod first.
        assert self.spec["strategy"]["type"] == "Recreate"

    def test_exactly_one_container(self):
        # Postgres + gunicorn + worker all run inside the one image (honcho);
        # no sidecars, no separate tiers.
        assert len(self.pod_spec["containers"]) == 1

    def test_no_init_container(self):
        # The single-image entrypoint does initdb/migrate/collectstatic/admin
        # itself; a separate init container would race it on the same PGDATA.
        assert not self.pod_spec.get("initContainers")

    # --- image --------------------------------------------------------------
    def test_uses_single_image_bare_name(self):
        # Bare name: the tag is set ONLY by kustomization.yaml images[].newTag.
        assert self.app["image"] == IMAGE

    def test_image_pull_policy_if_not_present(self):
        assert self.app["imagePullPolicy"] == "IfNotPresent"

    # --- network / capabilities --------------------------------------------
    def test_exposes_port_8000(self):
        ports = [p["containerPort"] for p in self.app.get("ports", [])]
        assert 8000 in ports

    def test_has_net_raw_capability(self):
        # nmap/naabu raw-socket scanning — the scanner tools share this pod.
        caps = self.app["securityContext"]["capabilities"]["add"]
        assert "NET_RAW" in caps

    # --- env ----------------------------------------------------------------
    def test_loads_configmap(self):
        sources = [e["configMapRef"]["name"] for e in self.app["envFrom"] if "configMapRef" in e]
        assert "openeasd-config" in sources

    def test_loads_secret(self):
        sources = [e["secretRef"]["name"] for e in self.app["envFrom"] if "secretRef" in e]
        assert "openeasd-secret" in sources

    def test_secret_overrides_configmap_order(self):
        assert_secret_after_configmap(self.app)

    # --- probes -------------------------------------------------------------
    def test_has_startup_probe(self):
        assert_health_probe(self.app["startupProbe"])

    def test_startup_probe_allows_slow_first_boot(self):
        # First boot on a fresh PVC does initdb + migrate + collectstatic + admin
        # before serving. Give it at least 5 minutes before liveness can kill it.
        probe = self.app["startupProbe"]
        budget = probe["periodSeconds"] * probe["failureThreshold"]
        assert budget >= 300, f"startupProbe budget {budget}s < 300s"

    def test_has_readiness_probe(self):
        assert_health_probe(self.app["readinessProbe"])

    def test_has_liveness_probe(self):
        assert_health_probe(self.app["livenessProbe"])

    # --- storage ------------------------------------------------------------
    def test_mounts_data_volume(self):
        # /data is mandatory: PGDATA is /data/pgdata — without a persistent
        # mount every pod replacement wipes the scan history.
        mounts = {m["mountPath"]: m["name"] for m in self.app["volumeMounts"]}
        assert "/data" in mounts
        vol = next(v for v in self.pod_spec["volumes"] if v["name"] == mounts["/data"])
        assert vol["persistentVolumeClaim"]["claimName"] == "openeasd-data"

    def test_data_pvc_name_matches_pvc_manifest(self):
        pvc = single("pvc.yaml")
        mounts = {m["mountPath"]: m["name"] for m in self.app["volumeMounts"]}
        vol = next(v for v in self.pod_spec["volumes"] if v["name"] == mounts["/data"])
        assert vol["persistentVolumeClaim"]["claimName"] == pvc["metadata"]["name"]

    # --- resources ----------------------------------------------------------
    def test_has_resource_limits(self):
        assert "limits" in self.app["resources"]
        assert "requests" in self.app["resources"]

    def test_memory_limit_survives_concurrent_scans(self):
        # The one pod runs Postgres + the scanner tools. A 1Gi Postgres was
        # OOM-killed under concurrent Passive·Deep load (exit 137) in the old
        # 3-tier layout; nuclei/amass add their own templates/brute to the same
        # limit here. Keep >= 4Gi.
        limit = self.app["resources"]["limits"]["memory"]
        assert mem_to_mib(limit) >= 4096, f"memory limit too low: {limit}"

    def test_memory_request_raised(self):
        request = self.app["resources"]["requests"]["memory"]
        assert mem_to_mib(request) >= 1024, f"memory request too low: {request}"


# ---------------------------------------------------------------------------
# PVC
# ---------------------------------------------------------------------------

class TestPVC:
    def setup_method(self):
        self.doc = single("pvc.yaml")

    def test_kind(self):
        assert self.doc["kind"] == "PersistentVolumeClaim"

    def test_namespace(self):
        assert self.doc["metadata"]["namespace"] == "default"

    def test_name(self):
        assert self.doc["metadata"]["name"] == "openeasd-data"

    def test_read_write_once(self):
        # Single-writer Postgres cluster — RWO (with Recreate on the Deployment)
        # keeps it to one pod at a time.
        assert self.doc["spec"]["accessModes"] == ["ReadWriteOnce"]

    def test_storage_size_floor(self):
        # OPERATIONS.md: start /data at 10 GB; it grows with scan history.
        size = self.doc["spec"]["resources"]["requests"]["storage"]
        assert mem_to_mib(size) >= 10 * 1024, f"PVC too small: {size}"


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

    def test_name(self):
        assert self.doc["metadata"]["name"] == "openeasd"

    def test_selector_matches_app_pod(self):
        # One pod labelled app: openeasd serves :8000. A leftover `tier: web`
        # selector would match nothing and the Service would have no endpoints.
        selector = self.doc["spec"]["selector"]
        assert selector == {"app": "openeasd"}
        deployment = single("app-deployment.yaml")
        labels = deployment["spec"]["template"]["metadata"]["labels"]
        for key, val in selector.items():
            assert labels.get(key) == val

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
# Ingress (optional — not in the kustomize base)
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
        # secret is applied imperatively with real values,
        # ingress is replaced by a host-level reverse proxy (e.g. Caddy → NodePort).
        resources = self.doc["resources"]
        expected = ["configmap.yaml", "pvc.yaml", "app-deployment.yaml", "service.yaml"]
        for f in expected:
            assert f in resources, f"{f} missing from kustomization resources"

    def test_secret_not_in_base(self):
        # Keeping the secret out of the base means `kubectl apply -k k8s/` can
        # never clobber the real ALLOWED_HOSTS / DB_PASSWORD.
        assert "secret.yaml" not in self.doc["resources"]

    def test_no_missing_files_on_disk(self):
        for resource in self.doc["resources"]:
            path = K8S_DIR / resource
            assert path.exists(), f"kustomization references {resource} but file does not exist"

    def test_images_pinned_to_release_tag(self):
        # Never pin prod to :latest — newTag is the single source of truth for
        # which version runs; rollback = set it back and re-apply.
        images = {img["name"]: img["newTag"] for img in self.doc["images"]}
        assert images[IMAGE].startswith("v"), f"newTag must be a vX.Y.Z release tag: {images[IMAGE]}"

    def test_only_single_image_pinned(self):
        # The 3-tier web/worker images are no longer published or referenced.
        names = {img["name"] for img in self.doc["images"]}
        assert names == {IMAGE}


# ---------------------------------------------------------------------------
# Directory drift guard
# ---------------------------------------------------------------------------

class TestK8sDirectory:
    def test_three_tier_manifests_removed(self):
        # The 3-tier k8s layout is gone (docker-compose.yml is the 3-tier path).
        # A stray old manifest here would be applied by someone running
        # `kubectl apply -f k8s/` and point at a Postgres Service that no longer exists.
        for stale in ("postgres.yaml", "web-deployment.yaml", "worker-deployment.yaml"):
            assert not (K8S_DIR / stale).exists(), f"stale 3-tier manifest still present: {stale}"

    def test_no_unexpected_manifests(self):
        expected = {
            "app-deployment.yaml",
            "configmap.yaml",
            "ingress.yaml",
            "kustomization.yaml",
            "pvc.yaml",
            "secret.yaml",
            "service.yaml",
        }
        actual = {p.name for p in K8S_DIR.iterdir() if p.suffix in (".yaml", ".yml")}
        assert actual == expected, f"unexpected k8s files: {actual ^ expected}"
