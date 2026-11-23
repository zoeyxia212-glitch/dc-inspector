"""Static checks for deploy/kubernetes (no cluster needed): the manifests must agree with the code."""

from pathlib import Path

import pytest
import yaml

import inspector
from inspector.config import load_collector_config

ROOT = Path(__file__).resolve().parent.parent
K8S = ROOT / "deploy" / "kubernetes"


def docs(name):
    return [d for d in yaml.safe_load_all((K8S / name).read_text()) if d]


def all_resources():
    kustomization = yaml.safe_load((K8S / "kustomization.yaml").read_text())
    return [d for f in kustomization["resources"] for d in docs(f)]


def workloads():
    return [d for d in all_resources() if d["kind"] == "Deployment"]


def containers(deployment):
    spec = deployment["spec"]["template"]["spec"]
    return spec.get("initContainers", []) + spec["containers"]


def test_kustomization_files_exist():
    k = yaml.safe_load((K8S / "kustomization.yaml").read_text())
    for f in k["resources"]:
        assert (K8S / f).is_file(), f
    for gen in k["configMapGenerator"]:
        for entry in gen["files"]:
            assert (K8S / entry.split("=")[-1]).is_file(), entry


def test_image_tag_matches_release_version():
    k = yaml.safe_load((K8S / "kustomization.yaml").read_text())
    assert k["images"][0]["newTag"] == inspector.__version__


def test_config_copies_match_repository_config():
    for name in ("server.yaml", "rules.yaml"):
        assert (K8S / "config" / name).read_text() == (ROOT / "config" / name).read_text(), name


def test_collector_config_is_valid():
    settings = load_collector_config(K8S / "config" / "sh-north.yaml")
    assert settings.hosts and settings.ssh_control_dir and settings.ssh_control_dir.startswith("/run/inspector")


@pytest.mark.parametrize("deployment", workloads(), ids=lambda d: d["metadata"]["name"])
def test_restricted_security_context(deployment):
    pod = deployment["spec"]["template"]["spec"]["securityContext"]
    assert pod["runAsNonRoot"] is True and pod["runAsUser"] != 0
    assert pod["seccompProfile"]["type"] == "RuntimeDefault"
    for c in containers(deployment):
        sc = c["securityContext"]
        assert sc["allowPrivilegeEscalation"] is False, c["name"]
        assert sc["readOnlyRootFilesystem"] is True, c["name"]
        assert sc["capabilities"]["drop"] == ["ALL"], c["name"]


@pytest.mark.parametrize("deployment", workloads(), ids=lambda d: d["metadata"]["name"])
def test_resource_limits_and_single_writer(deployment):
    assert deployment["spec"]["replicas"] == 1 and deployment["spec"]["strategy"]["type"] == "Recreate"
    for c in deployment["spec"]["template"]["spec"]["containers"]:
        assert c["resources"]["requests"] and c["resources"]["limits"], c["name"]


def test_probes_point_at_real_health_endpoints(app):
    routes = {r.rule for r in app.url_map.iter_rules()}
    central = next(d for d in workloads() if d["metadata"]["name"] == "central")
    web = next(c for c in central["spec"]["template"]["spec"]["containers"] if c["name"] == "web")
    probes = {k: web[k]["httpGet"]["path"] for k in ("startupProbe", "livenessProbe", "readinessProbe")}
    assert probes["livenessProbe"] == "/health/live" and probes["readinessProbe"] == "/health/ready"
    assert set(probes.values()) <= routes


def test_secret_references_are_documented():
    example = {d["metadata"]["name"]: set(d["stringData"]) for d in docs("secrets.example.yaml")}
    for deployment in workloads():
        for c in containers(deployment):
            for ref in c.get("envFrom", []):
                assert ref["secretRef"]["name"] in example
            for env in c.get("env", []):
                key_ref = env.get("valueFrom", {}).get("secretKeyRef")
                if key_ref:
                    assert key_ref["key"] in example[key_ref["name"]], env["name"]


def test_network_policy_is_default_deny():
    policies = {d["metadata"]["name"]: d for d in docs("networkpolicy.yaml")}
    deny = policies["default-deny"]["spec"]
    assert deny["podSelector"] == {} and set(deny["policyTypes"]) == {"Ingress", "Egress"}
    assert policies["collector"]["spec"]["ingress"] == []
