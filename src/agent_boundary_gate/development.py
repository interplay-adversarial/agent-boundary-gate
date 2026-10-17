"""Portable Kubernetes development resources and independent inventory checks.

Shared-gateway integration cannot establish whole-target containment or issue
live gate receipts. All observations here are explicitly development-only.
"""

import ipaddress
import json
import os
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

from pydantic import Field, TypeAdapter, model_validator

from agent_boundary_gate import development_receiver
from agent_boundary_gate.probe_delivery import PROBE_PATH
from agent_boundary_gate.probes import validate_receiver_url
from agent_boundary_gate.receipts import ReceiptContract

ImagePin = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9./:_-]{0,240}@sha256:[0-9a-f]{64}$")]
Namespace = Annotated[str, Field(pattern=r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")]
RUN_LABEL = "agent-boundary-gate.dev/run"


class DevelopmentConfig(ReceiptContract):
    run: Annotated[str, Field(pattern=r"^gate-dev-[a-z0-9]{16}$")]
    target_namespace: Namespace
    receiver_image: ImagePin
    workload_image: ImagePin

    @model_validator(mode="after")
    def separate_namespace(self):
        if self.run == self.target_namespace:
            raise ValueError("development-target-namespace-must-be-separate")
        return self


def resources(config: DevelopmentConfig) -> dict:
    """Render fresh per-run resources; never edit the target namespace/gateway."""
    namespace = config.run
    labels = {RUN_LABEL: config.run}

    def resource(kind, name, **fields):
        return {
            "apiVersion": "v1",
            "kind": kind,
            "metadata": {"name": name, "namespace": namespace, "labels": labels},
            **fields,
        }

    items = [
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": namespace, "labels": labels},
        },
        resource(
            "ConfigMap",
            "receiver-code",
            immutable=True,
            data={"receiver.py": Path(development_receiver.__file__).read_text()},
        ),
    ]
    for name in ("allowed", "forbidden"):
        items.append(
            resource(
                "Pod",
                name,
                spec={
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "securityContext": {
                        "runAsNonRoot": True,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "receiver",
                            "image": config.receiver_image,
                            "command": ["python3", "-I", "-B", "/code/receiver.py"],
                            "env": [{"name": "GATE_ATTEMPT", "value": config.run}],
                            "ports": [{"containerPort": 8000}],
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                            "resources": {
                                "requests": {"cpu": "25m", "memory": "32Mi"},
                                "limits": {"cpu": "250m", "memory": "128Mi"},
                            },
                            "readinessProbe": {"httpGet": {"path": "/health", "port": 8000}},
                            "volumeMounts": [
                                {"name": "code", "mountPath": "/code", "readOnly": True},
                                {"name": "state", "mountPath": "/tmp"},
                            ],
                        }
                    ],
                    "volumes": [
                        {"name": "code", "configMap": {"name": "receiver-code"}},
                        {"name": "state", "emptyDir": {"medium": "Memory", "sizeLimit": "8Mi"}},
                    ],
                },
            )
        )
        items[-1]["metadata"]["labels"] = {**labels, "receiver": name}
        items.append(
            resource(
                "Service",
                name,
                spec={
                    "selector": {**labels, "receiver": name},
                    "ports": [{"port": 8000, "targetPort": 8000}],
                },
            )
        )
    items.append(
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "receivers", "namespace": namespace, "labels": labels},
            "spec": {
                "podSelector": {"matchLabels": labels},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {
                        "from": [
                            {
                                "namespaceSelector": {
                                    "matchLabels": {
                                        "kubernetes.io/metadata.name": config.target_namespace
                                    }
                                },
                                "podSelector": {
                                    "matchLabels": {"openshell.ai/boundary-role": "supervisor"}
                                },
                            }
                        ],
                        "ports": [{"protocol": "TCP", "port": 8000}],
                    }
                ],
                "egress": [],
            },
        }
    )
    return {"apiVersion": "v1", "kind": "List", "items": items}


def policy(endpoints: dict[str, str], *, weakened: bool) -> dict:
    if set(endpoints) != {"allowed", "forbidden"} or len(set(endpoints.values())) != 2:
        raise ValueError("development-paired-endpoints-required")
    for endpoint in endpoints.values():
        validate_receiver_url(endpoint)
        hostname = urlsplit(endpoint).hostname
        assert hostname is not None  # validate_receiver_url above already rejected a missing one
        if ipaddress.ip_address(hostname).version != 4:
            raise ValueError("development-ipv4-endpoints-required")
    return {
        "version": 1,
        "filesystem_policy": {
            "include_workdir": True,
            "read_only": [
                "/bin",
                "/usr",
                "/lib",
                "/proc",
                "/dev/urandom",
                "/etc",
                "/opt",
                "/var/log",
            ],
            "read_write": ["/tmp", "/dev/null"],
        },
        "landlock": {"compatibility": "best_effort"},
        "network_policies": {
            name: {
                "name": "development-" + name,
                "endpoints": [
                    {
                        "host": urlsplit(endpoints[name]).hostname,
                        "port": urlsplit(endpoints[name]).port,
                    }
                ],
                "binaries": [{"path": PROBE_PATH}],
            }
            for name in (("allowed", "forbidden") if weakened else ("allowed",))
        },
    }


def inspect_pod(pod: dict, *, uid: str, image: str, run: str) -> dict:
    """Check independent API inventory; never equate Pod facts with a VM cell."""
    TypeAdapter(ImagePin).validate_python(image)
    metadata, spec, status = pod.get("metadata", {}), pod.get("spec", {}), pod.get("status", {})
    containers = spec.get("containers", [])
    states = status.get("containerStatuses", [])
    matched = (
        bool(uid)
        and metadata.get("uid") == uid
        and metadata.get("namespace") == run
        and metadata.get("name") in ("allowed", "forbidden")
        and metadata.get("labels", {}).get(RUN_LABEL) == run
        and not metadata.get("deletionTimestamp")
        and len(containers) == len(states) == 1
        and containers[0].get("name") == states[0].get("name") == "receiver"
        and containers[0].get("image") == image
        and states[0].get("imageID", "").endswith("@" + image.split("@")[1])
        and states[0].get("ready") is True
        and type(states[0].get("restartCount")) is int
        and states[0].get("restartCount") == 0
        and status.get("phase") == "Running"
        and spec.get("automountServiceAccountToken") is False
        and not spec.get("hostNetwork")
        and not spec.get("hostPID")
        and not spec.get("hostIPC")
        and containers[0].get("securityContext", {}).get("readOnlyRootFilesystem") is True
        and containers[0].get("securityContext", {}).get("allowPrivilegeEscalation") is False
        and not containers[0].get("securityContext", {}).get("privileged")
        and containers[0].get("securityContext", {}).get("capabilities", {}).get("drop") == ["ALL"]
        and not containers[0].get("securityContext", {}).get("capabilities", {}).get("add")
        and all(
            set(volume) <= {"name", "configMap", "emptyDir"} for volume in spec.get("volumes", [])
        )
    )
    return {
        "qualification": "development-only",
        "receiver_inventory_matches": bool(matched),
        "outer_boundary_closed": False,
        "watchdog_verified": False,
        "release_eligible": False,
    }


def inspect_target_pair(
    pods: list[dict],
    *,
    namespace: str,
    pair: str,
    sandbox_id: str,
    supervisor_uid: str,
    workload_uid: str,
    workload_image: str,
) -> dict:
    """Check both registered Pod identities, not just the sandbox-id selector.

    The Kubernetes driver labels only the supervisor with sandbox-id. Its
    boundary-pair selector is required to include the workload during inspection
    and subsequent cleanup observation.
    """
    TypeAdapter(ImagePin).validate_python(workload_image)
    roles: dict[str, dict] = {}
    for pod in pods:
        metadata = pod.get("metadata", {})
        labels = metadata.get("labels", {})
        role = labels.get("openshell.ai/boundary-role")
        if (
            role in roles
            or role not in ("supervisor", "workload")
            or metadata.get("namespace") != namespace
            or labels.get("openshell.ai/boundary-pair") != pair
            or metadata.get("deletionTimestamp")
        ):
            roles = {}
            break
        roles[role] = pod
    matched = bool(pair and sandbox_id and supervisor_uid and workload_uid) and set(roles) == {
        "supervisor",
        "workload",
    }
    if matched:
        for pod in roles.values():
            status = pod.get("status", {})
            states = status.get("containerStatuses", [])
            matched = matched and (
                status.get("phase") == "Running"
                and len(states) == 1
                and states[0].get("ready") is True
                and type(states[0].get("restartCount")) is int
                and states[0].get("restartCount") == 0
            )
        matched = (
            matched
            and roles["supervisor"]["metadata"].get("uid") == supervisor_uid
            and roles["workload"]["metadata"].get("uid") == workload_uid
            and roles["supervisor"]["metadata"]["labels"].get("openshell.ai/sandbox-id")
            == sandbox_id
        )
        workload = roles["workload"]
        containers = workload.get("spec", {}).get("containers", [])
        states = workload.get("status", {}).get("containerStatuses", [])
        matched = matched and (
            len(containers) == len(states) == 1
            and containers[0].get("name") == states[0].get("name")
            and containers[0].get("image") == workload_image
            and states[0].get("imageID", "").endswith("@" + workload_image.split("@")[1])
            and type(states[0].get("restartCount")) is int
            and states[0].get("restartCount") == 0
            and states[0].get("ready") is True
            and workload.get("status", {}).get("phase") == "Running"
        )
    return {
        "qualification": "development-only",
        "target_inventory_matches": bool(matched),
        "outer_boundary_closed": False,
        "immutable_delivery_verified": False,
        "whole_cell_cleanup_verified": False,
        "release_eligible": False,
    }


def prepare(config: DevelopmentConfig, destination: Path) -> dict:
    destination.mkdir(mode=0o700, exist_ok=False)
    rendered = resources(config)
    manifest = destination / "resources.json"
    fd = os.open(manifest, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(json.dumps(rendered, indent=2) + "\n")
    return {
        "status": "development-resources-prepared",
        "qualification": "development-only",
        "release_eligible": False,
    }
