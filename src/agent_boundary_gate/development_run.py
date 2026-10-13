"""Private, bounded development orchestration; no authenticated gate receipts.

Journal writes precede allocation requests. Unknown allocation outcomes and identity
changes remain unresolved; recovery never deletes an unregistered target by name.
"""

import fcntl
import json
import os
import re
import secrets
import time
import weakref
from pathlib import Path
from threading import Event
from typing import Annotated
from urllib.parse import urlsplit

from pydantic import Field

from agent_boundary_gate.development import (
    RUN_LABEL,
    DevelopmentConfig,
    ImagePin,
    Namespace,
    inspect_pod,
    inspect_target_pair,
    policy,
    resources,
)
from agent_boundary_gate.doctor import read_regular_input
from agent_boundary_gate.evidence import EvidenceStore, bytes_digest
from agent_boundary_gate.probe_delivery import PROBE_PATH
from agent_boundary_gate.process import AttemptStopped, bounded_process
from agent_boundary_gate.receipts import ReceiptContract

Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


class DevelopmentRunConfig(ReceiptContract):
    target_namespace: Namespace
    receiver_image: ImagePin
    workload_image: ImagePin
    openshell_executable: Path
    openshell_digest: Digest
    kubernetes_executable: Path
    kubernetes_digest: Digest
    context: Annotated[str, Field(min_length=1, max_length=200)]
    gateway: Annotated[str, Field(min_length=1, max_length=200)]
    probe_digest: Digest
    xdg_config_home: Path | None = None
    # Optional pull grant for an operator-owned internal development registry.
    image_pull_namespace: Namespace | None = None
    command_seconds: Annotated[int, Field(ge=5, le=120)] = 30
    profile_seconds: Annotated[int, Field(ge=30, le=600)] = 300
    cleanup_seconds: Annotated[int, Field(ge=30, le=300)] = 120


def _write(path: Path, value: dict) -> None:
    pending = path.with_suffix(".pending")
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        pending.unlink(missing_ok=True)


class DevelopmentRunner:
    """Operator-owned runner. One process per private campaign; explicit recovery.

    Binaries are snapshotted from digest-checked inputs. Cluster credentials stay
    in the operator environment, outside the workload. Journals are private,
    unsigned development records, never inputs to the live gate.
    """

    def __init__(self, config: DevelopmentRunConfig, output: Path, *, recover=False):
        self.lock = None
        self._lock_finalizer = None
        self.config = config
        if not recover:
            output.mkdir(mode=0o700, exist_ok=False)
        self.store = EvidenceStore(output, create=False)
        self.output = self.store.root
        try:
            self.lock = os.open(
                self.output / "runner.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
            )
            # The callback holds only the fd, never this runner. Explicit close
            # consumes the finalizer; abandoning a library instance releases its
            # lock without performing any cluster cleanup from garbage collection.
            self._lock_finalizer = weakref.finalize(self, os.close, self.lock)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # A killed writer can leave a fsynced but uncommitted temporary. The
            # committed journal remains authoritative; never infer allocations
            # from partial content. Exclusive locking makes removal safe here.
            pending = self.output / "journal.pending"
            if pending.exists() or pending.is_symlink():
                read_regular_input(pending, limit=65536, private=True)
                pending.unlink()
            if recover:
                self.state = json.loads(
                    read_regular_input(self.output / "journal.json", limit=65536, private=True)
                )
                if not isinstance(self.state, dict) or self.state.get("version") != "1":
                    raise ValueError("development-recovery-journal-invalid")
                if self.state.get("config_digest") != bytes_digest(
                    config.model_dump_json().encode()
                ):
                    raise ValueError("development-recovery-config-mismatch")
                allocations = self.state.get("allocations")
                if not isinstance(allocations, list) or len(allocations) > 2:
                    raise ValueError("development-recovery-journal-invalid")
                for allocation in allocations:
                    if (
                        not isinstance(allocation, dict)
                        or allocation.get("profile") not in ("healthy", "weakened")
                        or not isinstance(allocation.get("sandbox_name"), str)
                        or not re.fullmatch(r"gate-[0-9a-f]{14}", allocation["sandbox_name"])
                        or not isinstance(allocation.get("receiver_uids"), dict)
                    ):
                        raise ValueError("development-recovery-journal-invalid")
                    DevelopmentConfig(
                        run=allocation.get("run"),
                        target_namespace=config.target_namespace,
                        receiver_image=config.receiver_image,
                        workload_image=config.workload_image,
                    )
            else:
                self.state = {
                    "version": "1",
                    "config_digest": bytes_digest(config.model_dump_json().encode()),
                    "allocations": [],
                    "qualification": "development-only",
                    "release_eligible": False,
                }
                self.save()
            self.binaries = {}
            for name, source, expected in (
                ("openshell", config.openshell_executable, config.openshell_digest),
                ("kubernetes", config.kubernetes_executable, config.kubernetes_digest),
            ):
                raw = read_regular_input(source, limit=256 * 1024 * 1024)
                if bytes_digest(raw) != expected:
                    raise ValueError("development-executable-digest-mismatch")
                destination = self.output / (name + "-snapshot")
                if not recover:
                    fd = os.open(
                        destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700
                    )
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(raw)
                elif (
                    bytes_digest(read_regular_input(destination, limit=len(raw), private=True))
                    != expected
                ):
                    raise ValueError("development-snapshot-digest-mismatch")
                self.binaries[name] = str(destination)
        except BaseException as error:
            self._close_after_error(error)
            raise

    def __enter__(self):
        if self.lock is None:
            raise ValueError("development-runner-closed")
        return self

    def __exit__(self, error_type, error, traceback):
        if error is None:
            self.close()
        else:
            self._close_after_error(error)
        return False

    def _close_after_error(self, error):
        try:
            self.close()
        except OSError:
            # Retain the original initialization/body error and add only a fixed
            # diagnostic; close() itself still reports failures on normal exit.
            error.add_note("development-runner-lock-close-failed")

    def close(self):
        fd, self.lock = self.lock, None
        finalizer, self._lock_finalizer = self._lock_finalizer, None
        # Clear ownership before closing. Never retry a failed close on an fd
        # number that the OS might already have released and reused.
        if finalizer is not None:
            finalizer()
        elif fd is not None:
            os.close(fd)

    def save(self):
        _write(self.output / "journal.json", self.state)

    def command(self, kind, args, *, deadline, cancelled, data=None, check=True):
        argv = [self.binaries[kind]]
        argv += (
            ["--context", self.config.context]
            if kind == "kubernetes"
            else ["--gateway", self.config.gateway]
        )
        env = dict(os.environ)
        if self.config.xdg_config_home:
            env["XDG_CONFIG_HOME"] = str(self.config.xdg_config_home)
        result = bounded_process(
            argv + args,
            deadline=min(deadline, time.monotonic() + self.config.command_seconds),
            cancelled=cancelled,
            input_data=json.dumps(data).encode() if data is not None else None,
            max_output=1024 * 1024,
            env=env,
        )
        self.store.persist(result.stdout)
        if check and result.returncode != 0:
            raise ValueError("development-command-failed")
        return result

    def query(self, kind, args, **kwargs):
        result = self.command(kind, args, **kwargs)
        value = json.loads(result.stdout) if result.stdout.strip() else {}
        if not isinstance(value, dict):
            raise ValueError("development-invalid-command-output")
        return value

    def inventory(self, allocation, **bounds):
        run = allocation["run"]
        if set(allocation["receiver_uids"]) != {"allowed", "forbidden"}:
            raise ValueError("development-receivers-unregistered")
        for name, uid in allocation["receiver_uids"].items():
            pod = self.query("kubernetes", ["get", "pod", name, "-n", run, "-o", "json"], **bounds)
            if not inspect_pod(pod, uid=uid, image=self.config.receiver_image, run=run)[
                "receiver_inventory_matches"
            ]:
                raise ValueError("development-receiver-identity-changed")
        pods = self.query(
            "kubernetes",
            [
                "get",
                "pods",
                "-n",
                self.config.target_namespace,
                "-l",
                "openshell.ai/boundary-pair=" + allocation["boundary_pair"],
                "-o",
                "json",
            ],
            **bounds,
        )["items"]
        if not inspect_target_pair(
            pods,
            namespace=self.config.target_namespace,
            pair=allocation["boundary_pair"],
            sandbox_id=allocation["sandbox_id"],
            supervisor_uid=allocation["target_uids"]["supervisor"],
            workload_uid=allocation["target_uids"]["workload"],
            workload_image=self.config.workload_image,
        )["target_inventory_matches"]:
            raise ValueError("development-target-identity-changed")

    def sample(self, allocation, **bounds):
        counts = {}
        for name, uid in allocation["receiver_uids"].items():
            pod = self.query(
                "kubernetes", ["get", "pod", name, "-n", allocation["run"], "-o", "json"], **bounds
            )
            if not inspect_pod(
                pod, uid=uid, image=self.config.receiver_image, run=allocation["run"]
            )["receiver_inventory_matches"]:
                raise ValueError("development-receiver-identity-changed")
            snapshot = self.query(
                "kubernetes",
                [
                    "exec",
                    "-n",
                    allocation["run"],
                    name,
                    "--",
                    "python3",
                    "-I",
                    "-c",
                    "from pathlib import Path;print(Path('/tmp/capture.json').read_text())",
                ],
                **bounds,
            )
            if (
                snapshot.get("attempt") != allocation["run"]
                or type(snapshot.get("count")) is not int
                or not 0 <= snapshot["count"] <= 1000000
            ):
                raise ValueError("development-capture-incomplete")
            counts[name] = snapshot["count"]
            previous = allocation.setdefault("counts", {}).get(name, 0)
            allocation["counts"][name] = max(previous, snapshot["count"])
            if (
                snapshot["count"] < previous
                or type(snapshot.get("dropped")) is not int
                or snapshot["dropped"] != 0
            ):
                allocation["capture_lost"] = True
            self.save()
        if allocation.get("capture_lost"):
            raise ValueError("development-capture-incomplete")
        return counts

    def profile(self, weakened: bool, cancelled: Event):
        run, sandbox = "gate-dev-" + secrets.token_hex(8), "gate-" + secrets.token_hex(7)
        allocation = {
            "run": run,
            "sandbox_name": sandbox,
            "profile": "weakened" if weakened else "healthy",
            "receiver_uids": {},
            "pending": None,
            "complete": False,
        }
        self.state["allocations"].append(allocation)
        self.save()
        bounds = {
            "deadline": time.monotonic() + self.config.profile_seconds,
            "cancelled": cancelled,
        }
        config = DevelopmentConfig(
            run=run,
            target_namespace=self.config.target_namespace,
            receiver_image=self.config.receiver_image,
            workload_image=self.config.workload_image,
        )
        manifest = resources(config)
        try:
            allocation["pending"] = "namespace"
            self.save()
            created = self.query(
                "kubernetes",
                ["create", "-f", "-", "-o", "json"],
                data=manifest["items"][0],
                **bounds,
            )
            allocation["namespace_uid"] = created["metadata"]["uid"]
            allocation["pending"] = None
            self.save()
            if self.config.image_pull_namespace:
                allocation["pending"] = "image-grant"
                self.save()
                grant = {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "RoleBinding",
                    "metadata": {
                        "name": run,
                        "namespace": self.config.image_pull_namespace,
                        "labels": {RUN_LABEL: run},
                    },
                    "subjects": [{"kind": "Group", "name": "system:serviceaccounts:" + run}],
                    "roleRef": {
                        "apiGroup": "rbac.authorization.k8s.io",
                        "kind": "ClusterRole",
                        "name": "system:image-puller",
                    },
                }
                created = self.query(
                    "kubernetes", ["create", "-f", "-", "-o", "json"], data=grant, **bounds
                )
                allocation["image_grant_uid"] = created["metadata"]["uid"]
                allocation["pending"] = None
                self.save()
            self.command(
                "kubernetes",
                ["create", "-f", "-"],
                data={**manifest, "items": manifest["items"][1:]},
                **bounds,
            )
            pods = self.query("kubernetes", ["get", "pods", "-n", run, "-o", "json"], **bounds)[
                "items"
            ]
            allocation["receiver_uids"] = {
                p["metadata"]["name"]: p["metadata"]["uid"] for p in pods
            }
            self.save()
            self.command(
                "kubernetes",
                ["wait", "pod", "--all", "-n", run, "--for=condition=Ready", "--timeout=90s"],
                **bounds,
            )
            services = self.query(
                "kubernetes", ["get", "services", "-n", run, "-o", "json"], **bounds
            )["items"]
            endpoints = {
                s["metadata"]["name"]: "http://" + s["spec"]["clusterIP"] + ":8000/probe"
                for s in services
            }
            expected_policy = policy(endpoints, weakened=weakened)
            policy_path = self.output / (run + "-policy.json")
            _write(policy_path, expected_policy)
            allocation["pending"] = "sandbox"
            self.save()
            self.command(
                "openshell",
                [
                    "sandbox",
                    "create",
                    "--name",
                    sandbox,
                    "--label",
                    RUN_LABEL + "=" + run,
                    "--from",
                    config.workload_image,
                    "--policy",
                    str(policy_path),
                    "--detach",
                    "--no-auto-providers",
                    "--cpu",
                    "500m",
                    "--memory",
                    "256Mi",
                    "-o",
                    "json",
                    "--",
                    "/bin/sleep",
                    "600",
                ],
                **bounds,
            )
            target = self.query("openshell", ["sandbox", "get", sandbox, "-o", "json"], **bounds)
            allocation["sandbox_id"] = target["id"]
            allocation["pending"] = None
            self.save()
            supervisors = self.query(
                "kubernetes",
                [
                    "get",
                    "pods",
                    "-n",
                    config.target_namespace,
                    "-l",
                    "openshell.ai/sandbox-id=" + target["id"],
                    "-o",
                    "json",
                ],
                **bounds,
            )["items"]
            if len(supervisors) != 1:
                raise ValueError("development-supervisor-ambiguous")
            allocation["boundary_pair"] = supervisors[0]["metadata"]["labels"][
                "openshell.ai/boundary-pair"
            ]
            pods = self.query(
                "kubernetes",
                [
                    "get",
                    "pods",
                    "-n",
                    config.target_namespace,
                    "-l",
                    "openshell.ai/boundary-pair=" + allocation["boundary_pair"],
                    "-o",
                    "json",
                ],
                **bounds,
            )["items"]
            allocation["target_uids"] = {
                p["metadata"]["labels"]["openshell.ai/boundary-role"]: p["metadata"]["uid"]
                for p in pods
            }
            self.save()
            self.inventory(allocation, **bounds)
            active = self.query(
                "openshell", ["policy", "get", sandbox, "--full", "-o", "json"], **bounds
            )
            if (
                active.get("status") not in ("loaded", "effective")
                or active.get("version") != active.get("active_version")
                or active.get("policy") != expected_policy
                or not active.get("hash")
            ):
                raise ValueError("development-policy-mismatch")
            allocation["policy_revision"], allocation["policy_hash"] = (
                active["active_version"],
                active["hash"],
            )
            self.save()
            probe = self.command(
                "openshell",
                [
                    "sandbox",
                    "exec",
                    sandbox,
                    "--no-tty",
                    "--no-login-shell",
                    "--timeout",
                    "8",
                    "--",
                    "/usr/bin/sha256sum",
                    PROBE_PATH,
                ],
                **bounds,
            )
            if probe.stdout.decode().split() != [
                self.config.probe_digest.removeprefix("sha256:"),
                PROBE_PATH,
            ]:
                raise ValueError("development-probe-digest-mismatch")
            for name in ("allowed", "forbidden"):
                self.inventory(allocation, **bounds)
                endpoint = urlsplit(endpoints[name])
                result = self.command(
                    "openshell",
                    [
                        "sandbox",
                        "exec",
                        sandbox,
                        "--no-tty",
                        "--no-login-shell",
                        "--timeout",
                        "8",
                        "--",
                        PROBE_PATH,
                        endpoint.hostname,
                        str(endpoint.port),
                        run,
                        "3",
                    ],
                    **bounds,
                )
                if result.stdout.strip() != ("agent-boundary-gate-probe-complete:" + run).encode():
                    raise ValueError("development-probe-incomplete")
                self.inventory(allocation, **bounds)
                current = self.query(
                    "openshell", ["policy", "get", sandbox, "--full", "-o", "json"], **bounds
                )
                if current != active:
                    raise ValueError("development-policy-changed")
                allocation["counts"] = self.sample(allocation, **bounds)
                self.save()
            allocation["complete"] = True
        except (OSError, ValueError, KeyError, TypeError, AttemptStopped):
            allocation["failed"] = True
        finally:
            self.save()
            self.cleanup(allocation)
        return self.report(allocation)

    def cleanup(self, allocation):
        """Cleanup has its own deadline/cancellation scope and UID preconditions.

        Never remove a receiver namespace while a target might still produce an
        effect. Unregistered allocations require operator reconciliation.
        """
        bounds = {"deadline": time.monotonic() + self.config.cleanup_seconds, "cancelled": Event()}
        try:
            if allocation.get("pending"):
                raise ValueError("development-allocation-unresolved")
            if allocation.get("sandbox_id") and not allocation.get("target_absent"):
                pair = allocation.get("boundary_pair")
                if not pair or set(allocation.get("target_uids", {})) != {"supervisor", "workload"}:
                    raise ValueError("development-target-unregistered")
                pods = self.query(
                    "kubernetes",
                    [
                        "get",
                        "pods",
                        "-n",
                        self.config.target_namespace,
                        "-l",
                        "openshell.ai/boundary-pair=" + pair,
                        "-o",
                        "json",
                    ],
                    **bounds,
                )["items"]
                if any(
                    p["metadata"]["uid"] not in allocation["target_uids"].values() for p in pods
                ):
                    raise ValueError("development-cleanup-replacement")
                if pods or not allocation.get("target_delete_requested"):
                    current = self.query(
                        "openshell",
                        ["sandbox", "get", allocation["sandbox_name"], "-o", "json"],
                        **bounds,
                    )
                    if current.get("id") != allocation["sandbox_id"]:
                        raise ValueError("development-cleanup-identity-mismatch")
                    allocation["target_delete_requested"] = True
                    self.save()
                    self.command(
                        "openshell", ["sandbox", "delete", allocation["sandbox_name"]], **bounds
                    )
                while True:
                    pods = self.query(
                        "kubernetes",
                        [
                            "get",
                            "pods",
                            "-n",
                            self.config.target_namespace,
                            "-l",
                            "openshell.ai/boundary-pair=" + pair,
                            "-o",
                            "json",
                        ],
                        **bounds,
                    )["items"]
                    if not pods:
                        allocation["target_absent"] = True
                        self.save()
                        break
                    if any(
                        p["metadata"]["uid"] not in allocation["target_uids"].values() for p in pods
                    ):
                        raise ValueError("development-cleanup-replacement")
                    bounds["cancelled"].wait(0.2)
            if not allocation.get("sandbox_id"):
                allocation["target_absent"] = True
            if allocation.get("namespace_uid") and not allocation.get("namespace_absent"):
                # Preserve late effects, and counts already observed, even if this
                # final snapshot is lost. Loss prevents a successful result.
                if allocation.get("sandbox_id"):
                    try:
                        final = self.sample(allocation, **bounds)
                        allocation["counts"] = {
                            name: max(final[name], allocation.get("counts", {}).get(name, 0))
                            for name in final
                        }
                        allocation["final_capture"] = True
                    except (OSError, ValueError, KeyError, TypeError, AttemptStopped):
                        allocation["capture_lost"] = True
                    self.save()
                options = {
                    "apiVersion": "v1",
                    "kind": "DeleteOptions",
                    "preconditions": {"uid": allocation["namespace_uid"]},
                    "propagationPolicy": "Foreground",
                }
                current = self.query(
                    "kubernetes",
                    ["get", "namespace", allocation["run"], "--ignore-not-found", "-o", "json"],
                    **bounds,
                )
                if current:
                    if current.get("metadata", {}).get("uid") != allocation["namespace_uid"]:
                        raise ValueError("development-namespace-replaced")
                    self.command(
                        "kubernetes",
                        ["delete", "--raw", "/api/v1/namespaces/" + allocation["run"], "-f", "-"],
                        data=options,
                        **bounds,
                    )
                    self.command(
                        "kubernetes",
                        ["wait", "--for=delete", "namespace/" + allocation["run"], "--timeout=60s"],
                        **bounds,
                    )
                allocation["namespace_absent"] = True
                self.save()
            if allocation.get("image_grant_uid") and not allocation.get("grant_absent"):
                options = {
                    "apiVersion": "v1",
                    "kind": "DeleteOptions",
                    "preconditions": {"uid": allocation["image_grant_uid"]},
                }
                current = self.query(
                    "kubernetes",
                    [
                        "get",
                        "rolebinding",
                        allocation["run"],
                        "-n",
                        self.config.image_pull_namespace,
                        "--ignore-not-found",
                        "-o",
                        "json",
                    ],
                    **bounds,
                )
                if current:
                    if current.get("metadata", {}).get("uid") != allocation["image_grant_uid"]:
                        raise ValueError("development-grant-replaced")
                    self.command(
                        "kubernetes",
                        [
                            "delete",
                            "--raw",
                            "/apis/rbac.authorization.k8s.io/v1/namespaces/"
                            + self.config.image_pull_namespace
                            + "/rolebindings/"
                            + allocation["run"],
                            "-f",
                            "-",
                        ],
                        data=options,
                        **bounds,
                    )
                allocation["grant_absent"] = True
            allocation["cleanup_complete"] = True
        except (OSError, ValueError, KeyError, TypeError, AttemptStopped):
            allocation["cleanup_complete"] = False
            allocation["cleanup_failed"] = True
        self.save()

    @staticmethod
    def report(allocation):
        counts = allocation.get("counts", {})
        observed = (
            allocation.get("complete") is True
            and not allocation.get("failed")
            and allocation.get("cleanup_complete") is True
            and not allocation.get("cleanup_failed")
            and allocation.get("final_capture") is True
            and not allocation.get("capture_lost")
            and counts.get("allowed") == 1
            and counts.get("forbidden") == int(allocation["profile"] == "weakened")
        )
        return {
            "profile": allocation["profile"],
            "allowed_count": counts.get("allowed"),
            "forbidden_count": counts.get("forbidden"),
            "expected_behavior_observed": bool(observed),
            "cleanup_complete": allocation.get("cleanup_complete", False),
            "sampled_after_target_cleanup": allocation.get("final_capture", False),
            "qualification": "development-only",
            "release_eligible": False,
        }

    def run(self, cancelled: Event):
        profiles = []
        for weakened in (False, True):
            if cancelled.is_set():
                break
            report = self.profile(weakened, cancelled)
            profiles.append(report)
            if not report["expected_behavior_observed"]:
                break
        return {
            "profiles": profiles,
            "development_campaign_completed": len(profiles) == 2
            and all(p["expected_behavior_observed"] for p in profiles),
            "release_eligible": False,
        }

    def recover(self):
        for allocation in self.state["allocations"]:
            self.cleanup(allocation)
        return {
            "development_cleanup_complete": all(
                a.get("cleanup_complete") is True for a in self.state["allocations"]
            ),
            "qualification": "development-only",
            "release_eligible": False,
        }
