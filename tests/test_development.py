"""Portable development plans, independent inventory vetoes and real collector I/O."""

import copy
import http.client
import json
import tempfile
import unittest
from pathlib import Path
from threading import Thread
from unittest.mock import patch

from agent_boundary_gate.development import (
    DevelopmentConfig,
    inspect_pod,
    inspect_target_pair,
    policy,
    prepare,
    resources,
)
from agent_boundary_gate.development_receiver import Capture, Server
from agent_boundary_gate.probe_delivery import PROBE_PATH

IMAGE = "example/receiver@sha256:" + "a" * 64
RUN = "gate-dev-0123456789abcdef"


class DevelopmentTests(unittest.TestCase):
    def config(self, **changes):
        return DevelopmentConfig.model_validate(
            {
                "run": RUN,
                "target_namespace": "development-target",
                "receiver_image": IMAGE,
                "workload_image": "example/probe@sha256:" + "b" * 64,
                **changes,
            }
        )

    def pod(self):
        pod = next(p for p in resources(self.config())["items"] if p["kind"] == "Pod")
        pod["metadata"]["uid"] = "receiver-uid"
        pod["status"] = {
            "phase": "Running",
            "containerStatuses": [
                {
                    "name": "receiver",
                    "ready": True,
                    "restartCount": 0,
                    "imageID": "docker-pullable://" + IMAGE,
                }
            ],
        }
        return pod

    def test_plan_only_creates_owned_resources_outside_target_namespace(self):
        items = resources(self.config())["items"]
        self.assertEqual([r["kind"] for r in items].count("Namespace"), 1)
        self.assertTrue(all(r["metadata"].get("namespace", RUN) == RUN for r in items))
        code = next(r for r in items if r["kind"] == "ConfigMap")
        self.assertTrue(code["immutable"])
        network = next(r for r in items if r["kind"] == "NetworkPolicy")["spec"]
        self.assertEqual(network["egress"], [])
        self.assertEqual(network["ingress"][0]["ports"], [{"protocol": "TCP", "port": 8000}])
        for pod in (r for r in items if r["kind"] == "Pod"):
            self.assertFalse(pod["spec"]["automountServiceAccountToken"])
            self.assertEqual(pod["spec"]["restartPolicy"], "Never")

    def test_unpinned_image_invalid_namespace_and_shared_namespace_are_rejected(self):
        for changes in (
            {"receiver_image": "example/receiver:latest"},
            {"target_namespace": "target; command"},
            {"target_namespace": RUN},
            {"run": "shared"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.config(**changes)

    def test_policy_delta_adds_only_forbidden_endpoint_for_exact_owned_binary(self):
        endpoints = {
            "allowed": "http://127.0.0.1:8000/probe",
            "forbidden": "http://127.0.0.1:8001/probe",
        }
        healthy, weakened = policy(endpoints, weakened=False), policy(endpoints, weakened=True)
        self.assertEqual(
            healthy["network_policies"]["allowed"], weakened["network_policies"].pop("allowed")
        )
        self.assertEqual(set(weakened["network_policies"]), {"forbidden"})
        self.assertEqual(
            weakened["network_policies"]["forbidden"]["binaries"], [{"path": PROBE_PATH}]
        )
        self.assertEqual(healthy["filesystem_policy"], weakened["filesystem_policy"])
        for invalid in (
            {"allowed": endpoints["allowed"], "forbidden": endpoints["allowed"]},
            {"allowed": "http://example.com:8000/probe", "forbidden": endpoints["forbidden"]},
        ):
            with self.assertRaises(ValueError):
                policy(invalid, weakened=False)

    def test_inventory_matches_still_withhold_outer_closure_and_release(self):
        report = inspect_pod(self.pod(), uid="receiver-uid", image=IMAGE, run=RUN)
        self.assertTrue(report["receiver_inventory_matches"])
        self.assertFalse(report["outer_boundary_closed"])
        self.assertFalse(report["watchdog_verified"])
        self.assertFalse(report["release_eligible"])
        self.assertEqual(report["qualification"], "development-only")

    def test_replacement_restart_image_and_privileged_network_veto_inventory(self):
        pod = self.pod()
        mutations = [
            lambda p: p["spec"]["containers"][0]["securityContext"].update(privileged=True),
            lambda p: p["spec"]["containers"][0]["securityContext"]["capabilities"].update(
                add=["SYS_ADMIN"]
            ),
            lambda p: p["spec"]["volumes"].append({"name": "host", "hostPath": {"path": "/"}}),
            lambda p: p["metadata"].update(uid="replacement"),
            lambda p: p["metadata"].update(namespace="another-namespace"),
            lambda p: p["status"]["containerStatuses"][0].update(restartCount=1),
            lambda p: p["status"]["containerStatuses"][0].update(
                imageID="example/other@sha256:" + "c" * 64
            ),
            lambda p: p["spec"].update(hostNetwork=True),
            lambda p: p["spec"].update(automountServiceAccountToken=True),
            lambda p: p["spec"]["containers"][0]["securityContext"].update(
                readOnlyRootFilesystem=False
            ),
        ]
        for mutate in mutations:
            changed = copy.deepcopy(pod)
            mutate(changed)
            self.assertFalse(
                inspect_pod(changed, uid="receiver-uid", image=IMAGE, run=RUN)[
                    "receiver_inventory_matches"
                ]
            )

    def test_plan_outputs_are_private_and_existing_destinations_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "plan"
            report = prepare(self.config(), destination)
            self.assertFalse(report["release_eligible"])
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            self.assertEqual((destination / "resources.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                json.loads((destination / "resources.json").read_bytes())["kind"], "List"
            )
            with self.assertRaises(FileExistsError):
                prepare(self.config(), destination)

    def target_pair(self):
        workload = self.pod()
        workload["metadata"].update(
            name="workload",
            namespace="development-target",
            uid="workload-uid",
            labels={
                "openshell.ai/boundary-role": "workload",
                "openshell.ai/boundary-pair": "pair-1",
            },
        )
        supervisor = copy.deepcopy(workload)
        supervisor["metadata"].update(
            name="supervisor",
            uid="supervisor-uid",
            labels={
                "openshell.ai/boundary-role": "supervisor",
                "openshell.ai/boundary-pair": "pair-1",
                "openshell.ai/sandbox-id": "sandbox-1",
            },
        )
        return [supervisor, workload]

    def check_pair(self, pods):
        return inspect_target_pair(
            pods,
            namespace="development-target",
            pair="pair-1",
            sandbox_id="sandbox-1",
            supervisor_uid="supervisor-uid",
            workload_uid="workload-uid",
            workload_image=IMAGE,
        )

    def test_target_pair_requires_both_pods_and_pinned_workload_without_qualification(self):
        pods = self.target_pair()
        report = self.check_pair(pods)
        self.assertTrue(report["target_inventory_matches"])
        for key in (
            "outer_boundary_closed",
            "immutable_delivery_verified",
            "whole_cell_cleanup_verified",
            "release_eligible",
        ):
            self.assertFalse(report[key])
        self.assertFalse(self.check_pair(pods[:1])["target_inventory_matches"])
        self.assertFalse(self.check_pair([pods[0], pods[0]])["target_inventory_matches"])

    def test_target_pair_replacements_image_changes_and_generation_change_are_rejected(self):
        for modify in (
            lambda p: p[0]["metadata"].update(uid="new-supervisor"),
            lambda p: p[1]["metadata"].update(uid="new-workload"),
            lambda p: p[1]["metadata"]["labels"].update({"openshell.ai/boundary-pair": "pair-2"}),
            lambda p: p[1]["spec"]["containers"][0].update(image="example/unapproved:latest"),
            lambda p: p[1]["status"]["containerStatuses"][0].update(restartCount=1),
        ):
            pods = self.target_pair()
            modify(pods)
            self.assertFalse(self.check_pair(pods)["target_inventory_matches"])

    def test_real_collector_counts_only_correlated_requests_and_health_is_not_effect(self):
        with tempfile.TemporaryDirectory() as folder:
            capture = Capture(RUN, Path(folder) / "capture.json")
            server = Server(("127.0.0.1", 0), capture)
            worker = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            worker.start()
            try:
                for path, attempts, status in (
                    ("/health", [], 204),
                    ("/probe", ["other"], 404),
                    ("/probe", [RUN, RUN], 404),
                    ("/probe", [RUN], 204),
                ):
                    connection = http.client.HTTPConnection(*server.server_address, timeout=2)
                    try:
                        connection.putrequest("GET", path)
                        for attempt in attempts:
                            connection.putheader("X-Gate-Attempt", attempt)
                        connection.endheaders()
                        response = connection.getresponse()
                        self.assertEqual(response.status, status)
                        response.read()
                    finally:
                        connection.close()
                self.assertEqual(
                    json.loads(capture.destination.read_text()),
                    {"attempt": RUN, "count": 1, "dropped": 0},
                )
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=3)
            self.assertFalse(worker.is_alive())

    def test_failed_capture_write_invalidates_stale_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            capture = Capture(RUN, Path(folder) / "capture.json")
            capture.count = 1
            with patch("agent_boundary_gate.development_receiver.os.replace", side_effect=OSError):
                with self.assertRaises(OSError):
                    capture.save()
            self.assertFalse(capture.destination.exists())
            self.assertEqual(capture.count, 1)
