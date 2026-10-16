import contextlib
import io
import json
import os
import struct
import sys
import tempfile
import time
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError
from receipt_support import FakeReceiptBroker, lease_and_binding

from agent_boundary_gate.backends import BackendFailure
from agent_boundary_gate.backends.openshell import OpenShellBackend
from agent_boundary_gate.contracts import HttpGetAction
from agent_boundary_gate.evidence import bytes_digest
from agent_boundary_gate.probe_delivery import (
    DOMAIN,
    PROBE_PATH,
    DeliveryReceipt,
    DeliveryRejected,
    DeliveryVerifier,
    RustProbeArtifact,
    RustProbeDeployment,
    SignedDeliveryReceipt,
    delivery_payload,
    sign_delivery,
)
from agent_boundary_gate.process import ProcessResult
from scripts import stage_rust_probe as staging

D = "sha256:" + "a" * 64
ROOT = Path(__file__).resolve().parents[1]


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.lease, self.binding = lease_and_binding()
        self.key = Ed25519PrivateKey.generate()
        self.verifier = DeliveryVerifier({"synthetic-delivery": self.key.public_key()})
        self.deployment = RustProbeDeployment(
            artifact=RustProbeArtifact(
                target="x86_64-unknown-linux-musl",
                binary_digest=D,
                source_digest=D,
                manifest_digest=D,
            ),
            workload_image_digest=D,
        )
        self.request = self.verifier.request(self.lease, self.deployment)
        self.now = datetime.now(UTC)

    def receipt(self, **changes):
        return DeliveryReceipt(
            **(
                {
                    "signer_identity": "synthetic-delivery",
                    "request": self.request,
                    "issued_at": self.now,
                    "expires_at": self.now + timedelta(seconds=30),
                    "state": "verified-immutable-delivery",
                    "immutable_until": self.lease.lease_expires_at,
                }
                | changes
            )
        )

    def verify(self, receipt, *, request=None, verifier=None, key=None, now=None):
        return (verifier or self.verifier).verify(
            sign_delivery(receipt, key or self.key).model_dump_json().encode(),
            request=request or self.request,
            now=now or self.now,
        )

    def test_valid_and_snapshotted_trust(self):
        keys = {"synthetic-delivery": self.key.public_key()}
        verifier = DeliveryVerifier(keys)
        keys.clear()
        self.assertEqual(self.verify(self.receipt(), verifier=verifier), self.receipt())

    def test_challenge_and_entire_lease_binding_are_authenticated(self):
        for changes in (
            {"binding_digest": "sha256:" + "b" * 64},
            {"run_id": "replacement"},
            {"attempt_id": "replacement"},
            {"lease_id": "replacement"},
            {"cell_uid": "replacement"},
            {"effective_policy_digest": "sha256:" + "b" * 64},
            {"component": self.lease.component.model_copy(update={"generation": "replacement"})},
            {"component": self.lease.component.model_copy(update={"instance_uid": "replacement"})},
            {"lease_expires_at": self.lease.lease_expires_at + timedelta(seconds=1)},
        ):
            request = self.request.model_copy(
                update={"binding": self.lease.model_copy(update=changes)}
            )
            with self.subTest(changes=changes), self.assertRaises(DeliveryRejected):
                self.verify(self.receipt(request=request))
        with self.assertRaises(DeliveryRejected):
            self.verify(self.receipt(), request=self.verifier.request(self.lease, self.deployment))

    def test_artifact_architecture_and_image_mismatches_rejected(self):
        for changes in (
            {"binary_digest": "sha256:" + "b" * 64},
            {"source_digest": "sha256:" + "b" * 64},
            {"manifest_digest": "sha256:" + "b" * 64},
            {"target": "aarch64-unknown-linux-musl"},
        ):
            deployment = self.deployment.model_copy(
                update={"artifact": self.deployment.artifact.model_copy(update=changes)}
            )
            request = self.request.model_copy(update={"deployment": deployment})
            with self.subTest(changes=changes), self.assertRaises(DeliveryRejected):
                self.verify(self.receipt(request=request))
        request = self.request.model_copy(
            update={
                "deployment": self.deployment.model_copy(
                    update={"workload_image_digest": "sha256:" + "b" * 64}
                )
            }
        )
        with self.assertRaises(DeliveryRejected):
            self.verify(self.receipt(request=request))

    def test_stale_expired_future_overlong_and_mutable_delivery_rejected(self):
        for changes in (
            {"issued_at": self.now - timedelta(seconds=61)},
            {"issued_at": self.now + timedelta(seconds=1)},
            {"expires_at": self.now},
            {"expires_at": self.now + timedelta(seconds=61)},
            {"immutable_until": self.lease.lease_expires_at - timedelta(seconds=1)},
        ):
            with (
                self.subTest(changes=changes),
                self.assertRaises((DeliveryRejected, ValidationError)),
            ):
                self.verify(self.receipt(**changes))
        lease = self.lease.model_copy(update={"lease_expires_at": self.now + timedelta(seconds=10)})
        request = self.verifier.request(lease, self.deployment)
        with self.assertRaises(DeliveryRejected):
            self.verify(self.receipt(request=request), request=request)
        with self.assertRaises(DeliveryRejected):
            self.verify(self.receipt(), now=datetime(2026, 1, 1))

    def test_wrong_authority_tampering_and_signature_domain_rejected(self):
        with self.assertRaises(DeliveryRejected):
            self.verify(self.receipt(), key=Ed25519PrivateKey.generate())
        with self.assertRaises(DeliveryRejected):
            self.verify(self.receipt(), verifier=DeliveryVerifier({}))
        signed = sign_delivery(self.receipt(), self.key)
        for raw in (
            b"{}",
            b" " * 65537,
            True,
            signed.model_copy(update={"signature": "0" * 128}).model_dump_json().encode(),
        ):
            with self.assertRaises(DeliveryRejected):
                self.verifier.verify(raw, request=self.request, now=self.now)
        payload = delivery_payload(self.receipt()).replace(
            DOMAIN, b"agent-boundary-gate/lifecycle-receipt/1.0\0"
        )
        signed = signed.model_copy(update={"signature": self.key.sign(payload).hex()})
        with self.assertRaises(DeliveryRejected):
            self.verifier.verify(
                signed.model_dump_json().encode(), request=self.request, now=self.now
            )

    def test_unreviewed_paths_protocols_and_platforms_rejected(self):
        for change in ({"target": "native"}, {"protocol_digest": D}, {"package_version": "0.3.0"}):
            with self.assertRaises(ValidationError):
                RustProbeArtifact.model_validate(self.deployment.artifact.model_dump() | change)
        with self.assertRaises(ValidationError):
            RustProbeDeployment.model_validate(
                self.deployment.model_dump() | {"executable_path": "/tmp/probe"}
            )
        with self.assertRaises(ValidationError):
            self.receipt(issued_at=datetime(2026, 1, 1))

    def test_exported_schema_matches(self):
        self.assertEqual(
            self.deployment.artifact.protocol_digest,
            bytes_digest((ROOT / "probes/http/protocol-v1.json").read_bytes()),
        )
        self.assertEqual(
            json.loads(
                (ROOT / "schemas/probe-delivery/1.0/signed-delivery-receipt.json").read_text()
            ),
            SignedDeliveryReceipt.model_json_schema(),
        )

    def driver(self, provider):
        broker = FakeReceiptBroker()
        executable = Path(sys.executable)
        driver = OpenShellBackend(
            executable=executable,
            executable_digest=bytes_digest(executable.read_bytes()),
            gateway="rig",
            sandbox="gate-attempt-1",
            sandbox_uid="sandbox-1",
            policy_digest=self.lease.effective_policy_digest,
            policy_revision=3,
            lease=self.lease,
            receipt_provider=broker,
            receipt_verifier=broker.verifier,
            probe_runtime="rust",
            rust_deployment=self.deployment,
            delivery_provider=provider,
            delivery_verifier=self.verifier,
        )
        driver.require_binding(self.binding)
        request = broker.verifier.request("readiness", self.lease)
        driver._last_readiness = broker.verifier.verify(
            broker.fetch(request, deadline=1, cancelled=Event()),
            request=request,
            now=datetime.now(UTC),
        )
        return driver

    def provider(self):
        test = self

        class Provider:
            calls = []

            def fetch(self, request, **kwargs):
                self.calls.append(request)
                return (
                    sign_delivery(test.receipt(request=request), test.key)
                    .model_dump_json()
                    .encode()
                )

        return Provider()

    def replay(self, driver, url="http://127.0.0.1:8080/probe", **kwargs):
        return driver.replay(
            HttpGetAction(
                operation="http_get", receiver="allowed", path="/probe", timeout_seconds=1
            ),
            url,
            self.binding.attempt_id,
            deadline=time.monotonic() + 1,
            cancelled=kwargs.get("cancelled", Event()),
        )

    def test_fixed_rust_argv_and_fresh_delivery_for_each_action(self):
        provider = self.provider()
        driver = self.driver(provider)
        output = ("agent-boundary-gate-probe-complete:" + self.binding.attempt_id + "\n").encode()
        with patch.object(driver, "_command", return_value=ProcessResult(0, output)) as command:
            self.assertTrue(self.replay(driver))
            argv = command.call_args.args[0]
            self.assertEqual(
                argv[argv.index("--") + 1 :],
                [PROBE_PATH, "127.0.0.1", "8080", self.binding.attempt_id, "1"],
            )
            self.assertTrue(self.replay(driver, "http://[::1]:8080/probe"))
            self.assertTrue(self.replay(driver, "http://receiver:8080/probe"))
            argv = command.call_args.args[0]
            self.assertEqual(
                argv[argv.index("--") + 1 :],
                [PROBE_PATH, "receiver", "8080", self.binding.attempt_id, "1"],
            )
        self.assertEqual(len(provider.calls), 3)
        self.assertNotEqual(provider.calls[0].challenge, provider.calls[1].challenge)

    def test_missing_delivery_cancel_never_execute_or_fallback(self):
        provider = self.provider()
        driver = self.driver(provider)
        with patch.object(driver, "_command") as command:
            stopped = Event()
            stopped.set()
            self.assertFalse(self.replay(driver, cancelled=stopped))
            with patch.object(provider, "fetch", return_value=None):
                with self.assertRaises(BackendFailure) as caught:
                    self.replay(driver)
                self.assertEqual(str(caught.exception), "backend-probe-delivery-rejected")
            command.assert_not_called()

    def test_expiry_or_cancel_during_delivery_never_execute(self):
        provider = self.provider()
        driver = self.driver(provider)
        stop = Event()
        original = provider.fetch

        def fetch(request, **kwargs):
            stop.set()
            return original(request, **kwargs)

        with (
            patch.object(provider, "fetch", side_effect=fetch),
            patch.object(driver, "_command") as command,
            patch.object(self.verifier, "verify", wraps=self.verifier.verify) as verify,
        ):
            self.assertFalse(self.replay(driver, cancelled=stop))
            verify.assert_not_called()
            command.assert_not_called()

        def expired(request, **kwargs):
            now = datetime.now(UTC)
            return (
                sign_delivery(
                    self.receipt(
                        request=request,
                        issued_at=now - timedelta(seconds=2),
                        expires_at=now - timedelta(seconds=1),
                    ),
                    self.key,
                )
                .model_dump_json()
                .encode()
            )

        with (
            patch.object(provider, "fetch", side_effect=expired),
            patch.object(driver, "_command") as command,
        ):
            with self.assertRaises(BackendFailure):
                self.replay(driver)
            command.assert_not_called()

    def test_delivery_reply_after_deadline_never_executes(self):
        provider = self.provider()
        driver = self.driver(provider)
        original = provider.fetch

        def delayed(request, **kwargs):
            time.sleep(0.03)
            return original(request, **kwargs)

        with (
            patch.object(provider, "fetch", side_effect=delayed),
            patch.object(driver, "_command") as command,
            patch.object(self.verifier, "verify", wraps=self.verifier.verify) as verify,
        ):
            self.assertFalse(
                driver.replay(
                    HttpGetAction(
                        operation="http_get", receiver="allowed", path="/probe", timeout_seconds=1
                    ),
                    "http://127.0.0.1:8080/probe",
                    self.binding.attempt_id,
                    deadline=time.monotonic() + 0.01,
                    cancelled=Event(),
                )
            )
            verify.assert_not_called()
            command.assert_not_called()

    def test_cancellation_during_verification_never_executes(self):
        driver = self.driver(self.provider())
        stop = Event()
        original = self.verifier.verify

        def verify(*args, **kwargs):
            receipt = original(*args, **kwargs)
            stop.set()
            return receipt

        with (
            patch.object(self.verifier, "verify", side_effect=verify),
            patch.object(driver, "_command") as command,
        ):
            self.assertFalse(self.replay(driver, cancelled=stop))
            command.assert_not_called()

    def test_rust_selection_requires_all_trust_inputs(self):
        with self.assertRaises(ValueError):
            OpenShellBackend(
                probe_runtime="rust",
                executable=Path("missing"),
                executable_digest=D,
                gateway="rig",
                sandbox="gate-test",
                sandbox_uid="sandbox-1",
                policy_digest=D,
                policy_revision=1,
                lease=self.lease,
                receipt_provider=None,
                receipt_verifier=None,
            )


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        raw = bytearray(160)
        raw[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<H", raw, 16, 3)
        struct.pack_into("<H", raw, 18, 62)
        struct.pack_into("<Q", raw, 32, 64)
        struct.pack_into("<HH", raw, 54, 56, 1)
        struct.pack_into("<IIQQQQQQ", raw, 64, 1, 0, 128, 0, 0, 16, 16, 8)
        self.binary, self.manifest = self.root / "probe", self.root / "manifest.json"
        self.binary.write_bytes(raw)
        self.report = {
            "status": "experimental-build",
            "package_version": "0.2.0",
            "protocol": "agent-boundary-gate/http-probe/1.0",
            "protocol_digest": RustProbeArtifact.model_fields["protocol_digest"].default,
            "source_digest": D,
            "target": "x86_64-unknown-linux-musl",
            "binary_digest": bytes_digest(raw),
            "compiler_version": "1.98.1",
            "static_elf_verified": True,
            "artifact_privacy": "passed",
            "third_party_dependencies": 0,
            "live_qualified": False,
            "release_eligible": False,
        }
        self.repin()

    def repin(self):
        self.manifest.write_text(json.dumps(self.report))
        self.pins = RustProbeArtifact(
            target=self.report["target"],
            source_digest=D,
            binary_digest=bytes_digest(self.binary.read_bytes()),
            manifest_digest=bytes_digest(self.manifest.read_bytes()),
        )

    def stage(self):
        return staging.stage(
            binary=self.binary,
            manifest=self.manifest,
            pins=self.pins,
            destination=self.root / "output",
        )

    def test_verified_bytes_and_licenses_staged_without_execution(self):
        result = self.stage()
        self.assertEqual(result["status"], "verified-staging")
        self.assertFalse(result["release_eligible"])
        output = self.root / "output"
        self.assertEqual((output / "gate-http-probe").read_bytes(), self.binary.read_bytes())
        self.assertEqual((output / "gate-http-probe").stat().st_mode & 0o777, 0o555)
        self.assertEqual(output.stat().st_mode & 0o777, 0o700)
        self.assertEqual((output / "LICENSE").read_bytes(), (ROOT / "LICENSE").read_bytes())
        with self.assertRaises(FileExistsError):
            self.stage()

    @unittest.skipUnless(
        os.environ.get("GATE_RUST_PROBE_BINARY"), "native Linux CI artifact required"
    )
    def test_native_ci_artifact_staging_and_digest_rejection(self):
        # CI conformance fixture only: production approval pins must be supplied
        # independently, never learned from the artifact being admitted.
        binary = Path(os.environ["GATE_RUST_PROBE_BINARY"])
        manifest = binary.with_name("gate-http-probe.provenance.json")
        metadata = manifest.read_bytes()
        report = json.loads(metadata)
        pins = RustProbeArtifact(
            target=report["target"],
            binary_digest=report["binary_digest"],
            source_digest=report["source_digest"],
            manifest_digest=bytes_digest(metadata),
        )
        staging.stage(binary=binary, manifest=manifest, pins=pins, destination=self.root / "native")
        self.assertEqual((self.root / "native/gate-http-probe").read_bytes(), binary.read_bytes())
        from scripts.prepare_owned_image import prepare

        prepare(
            binary=binary,
            manifest=manifest,
            pins=pins,
            base_image="example/image@sha256:" + "a" * 64,
            destination=self.root / "native-image",
        )
        self.assertEqual(
            (self.root / "native-image/probe/gate-http-probe").read_bytes(), binary.read_bytes()
        )
        self.assertNotIn("RUN ", (self.root / "native-image/Dockerfile").read_text())
        self.assertNotIn("artifact-pins", (self.root / "native-image/.dockerignore").read_text())
        with self.assertRaises(ValueError):
            staging.stage(
                binary=binary,
                manifest=manifest,
                pins=pins.model_copy(update={"binary_digest": D}),
                destination=self.root / "wrong-pin",
            )

    def test_failed_publication_removes_only_new_output(self):
        with patch.object(staging.os, "rename", side_effect=OSError("synthetic-private-error")):
            with self.assertRaises(OSError):
                self.stage()
        self.assertFalse((self.root / "output").exists())
        self.assertTrue(self.binary.exists())

    def test_changed_bytes_metadata_foreign_platform_and_dynamic_binary_rejected(self):
        original = self.binary.read_bytes()
        self.binary.write_bytes(original + b"changed")
        with self.assertRaises(ValueError):
            self.stage()
        self.binary.write_bytes(original)
        self.manifest.write_text("{}")
        with self.assertRaises(ValueError):
            self.stage()
        for changes in (
            {"release_eligible": True},
            {"static_elf_verified": 1},
            {"third_party_dependencies": False},
            {"target": "aarch64-unknown-linux-musl"},
        ):
            report = self.report.copy()
            self.report.update(changes)
            self.repin()
            with self.assertRaises(ValueError):
                self.stage()
            self.report = report
        raw = bytearray(original)
        struct.pack_into("<I", raw, 64, 3)
        self.binary.write_bytes(raw)
        self.report["binary_digest"] = bytes_digest(raw)
        self.repin()
        with self.assertRaises(ValueError):
            self.stage()
        self.assertFalse((self.root / "output").exists())

    def test_special_inputs_and_output_symlinks_rejected(self):
        link = self.root / "symlink"
        link.symlink_to(self.binary)
        with self.assertRaises(OSError):
            staging.stage(
                binary=link,
                manifest=self.manifest,
                pins=self.pins,
                destination=self.root / "output",
            )
        os.mkfifo(self.root / "fifo")
        with self.assertRaises(ValueError):
            staging.stage(
                binary=self.root / "fifo",
                manifest=self.manifest,
                pins=self.pins,
                destination=self.root / "output",
            )
        (self.root / "output").symlink_to(self.root)
        with self.assertRaises(FileExistsError):
            self.stage()
        self.assertTrue(self.binary.exists())

    def test_staging_cli_does_not_export_paths_or_invalid_arguments(self):
        for argv in (["stage", "--private-invalid-option"], ["stage", "--binary", "private-value"]):
            output = io.StringIO()
            with patch.object(sys, "argv", argv), contextlib.redirect_stdout(output):
                self.assertEqual(staging.main(), 2)
            self.assertEqual(json.loads(output.getvalue())["error"], "rust-probe-stage-rejected")
            self.assertNotIn("private-value", output.getvalue())
