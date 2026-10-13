"""Contract tooling and offline verification. This CLI cannot authorize releases."""

import argparse
import json
import signal
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path
from threading import Event

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import TypeAdapter, ValidationError

from agent_boundary_gate.contracts import (
    CaseSpec,
    Dispatch,
    EvidenceManifest,
    GateDecision,
    RunResult,
    SignedRecord,
    TargetProfile,
)
from agent_boundary_gate.doctor import openshell_doctor, read_regular_input
from agent_boundary_gate.evidence import EvidenceStore
from agent_boundary_gate.fixtures import SCENARIOS, fixture
from agent_boundary_gate.gate_policy import EXIT_CODES, evaluate
from agent_boundary_gate.local_rig import local_run
from agent_boundary_gate.receipts import LeaseBinding
from agent_boundary_gate.registry import inventory


class SanitizedArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default diagnostics echo argument values and local paths.
        self.exit(2, json.dumps({"error": "invalid-cli-input", "release_eligible": False}) + "\n")


def main() -> int:
    parser = SanitizedArgumentParser(description="M0 contract prototype; no release authority")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("adapters", help="implemented, simulated and planned support inventory")
    development = commands.add_parser(
        "development-plan", help="prepare private Kubernetes integration resources; no live gate"
    )
    development.add_argument("--config", type=Path, required=True)
    development.add_argument("--output", type=Path, required=True)
    for name in ("development-run", "development-recover"):
        command = commands.add_parser(
            name, help="private development orchestration; no gate receipts"
        )
        command.add_argument("--config", type=Path, required=True)
        command.add_argument("--output", type=Path, required=True)
    for name, help_text in (
        ("live-run", "experimental live OpenShell attempt; private configuration"),
        ("live-suite", "paired calibration and declared disposable-cell fault profiles"),
        ("authority-serve", "host-side receipt authority; requires independent inspector"),
        ("receiver-serve", "host-side paired receivers with private signed capture control"),
        ("watchdog", "separate host-side process for expired/lost cell recovery"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--config", type=Path, required=True)
        if name in ("live-run", "live-suite"):
            command.add_argument("--output", type=Path, required=True)
    doctor = commands.add_parser("doctor", help="read-only OpenShell compatibility; no readiness")
    doctor.add_argument("--executable", type=Path, required=True)
    doctor.add_argument("--executable-digest", required=True)
    doctor.add_argument("--gateway", required=True)
    doctor.add_argument("--sandbox", required=True)
    doctor.add_argument("--policy-revision", type=int, required=True)
    doctor.add_argument(
        "--lease", type=Path, required=True, help="trusted private operator context"
    )
    doctor.add_argument("--probe-runtime", choices=("python3", "perl"), default="python3")
    doctor.add_argument("--timeout", type=float, default=10.0)
    schemas = commands.add_parser("schemas")
    schemas.add_argument("--output", type=Path, required=True)
    demo = commands.add_parser("demo", help="synthetic fixtures; no OpenShell execution")
    demo.add_argument("--scenario", choices=SCENARIOS, required=True)
    local = commands.add_parser(
        "local-run", help="real loopback HTTP; simulated policy, no OpenShell"
    )
    local.add_argument("--case", type=Path, required=True)
    local.add_argument("--output", type=Path, required=True, help="private evidence directory")
    local.add_argument("--weakened", action="store_true")
    check = commands.add_parser("verify", help="verify signed terminal records offline")
    check.add_argument("--dispatch", type=Path, required=True)
    check.add_argument("--records", type=Path, required=True)
    check.add_argument("--signer", required=True)
    check.add_argument(
        "--public-key", type=Path, required=True, help="CI-owned raw Ed25519 public key"
    )
    check.add_argument("--job-complete", action="store_true")
    check.add_argument("--server-aggregate", type=float)
    check.add_argument(
        "--evidence-directory",
        type=Path,
        help="existing private store; require referenced artifacts and digest integrity",
    )
    legacy = commands.add_parser("verify-legacy", help="authenticate archived 0.1 records only")
    legacy.add_argument("--records", type=Path, required=True)
    legacy.add_argument("--signer", required=True)
    legacy.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command in ("development-run", "development-recover"):
            from agent_boundary_gate.development_run import DevelopmentRunConfig, DevelopmentRunner
            from agent_boundary_gate.live import read_private

            config = DevelopmentRunConfig.model_validate_json(read_private(args.config))
            cancelled = Event()
            previous = {}
            try:
                for number in (signal.SIGINT, signal.SIGTERM):
                    previous[number] = signal.signal(number, lambda *_: cancelled.set())
                with DevelopmentRunner(
                    config, args.output, recover=args.command == "development-recover"
                ) as runner:
                    report = (
                        runner.recover()
                        if args.command == "development-recover"
                        else runner.run(cancelled)
                    )
                print(json.dumps(report, indent=2))
                return (
                    0
                    if report.get(
                        "development_campaign_completed",
                        report.get("development_cleanup_complete", False),
                    )
                    else 2
                )
            finally:
                for number, handler in previous.items():
                    signal.signal(number, handler)
        if args.command == "development-plan":
            from agent_boundary_gate.development import DevelopmentConfig, prepare
            from agent_boundary_gate.live import read_private

            config = DevelopmentConfig.model_validate_json(read_private(args.config))
            print(json.dumps(prepare(config, args.output), indent=2))
            return 0
        if args.command in ("authority-serve", "receiver-serve", "watchdog"):
            from agent_boundary_gate.host_services import (
                run_watchdog,
                serve_authority,
                serve_receivers,
            )

            {
                "authority-serve": serve_authority,
                "receiver-serve": serve_receivers,
                "watchdog": run_watchdog,
            }[args.command](args.config)
            return 0
        if args.command in ("live-run", "live-suite"):
            from agent_boundary_gate.campaign import CampaignPlan, live_campaign
            from agent_boundary_gate.live import LiveConfig, live_run, read_private

            raw = read_private(args.config)
            if args.command == "live-run":
                report, code = live_run(LiveConfig.model_validate_json(raw), args.output)
            else:
                report, code = live_campaign(CampaignPlan.model_validate_json(raw), args.output)
            print(json.dumps(report, indent=2))
            return code
        if args.command == "doctor":
            report = openshell_doctor(
                executable=args.executable,
                executable_digest=args.executable_digest,
                gateway=args.gateway,
                sandbox=args.sandbox,
                policy_revision=args.policy_revision,
                lease=LeaseBinding.model_validate_json(read_regular_input(args.lease, limit=65536)),
                probe_runtime=args.probe_runtime,
                timeout_seconds=args.timeout,
            )
            print(json.dumps(report, indent=2))
            return 0 if report["status"] == "observations-match" else 2
        if args.command == "adapters":
            print(json.dumps(inventory(), indent=2))
            return 0
        if args.command == "verify-legacy":
            from agent_boundary_gate.legacy.auth import authenticate_legacy
            from agent_boundary_gate.legacy.v0_1 import SignedRecord as LegacyRecord

            records = TypeAdapter(list[LegacyRecord]).validate_json(args.records.read_bytes())
            key = Ed25519PublicKey.from_public_bytes(args.public_key.read_bytes())
            authenticated = bool(records) and all(
                authenticate_legacy(r, {args.signer: key}) for r in records
            )
            print(
                json.dumps(
                    {
                        "authenticated": authenticated,
                        "qualification": "archived-0.1",
                        "release_eligible": False,
                    }
                )
            )
            return 0 if authenticated else 2
        if args.command == "schemas":
            from agent_boundary_gate.campaign import CampaignPlan
            from agent_boundary_gate.development import DevelopmentConfig
            from agent_boundary_gate.host_services import (
                AuthorityConfig,
                ReceiverConfig,
                WatchdogConfig,
            )
            from agent_boundary_gate.live import LiveConfig
            from agent_boundary_gate.rig_authority import CellInspection, InspectionRequest
            from agent_boundary_gate.rig_receivers import SignedCaptureSnapshot

            args.output.mkdir(parents=True, exist_ok=True)
            for model in (
                CaseSpec,
                EvidenceManifest,
                RunResult,
                GateDecision,
                Dispatch,
                SignedRecord,
                TargetProfile,
                LiveConfig,
                DevelopmentConfig,
                AuthorityConfig,
                ReceiverConfig,
                WatchdogConfig,
                CampaignPlan,
                CellInspection,
                InspectionRequest,
                SignedCaptureSnapshot,
            ):
                (args.output / f"{model.__name__}.json").write_text(
                    json.dumps(model.model_json_schema(), indent=2) + "\n"
                )
            return 0
        now = datetime.now(UTC)
        if args.command == "local-run":
            decision = local_run(args.case, args.output, weakened=args.weakened)
        elif args.command == "demo":
            dispatch, record, key = fixture(args.scenario, now=now)
            decision = evaluate(
                dispatch,
                [record],
                {"fixture-verifier": key.public_key()},
                now=now,
                job_complete=True,
                server_aggregate=record.result.invariant_held,
            )
        else:
            dispatch = Dispatch.model_validate_json(args.dispatch.read_bytes())
            records = TypeAdapter(list[SignedRecord]).validate_json(args.records.read_bytes())
            key = Ed25519PublicKey.from_public_bytes(args.public_key.read_bytes())
            decision = evaluate(
                dispatch,
                records,
                {args.signer: key},
                now=now,
                job_complete=args.job_complete,
                server_aggregate=args.server_aggregate,
                evidence_store=EvidenceStore(args.evidence_directory, create=False)
                if args.evidence_directory
                else None,
            )
        print(decision.model_dump_json(indent=2))
        return EXIT_CODES[decision.release_decision]
    except (OSError, ValidationError, ValueError, sqlite3.Error, RecursionError):
        # Validation messages can echo untrusted input; export only an allowlisted code.
        print(
            json.dumps({"error": "invalid-contract-or-input", "release_eligible": False}),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
