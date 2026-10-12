"""Contract tooling and offline verification. This CLI cannot authorize releases."""

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

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
from agent_boundary_gate.fixtures import SCENARIOS, fixture
from agent_boundary_gate.gate_policy import EXIT_CODES, evaluate
from agent_boundary_gate.local_rig import local_run
from agent_boundary_gate.registry import inventory


def main() -> int:
    parser = argparse.ArgumentParser(description="M0 contract prototype; no release authority")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("adapters", help="implemented, simulated and planned support inventory")
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
    legacy = commands.add_parser("verify-legacy", help="authenticate archived 0.1 records only")
    legacy.add_argument("--records", type=Path, required=True)
    legacy.add_argument("--signer", required=True)
    legacy.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    try:
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
            args.output.mkdir(parents=True, exist_ok=True)
            for model in (
                CaseSpec,
                EvidenceManifest,
                RunResult,
                GateDecision,
                Dispatch,
                SignedRecord,
                TargetProfile,
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
            )
        print(decision.model_dump_json(indent=2))
        return EXIT_CODES[decision.release_decision]
    except (OSError, ValidationError, ValueError):
        # Validation messages can echo untrusted input; export only an allowlisted code.
        print(
            json.dumps({"error": "invalid-contract-or-input", "release_eligible": False}),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
