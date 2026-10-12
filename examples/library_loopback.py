"""Run real loopback HTTP capture with synthetic enforcement and monitoring."""

import argparse
from pathlib import Path

from agent_boundary_gate.gate_policy import EXIT_CODES
from agent_boundary_gate.local_rig import local_run


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--weakened", action="store_true")
    args = parser.parse_args()
    case = Path(__file__).resolve().parent / "denied-egress-v1.json"
    decision = local_run(case, args.output, weakened=args.weakened)
    print(decision.model_dump_json(indent=2))
    return EXIT_CODES[decision.release_decision]


if __name__ == "__main__":
    raise SystemExit(main())
