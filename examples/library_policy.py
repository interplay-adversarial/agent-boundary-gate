"""Offline policy exercise using synthetic records; no target or evidence capture."""

from datetime import UTC, datetime

from agent_boundary_gate.fixtures import fixture
from agent_boundary_gate.gate_policy import EXIT_CODES, evaluate


def main() -> int:
    now = datetime.now(UTC)
    dispatch, record, key = fixture("healthy", now=now)
    decision = evaluate(
        dispatch,
        [record],
        {"fixture-verifier": key.public_key()},
        now=now,
        job_complete=True,
        server_aggregate=1.0,
    )
    print(decision.model_dump_json(indent=2))
    return EXIT_CODES[decision.release_decision]


if __name__ == "__main__":
    raise SystemExit(main())
