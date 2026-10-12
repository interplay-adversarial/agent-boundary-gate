"""Load pinned denied-egress cases and validate their frozen replay digest."""

import hashlib
import json
from pathlib import Path

from agent_boundary_gate.contracts import CaseSpec


def replay_digest(case: CaseSpec) -> str:
    data = json.dumps(
        [action.model_dump(mode="json") for action in case.actions],
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def load_case(path: Path) -> CaseSpec:
    case = CaseSpec.model_validate_json(path.read_bytes())
    if replay_digest(case) != case.replay_digest:
        raise ValueError("replay does not match the pinned digest")
    return case
