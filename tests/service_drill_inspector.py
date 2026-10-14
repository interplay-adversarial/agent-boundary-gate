"""Pinned synthetic inventory helper for real host-service process drills only.

No target, hypervisor or containment is inspected. State belongs to the fixture
owner and survives authority/watchdog death independently of their journals.
"""

import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from agent_boundary_gate.evidence import json_bytes
from agent_boundary_gate.rig_authority import CellInspection, InspectionRequest


def write(path, value):
    temporary = path.with_suffix(".new")
    temporary.write_bytes(json_bytes(value))
    temporary.chmod(0o600)
    temporary.replace(path)


def inspect():
    request = InspectionRequest.model_validate_json(sys.stdin.buffer.read(65537))
    root = Path(os.environ["GATE_DRILL_INVENTORY"])
    inventory = json.loads((root / "inventory.json").read_text())
    lease = inventory["binding"]
    if request.binding.model_dump(mode="json") != lease:
        raise ValueError("synthetic-inventory-binding-mismatch")
    if request.operation == "destroy":
        # Both inspector paths consult one independently retained identity.
        # A same-name replacement never counts as destruction of the original.
        if inventory["current_cell_uid"] != request.binding.cell_uid:
            raise ValueError("synthetic-replacement-must-not-be-deleted")
        write(root / "cleanup-entered.json", {"pid": os.getpid(), "binding": lease})
        while (root / "block-cleanup").exists():
            time.sleep(0.01)
        inventory["state"] = "destroyed"
        inventory["cleanup_calls"] += 1
        write(root / "inventory.json", inventory)
    observation = CellInspection(
        binding=request.binding,
        observed_at=datetime.now(UTC),
        state=inventory["state"],
        outer_boundary_closed=True,
        workload_cannot_access_authority=True,
        watchdog_active=True,
    )
    sys.stdout.write(observation.model_dump_json())


if __name__ == "__main__":
    inspect()
