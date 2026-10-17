"""Synthetic namespace API for actual allocator/controller process drills."""

import json
import os
import sys
import time
from pathlib import Path

from agent_boundary_gate.evidence import write_json_atomic


def main():
    root = Path(os.environ["GATE_ALLOCATOR_FIXTURE"])
    manifest = json.load(sys.stdin)
    name = manifest["metadata"]["name"]
    path = root / "api-state.json"
    state = json.loads(path.read_text()) if path.exists() else {}
    if name in state:
        return 17
    value = {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {**manifest["metadata"], "uid": "uid-" + name},
    }
    state[name] = value
    write_json_atomic(path, state)
    write_json_atomic(root / "api-entered.json", {"name": name, "pid": os.getpid()})
    while (root / "block-response").exists():
        time.sleep(0.01)
    if (root / "drop-response").exists():
        return 18
    print(json.dumps(value))
    return 0


if __name__ == "__main__":
    sys.exit(main())
