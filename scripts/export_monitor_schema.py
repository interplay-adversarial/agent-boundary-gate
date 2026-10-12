"""Export monitor heartbeats separately from immutable receipt and terminal schemas."""

import json
from pathlib import Path

from agent_boundary_gate.monitor import SignedMonitorHeartbeat

if __name__ == "__main__":
    folder = Path(__file__).resolve().parents[1] / "schemas/monitor/1.0"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "signed-monitor-heartbeat.json").write_text(
        json.dumps(SignedMonitorHeartbeat.model_json_schema(), indent=2, sort_keys=True) + "\n"
    )
