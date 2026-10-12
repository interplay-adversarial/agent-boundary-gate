"""Export the independent lifecycle receipt schema without touching archived records."""

import json
from pathlib import Path

from agent_boundary_gate.receipts import SignedLifecycleReceipt

if __name__ == "__main__":
    folder = Path(__file__).resolve().parents[1] / "schemas/receipts/1.0"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "signed-lifecycle-receipt.json").write_text(
        json.dumps(SignedLifecycleReceipt.model_json_schema(), indent=2, sort_keys=True) + "\n"
    )
