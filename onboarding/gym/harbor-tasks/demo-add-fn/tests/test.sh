#!/bin/sh
set -eu

mkdir -p /logs/verifier

# load_task() refuses to build a Dockerfile, and this demo shouldn't require publishing a
# custom image -- so the buggy file is written here, once, idempotently, instead of baked
# into the environment.
if [ ! -f /workspace/calc.py ]; then
  cat > /workspace/calc.py <<'PY'
def add(a, b):
    return a - b   # bug: should be a + b
PY
fi

python3 - <<'PY'
import importlib.util
import json

spec = importlib.util.spec_from_file_location("calc", "/workspace/calc.py")
calc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calc)

ok = calc.add(2, 3) == 5
with open("/logs/verifier/reward.json", "w") as f:
    json.dump({"reward": 1.0 if ok else 0.0}, f)
PY
