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

# Three independent checks, not just one pass/fail: this is what lets a Harbor
# task report partial credit via tests_passed/tests_total (see
# docs/adaptive-task-runner.md's "Structured progress signal" section), instead
# of only a single reward float. A completely broken add() scores 0/3; a fixed
# one scores 3/3; a differently-broken implementation could land in between.
checks = [calc.add(2, 3) == 5, calc.add(-1, 1) == 0, calc.add(0, 0) == 0]
tests_passed = sum(1 for c in checks if c)
tests_total = len(checks)
with open("/logs/verifier/reward.json", "w") as f:
    json.dump(
        {
            "reward": tests_passed / tests_total,
            "tests_passed": tests_passed,
            "tests_total": tests_total,
        },
        f,
    )
PY
