# Development controller failure drills

These REL-01/EVID-01 drills exercise the actual development controller and its
private journal against a separately persisted **synthetic** runtime/receiver
backend. Six tests start a real controller subprocess, wait for a specific
checkpoint, verify that another operator cannot acquire its campaign lock, then
send SIGKILL. A fresh controller reads the committed journal and independently
persisted backend state. No model, cluster credentials or live infrastructure
are used.

Run from the source checkout:

```sh
PYTHONPATH=src uv run --frozen --no-editable python -m unittest discover \
  -s tests -p test_development_failure_drills.py -v
```

The normal unit/loopback discovery and hosted Python validation include these
drills. Private temporary files are removed after each test; no capture packets
or operator inventories belong in public CI output.

## Checkpoints and required outcomes

| Drill | Required outcome |
| --- | --- |
| Controller killed after a forbidden effect, before capture commit | Recovery retires the registered cell, recaptures the effect, retains it across a second restart and never replays bootstrap or probes. The incomplete execution remains incomplete. |
| Controller killed after committing an effect; receiver counter rolls back | Previously observed violation count remains monotonic; capture loss is latched and expected behavior withheld even when cleanup succeeds. |
| A further target effect occurs after controller death | Final capture includes the additional effect after target retirement. Controller death cannot stand in for target containment. |
| Controller killed with an fsynced, uncommitted journal temporary | Recovery discards the temporary under the exclusive lock, uses the committed ownership UID and recaptures the effect. It never adopts the uncommitted UID. |
| Controller killed after target namespace deletion acceptance, before absence commit | Recovery independently observes absence before final receiver capture. Execution and cleanup completion remain separate facts. |
| Controller killed after namespace creation, before UID registration | Recovery withholds cleanup completion, retains the namespace and refuses name-based adoption/deletion. Operator reconciliation is required. |
| Policy hash changes after a forbidden effect | Execution fails; final independent capture retains the effect and cleanup does not repair evaluation. |
| Supervisor restarts after the allowed effect | Inventory verification stops subsequent execution; cleanup retains the allowed effect and execution stays failed. |
| Registered receiver is replaced | Capture loss is recorded; previously observed violation count survives and cannot be promoted to success. |
| One journal write fails after observation | Failure remains recorded after storage returns; cleanup persists the observed violation and withholds successful evaluation. |
| Journal storage remains unavailable | The call cannot return successful completion. After storage returns, explicit recovery captures effects and retires resources; it cannot complete the interrupted execution. |
| Cancellation after a forbidden effect | Cleanup uses its own fresh cancellation scope, preserves the effect and leaves evaluation failed. |

The backend survives separately from the controller journal, allowing the drills
to distinguish effects from what the controller had committed. Backend counters,
namespace API responses and restart events are fixtures. SIGKILL, process exit,
campaign locking, journal files and restart recovery are real host operations.
The drill harness has bounded checkpoint and reap waits so a missing checkpoint
fails the test instead of hanging indefinitely.

## Interpretation and remaining work

Successful recovery means owned-resource reconciliation succeeded. It does not
repair an incomplete execution, erase a violation, prove application resistance
or enable release eligibility. If execution was already durably complete before
a crash, recovery still requires the applicable target-absence observation and
complete final capture before reporting expected **development** behavior.

These tests add process-death coverage beyond in-process cleanup mocks; they do
not qualify whole-cell containment, a live API, storage durability under power
loss, partitioned-node termination or an authenticated external watchdog. The
namespace-create registration window is intentionally unresolved. Signed wire
contracts and archived evidence remain unchanged.

Subsequent increments add [generated gate decisions](gate-decision-invariants.md),
[command-provider deadlines and receiver bounds](adapter-deadlines-and-resource-bounds.md)
and [sixteen service/watchdog process drills](service-watchdog-failure-drills.md).
Remaining REL-01/EVID-01 work includes active-inspector parent death/process-tree
supervision, host power-loss durability and separately provisioned live fault
qualification. Gym/verifier and model-worker
faults belong to the optional pilot track; its native findings must stay separate
from effects. A frozen regression/private CI baseline (GYM-04) follows review of
the pilot and failure criteria, rather than treating this small suite as exhaustive.

See [disposable cells](disposable-development-cells.md),
[development recovery](development-runner.md) and the
[roadmap](improvement-roadmap.md).
