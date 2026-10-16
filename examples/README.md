# Examples coverage

This directory holds self-contained, runnable examples that need nothing beyond
the source checkout: no cluster, no Rust toolchain, no Gym/Interplay
onboarding environment, no network access.

| File | Demonstrates |
| --- | --- |
| `library_policy.py` | Offline `gate_policy.evaluate` against a synthetic fixture dispatch/record |
| `library_loopback.py` | `local_rig.local_run`: real loopback HTTP capture, synthetic enforcement/monitoring |
| `library_gym_bridge.py` | Offline `gym_bridge.evaluate_gym_bridge` fixture mapping, no Gym or model traffic |
| `decision-table.json`, `dispatch.json`, `evidence-manifest.json`, `run-result.json`, `denied-egress-v1.json`, `denied-egress-live-v1.json` | Static `0.2`-schema fixtures consumed by the examples above and by tests |
| `v0.1/*.json` | Frozen `0.1`-schema fixtures, kept only for `verify-legacy` regression coverage |

## Capabilities with no standalone example here

The capabilities below are real and tested, but each needs an operator-owned
resource this checkout cannot provide on its own (a live Kubernetes gateway, an
installed Rust toolchain, the separate Gym/Interplay onboarding locks, or
a provisioned live rig). Rather than ship an example that cannot actually run,
each row points at the doc section that already carries a complete, copy-pasteable
snippet for that operator-provided environment:

| Capability | What it needs | Snippet lives in |
| --- | --- | --- |
| Rust probe backend (`probe_runtime="rust"`) | A staged, digest-verified binary and delivery configuration | [rust-probe-delivery.md](../docs/rust-probe-delivery.md), [rust-probe-usage.md](../docs/rust-probe-usage.md) |
| Interplay/DataDesigner research campaigns (`red_team.red_team_run`) | `onboarding/red-team`'s pinned lock/interpreter and an adversarial/target/judge endpoint | [description-driven-red-team.md](../docs/description-driven-red-team.md) |
| Development runner / disposable cells (`development_run.DevelopmentRunner`) | An operator-owned Kubernetes gateway bootstrap | [development-runner.md](../docs/development-runner.md), [disposable-development-cells.md](../docs/disposable-development-cells.md) |
| Independent namespace allocator | The same Kubernetes gateway, plus the allocator service | [development-namespace-allocation.md](../docs/development-namespace-allocation.md) |
| Live workflow (`live.live_run`, `authority-serve`, `receiver-serve`, `watchdog`) | A provisioned live rig, trusted keys and an independent inspector | [live-workflow.md](../docs/live-workflow.md) |
| Gym onboarding / model smoke (`scripts/gym_replay.py`, `scripts.gym_smoke`) | `onboarding/gym`'s pinned lock/source, and a model endpoint for the smoke path | [gym-onboarding.md](../docs/gym-onboarding.md), [gym-model-smoke.md](../docs/gym-model-smoke.md) |

If you add a new offline-runnable example, also add a row to the first table
above and to [docs/library-usage.md](../docs/library-usage.md)'s entry-point
table — an example that exists but isn't indexed from either place is as good
as missing.
