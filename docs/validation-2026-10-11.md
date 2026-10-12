# Capture and lifecycle validation — 2026-10-11

64 tests passed on Python 3.12.14. Ruff lint and formatting checks passed.
The tests include actual loopback HTTP receivers and bounded subprocess execution;
direct OpenShell CLI readiness/deletion checks use test doubles.

Installed-CLI loopback checks produced the expected passing healthy simulation
and failing weakened simulation. Both outputs kept release eligibility disabled.
Synthetic examples are reproducible from the test suite; captured run packets
and fixture keys are excluded from this repository.

Verification exposed a missing standalone manifest artifact. The implementation
now persists the manifest by its canonical digest before signing the terminal
record; persistence failure makes the run invalid. Existing signed manifests were checked against their original digests. The regression test exercises
fresh manifest persistence and failure handling.

A process cleanup test also exposed a denied process-group signal. The runner
now attempts to reap the direct child and explicitly reports unconfirmed group
cleanup, preserving a non-passing result. It does not claim an external watchdog
or prove cleanup of a remote target.

The full test command was:

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -q
```

The integration tests require loopback socket access. They do not provision
cluster resources or contact external targets.
