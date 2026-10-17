"""CLI launcher with explicit synthetic receipt/journal write-failure injection.

These switches exist only in the test fixture. No product command accepts them.
The real CLI, private host configuration, IPC, signing and recovery run unchanged.
"""

import os
import sqlite3
from pathlib import Path

from agent_boundary_gate.cli import main
from agent_boundary_gate.evidence import EvidenceStore
from agent_boundary_gate.recovery import LeaseJournal


def launch():
    marker = Path(os.environ["GATE_DRILL_WRITE_FAULT"])
    journal = Path(os.environ["GATE_DRILL_JOURNAL"])
    persist, finish = EvidenceStore.persist, LeaseJournal.finish

    def fail_receipt(store, raw):
        if store.root == journal and marker.exists() and marker.read_text() == "receipt":
            raise OSError("synthetic-receipt-write-failure")
        return persist(store, raw)

    def fail_finish(store, *args, **kwargs):
        if marker.exists() and marker.read_text() == "finish":
            raise sqlite3.OperationalError("synthetic-journal-commit-failure")
        return finish(store, *args, **kwargs)

    EvidenceStore.persist, LeaseJournal.finish = fail_receipt, fail_finish
    return main()


if __name__ == "__main__":
    raise SystemExit(launch())
