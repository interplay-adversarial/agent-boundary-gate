# Agent Boundary Gate development guidance

This repository is an evidence-gate prototype maintained by Interplay Adversarial contributors. Read README.md and ADR-0002
before changing contracts or adapter boundaries.

- Keep core policy, signing and evidence contracts independent of target vendors.
- Boundary backends, agent adapters and observers live in this repo initially.
- Keep agent application identity separate from boundary runtime identity.
- Pin any third-party agent harness only from its official upstream repository,
  never a personal fork: a fork's history can silently diverge or be rewritten,
  dropping integration work the pin depended on without any signal in this repo.
  (The Hermes integration was removed 2026-10-16 after NousResearch/hermes-agent
  dropped pip/uv installability entirely — see docs/improvement-roadmap.md.)
- Planned adapters must remain explicitly planned; do not imply live qualification.
- Preserve raw violations, incident precedence, incomplete evidence and veto-only exceptions.
- Treat signed wire versions as immutable. Never rewrite archived evidence.
- Every required unsupported combination must withhold approval.
- Do not enable release eligibility during refactoring or local fixture work.
- Python 3.13+, strict Pydantic contracts, Ruff lint/format. Use the project uv environment.
- Run the gate and adapter tests plus loopback integration tests for behavioral changes.
- Keep private artifacts, credentials and signing keys out of Git and shared output.

Before publishing, run `python scripts/audit_publication.py` against the Git index
and scan the exported Git tree with a redacted secret scanner. Publish only source,
synthetic examples and portable documentation. Never commit deployment inventories,
private capture packets or operator credentials.
