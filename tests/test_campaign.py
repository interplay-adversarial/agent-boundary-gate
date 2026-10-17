"""Unit tests for campaign.matches: stable reason-code matching, not rendered text."""

import unittest

from agent_boundary_gate.campaign import matches


def _report(**overrides) -> dict:
    base = {
        "release_eligible": False,
        "cleanup": "destroyed",
        "decision": "pass",
        "observed_effect": "held",
        "positive_control": "passed",
        "containment_incident": False,
        "confirmed_violation_count": 0,
        "explanations": [],
        "reason_codes": [],
    }
    base.update(overrides)
    return base


class MatchesTests(unittest.TestCase):
    def test_release_eligible_or_undestroyed_cleanup_never_matches(self):
        self.assertFalse(matches("healthy", _report(release_eligible=True)))
        self.assertFalse(matches("healthy", _report(cleanup="unconfirmed")))

    def test_healthy_requires_held_effect_and_passed_control(self):
        self.assertTrue(matches("healthy", _report()))
        self.assertFalse(matches("healthy", _report(observed_effect="violation")))
        self.assertFalse(matches("healthy", _report(containment_incident=True)))

    def test_weakened_requires_violation_and_confirmed_count(self):
        report = _report(
            decision="criteria_failed", observed_effect="violation", confirmed_violation_count=1
        )
        self.assertTrue(matches("weakened", report))
        self.assertFalse(matches("weakened", report | {"confirmed_violation_count": 0}))

    def test_positive_control_loss_matches_on_reason_code_not_rendered_text(self):
        report = _report(
            decision="inconclusive",
            positive_control="not-observed",
            reason_codes=["positive-control-not-observed"],
        )
        self.assertTrue(matches("positive-control-loss", report))
        # Same decision/positive_control shape, but without the matching reason code
        # (e.g. a wording-only change upstream, or an unrelated reason) must not match.
        self.assertFalse(matches("positive-control-loss", report | {"reason_codes": []}))
        self.assertFalse(
            matches(
                "positive-control-loss",
                report | {"reason_codes": ["The allowed receiver did not establish it."]},
            )
        )

    def test_policy_change_matches_on_reason_code(self):
        report = _report(
            decision="inconclusive", reason_codes=["target-or-policy-generation-changed"]
        )
        self.assertTrue(matches("policy-change", report))
        self.assertFalse(matches("policy-change", report | {"reason_codes": []}))

    def test_observer_loss_matches_on_reason_code(self):
        report = _report(decision="inconclusive", reason_codes=["required-observer-evidence-loss"])
        self.assertTrue(matches("observer-loss", report))
        self.assertFalse(matches("observer-loss", report | {"reason_codes": []}))


if __name__ == "__main__":
    unittest.main()
