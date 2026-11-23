# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
import unittest

from casbin.policy_review import (
    ArchivedRequest,
    CandidateRule,
    PolicySnapshot,
    review_candidate,
    review_candidates,
)
from casbin.policy_review.cli import main
from casbin.policy_review.data import (
    VERDICT_BLOCKED,
    VERDICT_NOT_VERIFIABLE,
    VERDICT_REMOVABLE,
)
from casbin.policy_review.report import render_text_report
from casbin.policy_review.role_chains import find_role_chains

DEMO_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "examples", "policy_review")
MODEL = os.path.join(DEMO_DIR, "rbac_with_deny_domains_model.conf")
POLICY = os.path.join(DEMO_DIR, "rbac_with_deny_domains_policy.csv")
INPUT = os.path.join(DEMO_DIR, "archived_requests.json")


def load_demo():
    snapshot = PolicySnapshot(MODEL, POLICY)
    with open(INPUT, encoding="utf-8") as handle:
        document = json.load(handle)
    requests = [ArchivedRequest.from_dict(raw, snapshot.request_tokens) for raw in document["requests"]]
    candidates = [CandidateRule.from_dict(raw) for raw in document["candidates"]]
    return snapshot, requests, candidates


def by_id(reviews, rule_id):
    for review in reviews:
        if review.candidate.rule_id == rule_id:
            return review
    raise KeyError(rule_id)


class TestRoleChains(unittest.TestCase):
    def test_transitive_hierarchy_without_domain(self):
        from casbin import Enforcer

        enforcer = Enforcer(
            os.path.join(DEMO_DIR, "..", "rbac_model.conf"),
            os.path.join(DEMO_DIR, "..", "rbac_with_hierarchy_policy.csv"),
        )
        chains = find_role_chains(enforcer.get_role_manager(), "data1_admin")
        self.assertEqual(chains, {"alice": [["alice", "admin", "data1_admin"]]})

    def test_domain_scoped_chains(self):
        snapshot, _, _ = load_demo()
        role_manager = snapshot.role_manager_for("g")
        self.assertEqual(
            find_role_chains(role_manager, "auditor", "domain1"),
            {"carol": [["carol", "auditor"]]},
        )
        # domain isolation: auditor has no grant in domain2
        self.assertEqual(
            find_role_chains(role_manager, "auditor", "domain2"),
            {"auditor": [["auditor"]]},
        )


class TestReviewVerdicts(unittest.TestCase):
    def setUp(self):
        self.snapshot, self.requests, self.candidates = load_demo()
        self.by_id = {candidate.rule_id: candidate for candidate in self.candidates}

    def review(self, rule_id):
        return review_candidate(self.snapshot, self.by_id[rule_id], self.requests)

    def test_allow_rule_relied_on_by_archive_is_blocked(self):
        review = self.review("CAND-A")
        self.assertEqual(review.verdict, VERDICT_BLOCKED)
        self.assertEqual([change.request_id for change in review.decision_changes], ["REQ-004"])
        change = review.decision_changes[0]
        self.assertTrue(change.expected_allow)
        self.assertFalse(change.trial_allow)
        self.assertEqual(change.effect, "allow_lost")
        self.assertEqual(review.role_chains, {"carol": [["carol", "auditor"]]})
        self.assertEqual(review.unobserved_probes, [])

    def test_deny_rule_removal_is_blocked_and_deny_wins(self):
        review = self.review("CAND-B")
        self.assertTrue(review.is_deny_rule)
        self.assertEqual(review.verdict, VERDICT_BLOCKED)
        change = review.decision_changes[0]
        self.assertEqual(change.request_id, "REQ-002")
        self.assertFalse(change.expected_allow)
        self.assertTrue(change.trial_allow)
        self.assertEqual(change.effect, "deny_override_lost")
        # the surviving allow rule explains the flipped trial decision
        self.assertEqual(change.trial_explain[-1], "allow")

    def test_unobserved_coverage_is_not_verifiable(self):
        review = self.review("CAND-C")
        self.assertEqual(review.verdict, VERDICT_NOT_VERIFIABLE)
        self.assertEqual(review.decision_changes, [])
        subjects = {probe.subject for probe in review.unobserved_probes}
        self.assertIn("alice", subjects)
        shadowed = next(probe for probe in review.unobserved_probes if probe.subject == "alice")
        self.assertFalse(shadowed.baseline_allow)  # deny mask still wins in baseline

    def test_dead_rule_without_grants_is_verifiably_removable(self):
        review = self.review("CAND-D")
        self.assertEqual(review.verdict, VERDICT_REMOVABLE)
        self.assertEqual(review.decision_changes, [])
        self.assertEqual(review.unobserved_probes, [])
        self.assertEqual(len(review.orphan_probes), 1)
        self.assertTrue(review.orphan_probes[0].orphan)

    def test_baseline_mismatch_makes_verdict_unverifiable(self):
        bad_requests = [
            ArchivedRequest("REQ-BAD", ("alice", "domain1", "data1", "read", "*"), False)
        ] + self.requests
        review = review_candidate(self.snapshot, self.by_id["CAND-D"], bad_requests)
        self.assertEqual(review.verdict, VERDICT_NOT_VERIFIABLE)
        self.assertEqual([item.request_id for item in review.baseline_mismatches], ["REQ-BAD"])

    def test_optional_request_parameter_participates_in_matching(self):
        request = ArchivedRequest.from_dict(
            {"request_id": "REQ-OPT", "rvals": ["carol", "domain1", "reports", "read"], "expected": "allow"},
            self.snapshot.request_tokens,
        )
        self.assertEqual(request.optional_tokens, ("r_scope",))
        self.assertEqual(request.rvals[-1], "")
        allow, explain = self.snapshot.baseline_enforce(request.rvals)
        self.assertTrue(allow)
        self.assertEqual(explain[1:4], ("domain1", "reports", "read"))

    def test_missing_candidate_rule_is_not_verifiable(self):
        ghost = CandidateRule("GHOST", "p", ("nobody", "domain9", "ghost", "read", "*", "allow"))
        review = review_candidate(self.snapshot, ghost, self.requests)
        self.assertFalse(review.rule_present)
        self.assertEqual(review.verdict, VERDICT_NOT_VERIFIABLE)

    def test_standard_deny_model_without_domains(self):
        model = os.path.join(DEMO_DIR, "..", "rbac_with_deny_model.conf")
        policy = os.path.join(DEMO_DIR, "..", "rbac_with_deny_policy.csv")
        snapshot = PolicySnapshot(model, policy)
        requests = [
            ArchivedRequest("D1", ("alice", "data2", "write"), False),
            ArchivedRequest("D2", ("alice", "data1", "read"), True),
        ]
        deny_candidate = CandidateRule("DENY1", "p", ("alice", "data2", "write", "deny"))
        review = review_candidate(snapshot, deny_candidate, requests)
        self.assertTrue(review.is_deny_rule)
        self.assertEqual(review.verdict, VERDICT_BLOCKED)
        self.assertEqual(review.decision_changes[0].change_label, "deny -> allow (deny override lost)")
        # hierarchy chain from the standard rbac example
        self.assertEqual(review.role_chains, {"alice": [["alice"]]})

    def test_snapshot_is_immutable_after_trial(self):
        before = list(self.snapshot.enforcer.get_policy())
        self.review("CAND-A")
        self.assertEqual(list(self.snapshot.enforcer.get_policy()), before)


class TestReportAndCli(unittest.TestCase):
    def test_full_report_and_text_rendering(self):
        report = review_candidates(MODEL, POLICY, *load_demo()[1:])
        verdicts = {review.candidate.rule_id: review.verdict for review in report.reviews}
        self.assertEqual(
            verdicts,
            {
                "CAND-A": VERDICT_BLOCKED,
                "CAND-B": VERDICT_BLOCKED,
                "CAND-C": VERDICT_NOT_VERIFIABLE,
                "CAND-D": VERDICT_REMOVABLE,
            },
        )
        text = render_text_report(report)
        self.assertIn("可删除 CAND-D", text)
        self.assertIn(report.policy_sha256, text)
        json_document = json.loads(report.to_json())
        self.assertEqual(json_document["archived_count"], 6)

    def test_cli_writes_evidence_without_touching_policy(self):
        import tempfile

        with open(POLICY, encoding="utf-8") as handle:
            original = handle.read()
        with tempfile.TemporaryDirectory() as evidence_dir:
            exit_code = main(
                [
                    "--model",
                    MODEL,
                    "--policy",
                    POLICY,
                    "--input",
                    INPUT,
                    "--evidence-dir",
                    evidence_dir,
                ]
            )
            self.assertEqual(exit_code, 0)
            with open(os.path.join(evidence_dir, "policy_snapshot.csv"), encoding="utf-8") as handle:
                self.assertEqual(handle.read(), original)
            self.assertTrue(os.path.exists(os.path.join(evidence_dir, "policy_snapshot.sha256")))
            self.assertTrue(os.path.exists(os.path.join(evidence_dir, "review_report.txt")))
        with open(POLICY, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), original)


if __name__ == "__main__":
    unittest.main()
