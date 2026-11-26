import unittest
from copy import deepcopy

from policy_sentry.writing.batching import (
    BatchLimits,
    InfeasiblePlanError,
    ReleasePlan,
    _is_splittable,
    batch_usage,
    build_release_plan,
    document_size,
    explain_rollback,
)
from policy_sentry.writing.rule_engine import (
    AccessRequest,
    effective_permissions,
    requests_from_policy,
)

DENY_STATEMENT = {
    "Sid": "DenySecretExport",
    "Effect": "Deny",
    "Action": ["secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue"],
    "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/*",
    "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}},
}
ALLOW_S3 = {
    "Sid": "S3ReadWrite",
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"],
    "Resource": [
        "arn:aws:s3:::example-org-audit-logs",
        "arn:aws:s3:::example-org-audit-logs/*",
        "arn:aws:s3:::example-org-data",
        "arn:aws:s3:::example-org-data/*",
    ],
}
ALLOW_KMS = {
    "Sid": "KmsDecrypt",
    "Effect": "Allow",
    "Action": ["kms:Decrypt", "kms:DescribeKey"],
    "Resource": "arn:aws:kms:us-east-1:123456789012:key/abcd1234",
}


def sample_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [deepcopy(DENY_STATEMENT), deepcopy(ALLOW_S3), deepcopy(ALLOW_KMS)],
    }


class SplittabilityTestCase(unittest.TestCase):
    def test_deny_conditions_and_not_clauses_are_atomic(self):
        self.assertFalse(_is_splittable(deepcopy(DENY_STATEMENT)))
        self.assertFalse(_is_splittable({"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"}))
        self.assertFalse(
            _is_splittable({"Effect": "Allow", "Action": ["s3:*"], "Resource": ["*"], "Condition": {}})
        )
        self.assertFalse(
            _is_splittable(
                {
                    "Effect": "Allow",
                    "Action": ["s3:*"],
                    "Resource": ["*"],
                    "Principal": {"AWS": "arn:aws:iam::1:root"},
                }
            )
        )

    def test_plain_allow_with_lists_is_splittable(self):
        self.assertTrue(_is_splittable(deepcopy(ALLOW_S3)))
        # String (non-list) clauses stay atomic because they cannot be decomposed.
        self.assertFalse(_is_splittable({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}))


class SafePlanTestCase(unittest.TestCase):
    def setUp(self):
        self.policy = sample_policy()

    def test_two_batches_when_policy_fits_deny_isolated(self):
        plan = build_release_plan(self.policy, BatchLimits())
        # Deny occupies batch one; the allows follow even when everything would fit.
        self.assertEqual(len(plan.batches), 2)
        self.assertTrue(plan.feasible)
        self.assertTrue(
            all(f.statement["Effect"] == "Deny" for f in plan.batches[0].fragments)
        )

    def test_byte_limit_forces_multiple_respecting_batches(self):
        plan = build_release_plan(self.policy, BatchLimits(max_bytes=500))
        self.assertGreater(len(plan.batches), 1)
        for batch in plan.batches:
            usage = batch_usage(batch)
            self.assertLessEqual(usage["bytes"], 500)
            self.assertLessEqual(usage["statements"], 20)

    def test_deny_is_never_split_and_always_first(self):
        plan = build_release_plan(self.policy, BatchLimits(max_bytes=400))
        first_batch = plan.batches[0]
        deny_fragments = [f for f in first_batch.fragments if f.statement["Effect"] == "Deny"]
        self.assertEqual(len(deny_fragments), 1)
        self.assertEqual(deny_fragments[0].source_index, 0)
        # The deny occupies batch one on its own: no allow window opens with it.
        self.assertTrue(all(f.statement["Effect"] == "Deny" for f in first_batch.fragments))
        # The conditional deny survives untouched (aside from Sid handling).
        deny_statement = deny_fragments[0].statement
        self.assertEqual(deny_statement["Condition"], DENY_STATEMENT["Condition"])
        self.assertEqual(deny_statement["Action"], DENY_STATEMENT["Action"])
        # No later batch contains a Deny.
        for batch in plan.batches[1:]:
            self.assertTrue(all(f.statement["Effect"] != "Deny" for f in batch.fragments))

    def test_deny_sharing_can_be_opted_in(self):
        plan = build_release_plan(
            self.policy, BatchLimits(max_bytes=600, deny_first_batch=False)
        )
        first_effects = {f.statement["Effect"] for f in plan.batches[0].fragments}
        self.assertIn("Deny", first_effects)
        # Even when sharing, the deny fragment still precedes every allow fragment.
        order = [f.statement["Effect"] for b in plan.batches for f in b.fragments]
        self.assertEqual(order[0], "Deny")
        self.assertEqual(order.index("Allow") > 0, True)

    def test_no_prefix_state_widens_the_approved_envelope(self):
        plan = build_release_plan(self.policy, BatchLimits(max_bytes=400))
        probes = requests_from_policy(self.policy)
        source_decisions = effective_permissions([self.policy], probes)
        installed = []
        for document in plan.documents():
            installed.append(document)
            decisions = effective_permissions(installed, probes)
            for probe in probes:
                marker = (probe.action, probe.resource)
                if decisions[marker] == "Allow":
                    self.assertEqual(source_decisions[marker], "Allow")

    def test_full_installation_equals_source_policy(self):
        plan = build_release_plan(self.policy, BatchLimits(max_bytes=400))
        probes = requests_from_policy(self.policy)
        # Include the explicitly denied requests so deny equivalence is also replayed.
        probes.append(
            AccessRequest(
                "secretsmanager:GetSecretValue",
                "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/app",
                {"aws:RequestedRegion": "eu-west-1"},
            )
        )
        self.assertEqual(
            effective_permissions(plan.documents(), probes),
            effective_permissions([self.policy], probes),
        )

    def test_fragments_reconstruct_the_cartesian_product(self):
        plan = build_release_plan(self.policy, BatchLimits(max_bytes=400))
        s3_fragments = [
            f
            for batch in plan.batches
            for f in batch.fragments
            if f.source_index == 1
        ]
        pairs = {
            (action, resource)
            for fragment in s3_fragments
            for action in fragment.statement["Action"]
            for resource in fragment.statement["Resource"]
        }
        expected = {
            (action, resource) for action in ALLOW_S3["Action"] for resource in ALLOW_S3["Resource"]
        }
        self.assertEqual(pairs, expected)

    def test_structural_statement_limit_is_enforced(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [f"s3:Action{index}"],
                    "Resource": [f"arn:aws:s3:::bucket{index}"],
                }
                for index in range(5)
            ],
        }
        plan = build_release_plan(policy, BatchLimits(max_statements=2))
        self.assertTrue(all(len(batch.fragments) <= 2 for batch in plan.batches))
        self.assertEqual(sum(len(batch.fragments) for batch in plan.batches), 5)

    def test_action_entry_limit_triggers_action_level_split(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [f"s3:Action{index}" for index in range(6)],
                    "Resource": ["arn:aws:s3:::bucket/object"],
                }
            ],
        }
        plan = build_release_plan(policy, BatchLimits(max_action_entries=2))
        for batch in plan.batches:
            self.assertLessEqual(batch_usage(batch)["action_entries"], 2)


class InfeasibilityTestCase(unittest.TestCase):
    def test_oversized_atomic_deny_returns_reviewable_blockers(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": ["s3:*"],
                    "Resource": ["arn:aws:s3:::" + "x" * 9000],
                }
            ],
        }
        with self.assertRaises(InfeasiblePlanError) as context:
            build_release_plan(policy, BatchLimits(max_bytes=6144))
        self.assertTrue(any("Deny statement 0" in blocker for blocker in context.exception.blockers))

    def test_minimal_fragment_overflow_is_reported(self):
        # A single (action, resource) pair whose ARN alone exceeds the document cap.
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["arn:aws:s3:::" + "y" * 6000],
                }
            ],
        }
        with self.assertRaises(InfeasiblePlanError):
            build_release_plan(policy, BatchLimits(max_bytes=1024))

    def test_verify_plan_rejects_tampered_ordering(self):
        plan = build_release_plan(sample_policy(), BatchLimits(max_bytes=400))
        # Manually move a deny behind an allow and confirm verification catches it.
        deny_batch = plan.batches[0]
        deny_fragment = next(f for f in deny_batch.fragments if f.statement["Effect"] == "Deny")
        deny_batch.fragments.remove(deny_fragment)
        plan.batches[-1].fragments.append(deny_fragment)
        with self.assertRaises(InfeasiblePlanError) as context:
            plan.verify()
        self.assertTrue(any("deny window" in blocker for blocker in context.exception.blockers))


class EdgeCaseTestCase(unittest.TestCase):
    def test_policy_without_statement_is_rejected(self):
        with self.assertRaises(ValueError):
            build_release_plan({"Version": "2012-10-17"}, BatchLimits())

    def test_empty_statement_list_yields_empty_feasible_plan(self):
        plan = build_release_plan({"Version": "2012-10-17", "Statement": []}, BatchLimits())
        self.assertTrue(plan.feasible)
        self.assertEqual(plan.documents(), [])

    def test_allow_only_policy_starts_with_batch_one(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:PutObject"],
                    "Resource": ["arn:aws:s3:::bucket/a", "arn:aws:s3:::bucket/b"],
                }
            ],
        }
        plan = build_release_plan(policy, BatchLimits(max_bytes=300))
        self.assertEqual(plan.batches[0].sequence, 1)
        self.assertTrue(all(f.statement["Effect"] == "Allow" for f in plan.batches[0].fragments))

    def test_dict_form_statement_is_accepted(self):
        policy = {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::b/a"]},
        }
        plan = build_release_plan(policy, BatchLimits(max_bytes=250))
        self.assertEqual(len(plan.batches), 1)


class ManifestAndRollbackTestCase(unittest.TestCase):
    def test_manifest_describes_install_and_rollback(self):
        plan = build_release_plan(sample_policy(), BatchLimits(max_bytes=400))
        manifest = plan.to_manifest()
        self.assertTrue(manifest["feasible"])
        self.assertEqual(len(manifest["batches"]), len(plan.batches))
        for entry in manifest["batches"]:
            self.assertEqual(entry["install"], f"batch-{entry['sequence']:02d}.json")
            self.assertLessEqual(entry["bytes"], 400)

    def test_rollback_keeps_deny_batch_last_to_remove(self):
        plan = build_release_plan(sample_policy(), BatchLimits(max_bytes=400))
        rollback = explain_rollback(plan, 2)
        self.assertEqual(rollback["detach"], ["batch-02.json"])
        # Full rollback is reverse order; batch-01 (the denies) is removed last.
        self.assertEqual(rollback["full_rollback_order"][-1], "batch-01.json")

    def test_document_size_is_utf8_compact_json(self):
        policy = sample_policy()
        self.assertEqual(document_size(policy), len(__import__("orjson").dumps(policy)))

    def test_plan_is_a_dataclass_with_documents(self):
        plan = build_release_plan(sample_policy(), BatchLimits(max_bytes=400))
        self.assertIsInstance(plan, ReleasePlan)
        self.assertEqual(len(plan.documents()), len(plan.batches))
        for document in plan.documents():
            self.assertEqual(document["Version"], "2012-10-17")


if __name__ == "__main__":
    unittest.main()
