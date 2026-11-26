import unittest

from policy_sentry.writing.rule_engine import (
    AccessRequest,
    effective_permissions,
    evaluate_policies,
    requests_from_policy,
    statement_matches,
    wildcard_match,
)


class WildcardMatchTestCase(unittest.TestCase):
    def test_wildcards_and_case_insensitivity(self):
        self.assertTrue(wildcard_match("s3:Get*", "S3:GetObject"))
        self.assertTrue(wildcard_match("arn:aws:s3:::bucket/??", "arn:aws:s3:::bucket/ab"))
        self.assertFalse(wildcard_match("arn:aws:s3:::bucket/??", "arn:aws:s3:::bucket/abc"))


class StatementMatchingTestCase(unittest.TestCase):
    def test_action_and_resource_clauses(self):
        statement = {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::bucket/*",
        }
        self.assertTrue(
            statement_matches(statement, AccessRequest("s3:GetObject", "arn:aws:s3:::bucket/a"))
        )
        self.assertFalse(
            statement_matches(statement, AccessRequest("s3:PutObject", "arn:aws:s3:::bucket/a"))
        )

    def test_not_action_clause(self):
        statement = {"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"}
        self.assertTrue(statement_matches(statement, AccessRequest("s3:GetObject", "*")))
        self.assertFalse(statement_matches(statement, AccessRequest("iam:CreateUser", "*")))

    def test_string_conditions(self):
        statement = {
            "Effect": "Deny",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "*",
            "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}},
        }
        self.assertTrue(
            statement_matches(
                statement,
                AccessRequest(
                    "secretsmanager:GetSecretValue", "*", {"aws:RequestedRegion": "eu-west-1"}
                ),
            )
        )
        self.assertFalse(
            statement_matches(
                statement,
                AccessRequest(
                    "secretsmanager:GetSecretValue", "*", {"aws:RequestedRegion": "us-east-1"}
                ),
            )
        )

    def test_not_resource_clause(self):
        statement = {"Effect": "Allow", "Action": "s3:*", "NotResource": "arn:aws:s3:::secret"}
        self.assertTrue(
            statement_matches(statement, AccessRequest("s3:GetObject", "arn:aws:s3:::other"))
        )
        self.assertFalse(
            statement_matches(statement, AccessRequest("s3:GetObject", "arn:aws:s3:::secret"))
        )

    def test_if_exists_vacuous_when_key_absent(self):
        statement = {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": {"StringEqualsIfExists": {"ec2:Region": "us-east-1"}},
        }
        self.assertTrue(statement_matches(statement, AccessRequest("s3:GetObject", "*")))
        self.assertFalse(
            statement_matches(
                statement, AccessRequest("s3:GetObject", "*", {"ec2:Region": "eu-west-1"})
            )
        )

    def test_numeric_condition(self):
        statement = {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": {"NumericLessThanEquals": {"s3:max-keys": "10"}},
        }
        self.assertTrue(
            statement_matches(statement, AccessRequest("s3:GetObject", "*", {"s3:max-keys": 5}))
        )
        self.assertFalse(
            statement_matches(statement, AccessRequest("s3:GetObject", "*", {"s3:max-keys": 50}))
        )

    def test_unknown_condition_fails_closed_for_allow(self):
        statement = {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": {"DateGreaterThan": {"aws:CurrentTime": "2026-01-01T00:00:00Z"}},
        }
        self.assertFalse(statement_matches(statement, AccessRequest("s3:GetObject", "*")))


class EvaluationTestCase(unittest.TestCase):
    def setUp(self):
        self.policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:Get*", "Resource": "arn:aws:s3:::bucket/*"},
                {
                    "Effect": "Deny",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/secret",
                    "Condition": {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}},
                },
            ],
        }

    def test_explicit_deny_wins_over_allow(self):
        denied = AccessRequest(
            "s3:GetObject",
            "arn:aws:s3:::bucket/secret",
            {"aws:RequestedRegion": "eu-west-1"},
        )
        self.assertEqual(evaluate_policies([self.policy], denied), "Deny")

    def test_allowed_when_deny_condition_does_not_match(self):
        allowed = AccessRequest(
            "s3:GetObject",
            "arn:aws:s3:::bucket/secret",
            {"aws:RequestedRegion": "us-east-1"},
        )
        self.assertEqual(evaluate_policies([self.policy], allowed), "Allow")

    def test_implicit_deny_by_default(self):
        self.assertEqual(
            evaluate_policies([self.policy], AccessRequest("s3:PutObject", "arn:aws:s3:::bucket/x")),
            "Deny",
        )

    def test_deny_from_earlier_policy_beats_allow_in_later_policy(self):
        deny_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Deny", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/x"}
            ],
        }
        allow_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
        }
        request = AccessRequest("s3:GetObject", "arn:aws:s3:::bucket/x")
        self.assertEqual(evaluate_policies([deny_policy, allow_policy], request), "Deny")

    def test_effective_permissions_matrix_and_probes(self):
        probes = requests_from_policy(self.policy)
        matrix = effective_permissions([self.policy], probes)
        self.assertIn(("s3:Get*", "arn:aws:s3:::bucket/*"), matrix)
        # Deny statements do not add probes of their own.
        self.assertEqual(len(probes), 1)


if __name__ == "__main__":
    unittest.main()
