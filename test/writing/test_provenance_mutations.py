"""
Behavioural tests for provenance when the *content* of the catalog or the
corrections changes, rather than the shipped example snapshots.
"""

import copy
import unittest

from policy_sentry.shared.iam_data import load_iam_definition
from policy_sentry.writing.corrections import parse_corrections
from policy_sentry.writing.provenance import render_artifact

# Both write and tagging are requested for the same parameter. A correction
# that moves PutParameter from Tagging to Write therefore moves it between
# statements, which is exactly the case a reviewer must be able to see.
TEMPLATE = {
    "mode": "crud",
    "name": "MutatingCase",
    "write": ["arn:aws:ssm:us-east-1:123456789012:parameter/demo"],
    "tagging": ["arn:aws:ssm:us-east-1:123456789012:parameter/demo"],
    "read": ["arn:aws:ssm:us-east-1:123456789012:parameter/demo"],
}
PARAMETER_ARN = "arn:aws:ssm:us-east-1:123456789012:parameter/demo"


def catalog():
    definition = load_iam_definition("policy_sentry/shared/data/iam-definition.json")
    return {
        "policy_sentry_schema_version": definition["policy_sentry_schema_version"],
        "ssm": copy.deepcopy(definition["ssm"]),
        "iam": copy.deepcopy(definition["iam"]),
    }


def set_level(definition, action, level, *, documented=None):
    entry = definition["ssm"]["privileges"][action]
    entry["access_level"] = level
    entry["access_level_documented"] = documented if documented is not None else level
    return definition


def corrections(*entries):
    return parse_corrections({"corrections": list(entries)})


def rule(rule_id, action, level, status="approved"):
    return {
        "id": rule_id,
        "service": "ssm",
        "action": action,
        "corrected_access_level": level,
        "rationale": "test",
        "approval": {"status": status, "approver": "board", "approved_at": "2026-01-01"},
    }


def record_for(artifact, action):
    return next(record for record in artifact.records if record["action"] == action)


class CorrectionMovesActionBetweenStatementsTests(unittest.TestCase):
    def test_documented_tagging_places_action_in_tagging_statement(self):
        definition = set_level(catalog(), "PutParameter", "Tagging")
        artifact = render_artifact(TEMPLATE, definition, corrections(), "documented")
        record = record_for(artifact, "ssm:PutParameter")
        self.assertEqual(record["statement"]["sid"], "SsmTaggingParameter")
        self.assertEqual(record["catalog"]["documented_access_level"], "Tagging")
        self.assertEqual(record["catalog"]["effective_access_level"], "Tagging")
        self.assertIsNone(record["correction"])

    def test_approved_correction_moves_action_into_write_statement(self):
        definition = set_level(catalog(), "PutParameter", "Tagging")
        artifact = render_artifact(
            TEMPLATE, definition, corrections(rule("C1", "PutParameter", "Write")), "corrected"
        )
        record = record_for(artifact, "ssm:PutParameter")
        self.assertEqual(record["statement"]["sid"], "SsmWriteParameter")
        self.assertEqual(record["catalog"]["documented_access_level"], "Tagging")
        self.assertEqual(record["catalog"]["effective_access_level"], "Write")
        self.assertEqual(record["correction"]["id"], "C1")
        self.assertEqual(record["approval"]["status"], "approved")

    def test_pending_rule_does_not_move_action(self):
        definition = set_level(catalog(), "PutParameter", "Tagging")
        artifact = render_artifact(
            TEMPLATE,
            definition,
            corrections(rule("C1", "PutParameter", "Write", status="pending")),
            "pending",
        )
        record = record_for(artifact, "ssm:PutParameter")
        self.assertIsNone(record["correction"])
        self.assertEqual(record["statement"]["sid"], "SsmTaggingParameter")

    def test_corrected_action_is_not_left_in_the_old_statement(self):
        definition = set_level(catalog(), "PutParameter", "Tagging")
        artifact = render_artifact(
            TEMPLATE, definition, corrections(rule("C1", "PutParameter", "Write")), "corrected"
        )
        self.assertEqual(record_for(artifact, "ssm:PutParameter")["statement"]["sid"], "SsmWriteParameter")
        tagging = [s for s in artifact.statements if s["sid"] == "SsmTaggingParameter"]
        if tagging:
            self.assertNotIn("ssm:PutParameter", tagging[0]["actions"])

    def test_action_outside_template_is_not_recorded(self):
        artifact = render_artifact(TEMPLATE, catalog(), corrections(), "scoped")
        actions = {record["action"] for record in artifact.records}
        self.assertIn("ssm:PutParameter", actions)
        self.assertNotIn("ssm:CreateDocument", actions)
        self.assertNotIn("ssm:ModifyDocumentPermission", actions)

    def test_unused_service_is_absent_from_catalog_scope(self):
        definition = set_level(catalog(), "PutParameter", "Tagging")
        artifact = render_artifact(TEMPLATE, definition, corrections(), "scope")
        self.assertEqual(artifact.catalog_version.services, ["ssm"])

    def test_statement_conditions_are_explicitly_null(self):
        artifact = render_artifact(TEMPLATE, catalog(), corrections(), "conditions")
        record = record_for(artifact, "ssm:GetParameter")
        self.assertIsNone(record["conditions"]["statement_conditions"])
        self.assertEqual(record["conditions"]["source"], "catalog")

    def test_basis_fingerprint_ignores_unrelated_actions(self):
        baseline = set_level(catalog(), "PutParameter", "Tagging")
        untouched = copy.deepcopy(baseline)
        set_level(untouched, "CreateDocument", "Read")
        first = render_artifact(TEMPLATE, baseline, corrections(), "a")
        second = render_artifact(TEMPLATE, untouched, corrections(), "b")
        self.assertEqual(
            record_for(first, "ssm:PutParameter")["basis_fingerprint"],
            record_for(second, "ssm:PutParameter")["basis_fingerprint"],
        )

    def test_basis_fingerprint_changes_when_resource_changes(self):
        baseline = set_level(catalog(), "PutParameter", "Tagging")
        artifact_a = render_artifact(TEMPLATE, baseline, corrections(), "a")
        narrower = copy.deepcopy(TEMPLATE)
        narrower["tagging"] = ["arn:aws:ssm:us-east-1:123456789012:parameter/demo/narrow"]
        artifact_b = render_artifact(narrower, baseline, corrections(), "b")
        self.assertNotEqual(
            record_for(artifact_a, "ssm:PutParameter")["basis_fingerprint"],
            record_for(artifact_b, "ssm:PutParameter")["basis_fingerprint"],
        )


if __name__ == "__main__":
    unittest.main()
