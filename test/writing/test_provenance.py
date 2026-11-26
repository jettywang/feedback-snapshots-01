import copy
import json
import unittest
from pathlib import Path

from policy_sentry.shared.iam_data import load_iam_definition
from policy_sentry.writing.corrections import load_corrections
from policy_sentry.util.file import read_yaml_file
from policy_sentry.writing.provenance import (
    build_report,
    render_artifact,
    write_artifacts,
)

EXAMPLES = Path("examples/provenance")
TEMPLATE = EXAMPLES / "template.yml"
CORRECTIONS = EXAMPLES / "corrections.yml"
CATALOGS = [
    ("catalog-2026-10-01", EXAMPLES / "catalogs/catalog-2026-10-01.json"),
    ("catalog-2026-11-15", EXAMPLES / "catalogs/catalog-2026-11-15.json"),
    ("catalog-2026-12-01", EXAMPLES / "catalogs/catalog-2026-12-01.json"),
]


def build():
    return build_report(TEMPLATE, CATALOGS, CORRECTIONS)


class ProvenanceRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = build()
        cls.baseline = cls.report["artifacts"][0]

    def record(self, action, artifact=None):
        artifact = artifact or self.baseline
        return next(record for record in artifact["records"] if record["action"] == action)

    def test_every_rendered_action_has_a_record(self):
        for statement in self.baseline["policy"]["Statement"]:
            for action in statement["Action"]:
                self.record(action)

    def test_record_locates_statement_action_and_catalog_version(self):
        record = self.record("ssm:PutParameter")
        self.assertEqual(record["statement"]["sid"], "SsmWriteParameter")
        self.assertEqual(record["rendered_action"], "ssm:PutParameter")
        self.assertEqual(record["catalog"]["version"], "catalog-2026-10-01")
        self.assertEqual(record["catalog"]["documented_access_level"], "Tagging")
        self.assertEqual(record["catalog"]["effective_access_level"], "Write")
        self.assertTrue(record["catalog"]["fingerprint"])

    def test_record_names_the_correction_and_approval(self):
        record = self.record("ssm:PutParameter")
        self.assertEqual(record["correction"]["id"], "SEC-194-C01")
        self.assertEqual(record["approval"]["status"], "approved")
        self.assertEqual(record["approval"]["approver"], "security-review-board")
        self.assertEqual(record["approval"]["reference"], "ARB-2026-101")

    def test_record_carries_origin_and_conditions(self):
        record = self.record("ssm:GetParameter")
        self.assertEqual(record["origin"]["template_section"], "read")
        self.assertEqual(record["origin"]["requested_access_level"], "Read")
        self.assertIn("arn:aws:ssm:us-east-1:123456789012:parameter/demo", record["origin"]["requested_arns"])
        self.assertIn("aws:ResourceTag/${TagKey}", record["conditions"]["keys"])
        self.assertIsNone(record["approval"]["approver"])

    def test_dependent_action_records_its_parent(self):
        record = self.record("iam:PassRole")
        self.assertEqual(record["origin"]["kind"], "dependent_action")
        self.assertTrue(record["origin"]["dependent_of"])
        self.assertEqual(record["statement"]["sid"], "MultMultNone")

    def test_record_ids_are_unique_and_stable(self):
        ids = [record["record_id"] for record in self.baseline["records"]]
        self.assertEqual(len(ids), len(set(ids)))
        again = build()
        self.assertEqual(
            [record["record_id"] for record in again["artifacts"][0]["records"]],
            ids,
        )

    def test_report_scopes_corrections_to_the_policy(self):
        self.assertEqual(self.report["corrections"]["relevant_ids"], ["SEC-194-C01", "SEC-194-C02"])
        self.assertEqual(self.report["corrections"]["irrelevant_ids"], ["SEC-194-C04"])

    def test_report_scopes_catalog_to_services_used(self):
        self.assertEqual(self.baseline["catalog"]["services"], ["iam", "secretsmanager", "ssm"])

    def test_report_scopes_template_sections_to_those_used(self):
        self.assertEqual(
            self.report["template"]["sections_used"],
            ["actions", "permissions-management", "read", "tagging", "write"],
        )


class UnapprovedCorrectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = build()

    def test_pending_rule_is_named_with_affected_template_part(self):
        blocked = {entry["correction_id"]: entry for entry in self.report["blocked_by_unapproved_rules"]}
        self.assertIn("SEC-194-C03", blocked)
        entry = blocked["SEC-194-C03"]
        self.assertEqual(entry["action"], "secretsmanager:CreateSecret")
        self.assertEqual(entry["approval_status"], "pending")
        self.assertEqual(entry["effect_if_approved"], "would_remove_action")
        self.assertEqual(
            [part["template_section"] for part in entry["template_parts"]],
            ["tagging"],
        )
        self.assertIn("tagging", entry["message"])
        self.assertIn("cannot be published", entry["message"])

    def test_pending_rule_is_not_applied_to_the_artifact(self):
        record = next(
            record
            for record in self.report["artifacts"][0]["records"]
            if record["action"] == "secretsmanager:CreateSecret"
        )
        self.assertIsNone(record["correction"])
        self.assertEqual(record["approval"]["status"], "catalog_documented")

    def test_pending_rule_outside_the_template_is_not_in_the_report(self):
        ids = {entry["correction_id"] for entry in self.report["blocked_by_unapproved_rules"]}
        self.assertNotIn("SEC-194-C04", ids)


class CrossCatalogComparisonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = build()
        cls.correction_case, cls.unrelated_case = cls.report["comparisons"]

    def test_correction_case_links_both_actual_artifacts(self):
        comparison = self.correction_case
        self.assertEqual(comparison["baseline"], "catalog-2026-10-01")
        self.assertEqual(comparison["catalog"], "catalog-2026-11-15")
        self.assertTrue(comparison["artifacts"]["policies_identical"])
        self.assertEqual(
            comparison["artifacts"]["baseline"]["policy_sha256"],
            self.report["artifacts"][0]["policy_sha256"],
        )
        self.assertEqual(
            comparison["artifacts"]["catalog"]["policy_sha256"],
            self.report["artifacts"][1]["policy_sha256"],
        )

    def test_correction_case_points_at_action_and_statement(self):
        comparison = self.correction_case
        self.assertEqual([entry["action"] for entry in comparison["actions"]], ["ssm:PutParameter"])
        change = comparison["actions"][0]
        self.assertEqual(change["status"], "catalog_changed")
        self.assertFalse(change["permissions_changed"])
        self.assertEqual(change["before"]["statement"]["sid"], "SsmWriteParameter")
        self.assertEqual(change["after"]["statement"]["sid"], "SsmWriteParameter")
        self.assertEqual(
            change["causes"][0],
            {
                "type": "catalog_entry",
                "field": "documented_access_level",
                "before": "Tagging",
                "after": "Write",
            },
        )
        statement = next(s for s in comparison["statements"] if s["sid"] == "SsmWriteParameter")
        self.assertEqual(statement["status"], "basis_changed")
        self.assertEqual(statement["changed_actions"], ["ssm:PutParameter"])

    def test_correction_case_flags_the_approval_to_reopen(self):
        reopen = self.correction_case["approvals"]["reopen"]
        self.assertEqual([entry["correction_id"] for entry in reopen], ["SEC-194-C01"])
        self.assertEqual(reopen[0]["documented_access_level"], {"baseline": "Tagging", "catalog": "Write"})
        still_applies = self.correction_case["approvals"]["still_applies"]
        self.assertEqual([entry["correction_id"] for entry in still_applies], ["SEC-194-C02"])

    def test_correction_case_keeps_unchanged_actions_on_their_original_basis(self):
        unchanged = {entry["action"]: entry for entry in self.correction_case["unchanged"]}
        self.assertIn("ssm:CreateDocument", unchanged)
        document = unchanged["ssm:CreateDocument"]
        self.assertEqual(document["record_id"], document["superseded_record_id"])
        self.assertTrue(unchanged["ssm:CreateDocument"]["reused_basis"])
        self.assertEqual(self.correction_case["summary"]["actions_unchanged"], 31)

    def test_unrelated_change_only_touches_unused_actions(self):
        comparison = self.unrelated_case
        self.assertEqual(comparison["verdict"], "catalog_changed_outside_template")
        self.assertEqual(comparison["actions"], [])
        self.assertEqual(
            [entry["action"] for entry in comparison["catalog_delta"]["not_used_by_template"]],
            ["lambda:GetFunction"],
        )
        self.assertEqual(comparison["catalog_delta"]["used_by_template"], [])
        self.assertEqual(comparison["approvals"]["reopen"], [])
        self.assertEqual(comparison["summary"]["records_reused"], 32)


class ArtifactWritingTests(unittest.TestCase):
    def test_written_files_are_independently_verifiable(self):
        import hashlib
        import tempfile

        report = build()
        with tempfile.TemporaryDirectory() as directory:
            written = write_artifacts(report, directory)
            self.assertTrue(written)
            manifest = json.loads((Path(directory) / "manifest.json").read_text())
            for relative_path, digest in manifest["files"].items():
                payload = (Path(directory) / relative_path).read_bytes()
                self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)

            artifact = json.loads((Path(directory) / "catalog-2026-10-01" / "provenance.json").read_text())
            policy = (Path(directory) / "catalog-2026-10-01" / "policy.json").read_bytes()
            self.assertEqual(hashlib.sha256(policy).hexdigest(), hashlib.sha256(policy).hexdigest())
            self.assertEqual(artifact["policy"], report["artifacts"][0]["policy"])


class RenderIsolationTests(unittest.TestCase):
    def test_rendering_one_catalog_does_not_disturb_the_catalog_view(self):
        catalog = load_iam_definition(CATALOGS[0][1])
        snapshot = copy.deepcopy(catalog)
        corrections = load_corrections(CORRECTIONS)
        template = {"mode": "crud", "write": ["arn:aws:ssm:us-east-1:123456789012:parameter/demo"]}
        render_artifact(template, catalog, corrections, "probe")
        self.assertEqual(catalog, snapshot)


class MinimizedArtifactTests(unittest.TestCase):
    def test_minimized_statements_still_name_concrete_actions(self):
        template = read_yaml_file(EXAMPLES / "template.yml")
        from policy_sentry.shared.iam_data import use_iam_definition

        from policy_sentry.writing.sid_group import SidGroup

        with use_iam_definition(load_iam_definition(CATALOGS[0][1])):
            sid_group = SidGroup()
            minimized = sid_group.process_template(template, 0)

        self.assertTrue(any("*" in action for statement in minimized["Statement"] for action in statement["Action"]))
        for statement in minimized["Statement"]:
            for backing in sid_group.rendered_actions[statement["Sid"]]:
                self.assertIn(":", backing["action"])
                self.assertIn(backing["pattern"], statement["Action"])


if __name__ == "__main__":
    unittest.main()


class MinimizedReportTests(unittest.TestCase):
    def test_minimized_report_keeps_action_level_provenance(self):
        report = build_report(TEMPLATE, CATALOGS[:1], CORRECTIONS, minimize=0)
        artifact = report["artifacts"][0]
        self.assertTrue(
            any("*" in action for statement in artifact["policy"]["Statement"] for action in statement["Action"])
        )
        record = next(record for record in artifact["records"] if record["action"] == "ssm:PutParameter")
        self.assertEqual(record["origin"]["template_section"], "write")
        self.assertEqual(record["correction"]["id"], "SEC-194-C01")
        self.assertIn(record["rendered_action"], next(
            statement["Action"]
            for statement in artifact["policy"]["Statement"]
            if statement["Sid"] == record["statement"]["sid"]
        ))

    def test_minimized_report_still_flags_pending_rule(self):
        report = build_report(TEMPLATE, CATALOGS[:1], CORRECTIONS, minimize=0)
        blocked = {entry["correction_id"]: entry for entry in report["blocked_by_unapproved_rules"]}
        self.assertEqual(blocked["SEC-194-C03"]["effect_if_approved"], "would_remove_action")
        self.assertEqual(blocked["SEC-194-C03"]["template_parts"][0]["template_section"], "tagging")
