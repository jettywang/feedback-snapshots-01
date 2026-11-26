import unittest

from policy_sentry.writing.corrections import (
    CorrectionError,
    apply_corrections,
    load_corrections,
    parse_corrections,
)

CATALOG = {
    "policy_sentry_schema_version": "v2",
    "ssm": {
        "service_name": "AWS Systems Manager",
        "prefix": "ssm",
        "service_authorization_url": "https://example.invalid/ssm",
        "privileges": {
            "PutParameter": {
                "privilege": "PutParameter",
                "access_level": "Tagging",
                "access_level_documented": "Tagging",
                "access_level_override": None,
                "resource_types": {"parameter": {"condition_keys": [], "dependent_actions": []}},
            },
            "GetParameter": {
                "privilege": "GetParameter",
                "access_level": "Read",
                "access_level_documented": "Read",
                "access_level_override": None,
                "resource_types": {"parameter": {"condition_keys": [], "dependent_actions": []}},
            },
        },
        "privileges_lower_name": {"putparameter": "PutParameter", "getparameter": "GetParameter"},
        "resources": {"parameter": {"arn": "arn:${Partition}:ssm:${Region}:${Account}:parameter/${Name}"}},
        "resources_lower_name": {"parameter": "parameter"},
        "conditions": {},
    },
}


def correction(**overrides):
    payload = {
        "id": "C1",
        "service": "ssm",
        "action": "PutParameter",
        "corrected_access_level": "Write",
        "rationale": "Parameters are writes.",
        "approval": {"status": "approved", "approver": "board", "approved_at": "2026-10-09"},
    }
    payload.update(overrides)
    return payload


class CorrectionParsingTests(unittest.TestCase):
    def test_parses_approval_and_hashes_file(self):
        parsed = parse_corrections({"corrections": [correction()]})
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed.corrections[0].approval.status, "approved")
        self.assertEqual(len(parsed.sha256), 64)

    def test_hash_ignores_mapping_order(self):
        first = parse_corrections({"corrections": [correction()]})
        second = parse_corrections({"corrections": [correction(service="ssm")]})
        self.assertEqual(first.sha256, second.sha256)

    def test_rejects_duplicate_ids(self):
        with self.assertRaises(CorrectionError):
            parse_corrections({"corrections": [correction(), correction(action="GetParameter")]})

    def test_rejects_conflicting_corrections_for_one_action(self):
        with self.assertRaises(CorrectionError):
            parse_corrections(
                {"corrections": [correction(), correction(id="C2", corrected_access_level="List")]}
            )

    def test_rejects_unknown_access_level(self):
        with self.assertRaises(CorrectionError):
            parse_corrections({"corrections": [correction(corrected_access_level="Admin")]})

    def test_rejects_unknown_approval_status(self):
        with self.assertRaises(CorrectionError):
            parse_corrections({"corrections": [correction(approval={"status": "maybe"})]})


class CorrectionApplicationTests(unittest.TestCase):
    def setUp(self):
        self.corrections = parse_corrections({"corrections": [correction()]})

    def test_approved_correction_changes_effective_level(self):
        view = apply_corrections(CATALOG, self.corrections)
        self.assertEqual(view.catalog["ssm"]["privileges"]["PutParameter"]["access_level"], "Write")
        self.assertEqual(view.catalog["ssm"]["privileges"]["PutParameter"]["access_level_documented"], "Tagging")
        self.assertEqual(view.applied[0].documented_access_level, "Tagging")

    def test_pending_correction_does_not_change_generation(self):
        pending = parse_corrections({"corrections": [correction(approval={"status": "pending"})]})
        view = apply_corrections(CATALOG, pending)
        self.assertEqual(view.catalog["ssm"]["privileges"]["PutParameter"]["access_level"], "Tagging")
        self.assertEqual(view.applied, [])

    def test_unapproved_correction_only_applies_for_what_if(self):
        pending = parse_corrections({"corrections": [correction(approval={"status": "pending"})]})
        view = apply_corrections(CATALOG, pending, include_unapproved=True)
        self.assertEqual(view.catalog["ssm"]["privileges"]["PutParameter"]["access_level"], "Write")

    def test_original_catalog_is_not_mutated(self):
        apply_corrections(CATALOG, self.corrections)
        self.assertEqual(CATALOG["ssm"]["privileges"]["PutParameter"]["access_level"], "Tagging")

    def test_missing_action_is_reported_not_silently_ignored(self):
        corrections = parse_corrections(
            {"corrections": [correction(action="DoesNotExist")]}
        )
        view = apply_corrections(CATALOG, corrections)
        self.assertEqual(view.applied, [])
        self.assertEqual(len(view.skipped), 1)
        self.assertIn("not present in this catalog", view.skipped[0].issue)

    def test_missing_service_is_reported(self):
        corrections = parse_corrections({"corrections": [correction(service="s3", action="PutBucketPolicy")]})
        view = apply_corrections(CATALOG, corrections)
        self.assertEqual(len(view.skipped), 1)
        self.assertIn("not present in this catalog", view.skipped[0].issue)


class LoadCorrectionsFileTests(unittest.TestCase):
    def test_load_shipped_example(self):
        parsed = load_corrections("examples/provenance/corrections.yml")
        self.assertEqual(parsed.for_action("ssm", "PutParameter").id, "SEC-194-C01")
        self.assertFalse(parsed.for_action("secretsmanager", "CreateSecret").is_approved)


if __name__ == "__main__":
    unittest.main()
