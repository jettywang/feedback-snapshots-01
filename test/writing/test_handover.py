import copy
import os
import unittest

from policy_sentry.util.file import read_yaml_file
from policy_sentry.writing.handover import (
    HandoverConfigError,
    evaluate_handover,
    render_effective_policy,
    render_temporary_policy,
    usable_permissions,
)
from policy_sentry.writing.sid_group import SidGroup

EXAMPLE_PATH = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        os.path.pardir,
        os.path.pardir,
        "examples",
        "yml",
        "handover",
        "two-project-handover.yml",
    )
)

BEFORE = "2026-11-30T00:00:00Z"
DURING = "2026-12-01T12:00:00Z"
AFTER = "2026-12-03T00:00:00Z"

SHARED = "arn:aws:s3:::shared-policies/team/*"
ALPHA = "arn:aws:s3:::project-alpha/artifacts/*"
BETA = "arn:aws:s3:::project-beta/artifacts/*"


def _rows(result):
    return {(row["action"], row["resource"]): row for row in result["available_permissions"]}


def _minimal_cfg(**overrides):
    cfg = {
        "mode": "crud",
        "name": "TestRole",
        "read": [SHARED],
        "handover": {
            "approval": {"project": "project-alpha", "start": "2026-12-01T00:00:00Z", "end": "2026-12-02T00:00:00Z"},
            "projects": [
                {
                    "name": "project-alpha",
                    "access": {"read": [SHARED], "write": [SHARED]},
                }
            ],
        },
    }
    for key, value in overrides.items():
        cfg[key] = value
    return cfg


class HandoverPhasesTestCase(unittest.TestCase):
    def setUp(self):
        self.cfg = read_yaml_file(EXAMPLE_PATH)

    def test_before_window_keeps_only_standing_permission(self):
        result = evaluate_handover(self.cfg, BEFORE)
        self.assertEqual(result["handover"]["status"], "scheduled")
        self.assertEqual(result["handover"]["active_projects"], [])
        rows = _rows(result)
        self.assertIn(("s3:GetObject", SHARED), rows)
        self.assertNotIn(("s3:PutObject", SHARED), rows)
        self.assertFalse(any(resource == ALPHA for _, resource in rows))
        self.assertTrue(all(row["origins"] == ["standing"] for row in rows.values()))
        self.assertEqual(result["summary"]["available"], len(result["standing_scope"]))

    def test_during_window_only_approved_project_gains_actions(self):
        result = evaluate_handover(self.cfg, DURING)
        self.assertEqual(result["handover"]["status"], "active")
        self.assertEqual(result["handover"]["active_projects"], ["project-alpha"])
        rows = _rows(result)

        self.assertEqual(rows[("s3:PutObject", SHARED)]["origins"], ["temporary"])
        self.assertIn(("s3:PutObject", ALPHA), rows)
        self.assertIn(("s3:GetObject", ALPHA), rows)
        # project-beta is declared but not approved, so it must not add any permission.
        self.assertFalse(any(resource == BETA for _, resource in rows))
        self.assertFalse(any(str(row["sources"]).find("project-beta") >= 0 for row in rows.values()))

    def test_after_window_matches_before_window(self):
        before = evaluate_handover(self.cfg, BEFORE)
        after = evaluate_handover(self.cfg, AFTER)
        self.assertEqual(after["handover"]["status"], "expired")
        self.assertEqual(after["available_permissions"], before["available_permissions"])
        self.assertEqual(after["standing_scope"], before["standing_scope"])
        self.assertEqual(after["summary"]["temporary_only"], 0)

    def test_shared_resource_keeps_standing_action_after_expiry(self):
        after = evaluate_handover(self.cfg, AFTER)
        rows = _rows(after)
        self.assertEqual(rows[("s3:GetObject", SHARED)]["origins"], ["standing"])
        self.assertIn(("s3:GetObject", SHARED), rows)
        # The formal role still reads the shared prefix; the temporary write grant is gone.
        self.assertNotIn(("s3:PutObject", SHARED), rows)


class HandoverProvenanceTestCase(unittest.TestCase):
    def setUp(self):
        self.cfg = read_yaml_file(EXAMPLE_PATH)

    def test_window_boundary_is_start_inclusive_end_exclusive(self):
        result = evaluate_handover(self.cfg, "2026-12-02T00:00:00Z")
        self.assertEqual(result["handover"]["status"], "expired")
        start = evaluate_handover(self.cfg, "2026-12-01T00:00:00Z")
        self.assertEqual(start["handover"]["status"], "active")

    def test_shared_permission_lists_both_sources(self):
        rows = _rows(evaluate_handover(self.cfg, DURING))
        row = rows[("s3:GetObject", SHARED)]
        self.assertEqual(row["origins"], ["standing", "temporary"])
        self.assertEqual(len(row["sources"]), 2)
        self.assertIn({"origin": "standing"}, row["sources"])
        temporary = next(source for source in row["sources"] if source["origin"] == "temporary")
        self.assertEqual(temporary["project"], "project-alpha")
        self.assertEqual(temporary["approval"]["project"], "project-alpha")

    def test_temporary_only_permission_cites_the_approval(self):
        rows = _rows(evaluate_handover(self.cfg, DURING))
        row = rows[("s3:PutObject", ALPHA)]
        self.assertEqual(row["origins"], ["temporary"])
        self.assertEqual(row["sources"][0]["project"], "project-alpha")
        self.assertEqual(row["sources"][0]["approval"]["start"], "2026-12-01T00:00:00Z")

    def test_standing_and_temporary_scopes_are_reconstructable(self):
        result = evaluate_handover(self.cfg, DURING)
        standing_pairs = {(row["action"], row["resource"]) for row in result["standing_scope"]}
        temporary_pairs = {(row["action"], row["resource"]) for row in result["temporary_scope"]}
        self.assertIn(("s3:GetObject", SHARED), standing_pairs)
        self.assertNotIn(("s3:PutObject", SHARED), standing_pairs)
        self.assertIn(("s3:PutObject", SHARED), temporary_pairs)
        self.assertIn(("s3:GetObject", ALPHA), temporary_pairs)
        self.assertFalse(any(resource == BETA for _, resource in temporary_pairs))
        available = {(row["action"], row["resource"]) for row in result["available_permissions"]}
        self.assertEqual(available, standing_pairs | temporary_pairs)

    def test_usable_permissions_helper_matches_report(self):
        self.assertEqual(
            usable_permissions(self.cfg, DURING),
            evaluate_handover(self.cfg, DURING)["available_permissions"],
        )


class HandoverImmutabilityTestCase(unittest.TestCase):
    def test_removing_temporary_policy_does_not_touch_standing(self):
        cfg = read_yaml_file(EXAMPLE_PATH)
        standing_before = evaluate_handover(cfg, BEFORE)["standing_scope"]
        temporary_during = render_temporary_policy(cfg, DURING)
        self.assertTrue(temporary_during["Statement"])
        # Removing the temporary approval is equivalent to evaluating outside the window.
        after = evaluate_handover(cfg, AFTER)
        self.assertEqual(after["standing_scope"], standing_before)
        self.assertEqual(render_temporary_policy(cfg, AFTER)["Statement"], [])
        self.assertTrue(render_effective_policy(cfg, AFTER)["Statement"])

    def test_evaluating_does_not_mutate_the_template(self):
        cfg = read_yaml_file(EXAMPLE_PATH)
        snapshot = copy.deepcopy(cfg)
        evaluate_handover(cfg, DURING)
        render_temporary_policy(cfg, DURING)
        render_effective_policy(cfg, DURING)
        self.assertEqual(cfg, snapshot)

    def test_write_policy_refuses_a_handover_template(self):
        cfg = read_yaml_file(EXAMPLE_PATH)
        with self.assertRaises(ValueError):
            SidGroup().process_template(cfg)

    def test_missing_handover_block_is_a_config_error(self):
        with self.assertRaises(HandoverConfigError):
            evaluate_handover({"mode": "crud", "read": [SHARED]}, DURING)

    def test_crud_template_alone_still_renders(self):
        cfg = read_yaml_file(EXAMPLE_PATH)
        cfg.pop("handover")
        rendered = SidGroup().process_template(cfg)
        self.assertTrue(rendered["Statement"])


class HandoverConflictTestCase(unittest.TestCase):
    def test_unknown_approved_project_is_a_conflict(self):
        cfg = _minimal_cfg()
        cfg["handover"]["approval"]["project"] = "project-beta"
        result = evaluate_handover(cfg, DURING)
        codes = [conflict["code"] for conflict in result["conflicts"]]
        self.assertIn("approval-unknown-project", codes)
        self.assertEqual(result["temporary_scope"], [])

    def test_window_that_ends_before_it_starts_is_a_conflict(self):
        cfg = _minimal_cfg()
        cfg["handover"]["approval"]["start"] = "2026-12-02T00:00:00Z"
        cfg["handover"]["approval"]["end"] = "2026-12-01T00:00:00Z"
        result = evaluate_handover(cfg, DURING)
        self.assertEqual(result["handover"]["status"], "invalid-window")
        self.assertEqual(result["conflicts"][0]["code"], "invalid-window")

    def test_wildcard_temporary_action_is_a_conflict(self):
        cfg = _minimal_cfg()
        cfg["handover"]["projects"][0]["access"] = {
            "wildcard-only": {"single-actions": ["s3:ListAllMyBuckets"]},
            "read": [SHARED],
        }
        result = evaluate_handover(cfg, DURING)
        conflicts = result["conflicts"]
        self.assertTrue(any(conflict["code"] == "temporary-resource-unbounded" for conflict in conflicts))
        # The unbounded action is withheld, but the bounded project read access still applies.
        self.assertNotIn(("s3:ListAllMyBuckets", "*"), _rows(result))
        self.assertTrue(any(resource == SHARED for _, resource in _rows(result)))

    def test_formal_deny_mixed_with_temporary_allow_is_a_conflict(self):
        cfg = _minimal_cfg(effect="Deny")
        result = evaluate_handover(cfg, DURING)
        codes = [conflict["code"] for conflict in result["conflicts"]]
        self.assertIn("effect-not-expressible", codes)

    def test_duplicate_project_names_are_a_conflict(self):
        cfg = _minimal_cfg()
        cfg["handover"]["projects"].append(copy.deepcopy(cfg["handover"]["projects"][0]))
        result = evaluate_handover(cfg, DURING)
        codes = [conflict["code"] for conflict in result["conflicts"]]
        self.assertIn("duplicate-project", codes)
        self.assertEqual(result["temporary_scope"], [])

    def test_projects_without_approval_are_a_conflict(self):
        cfg = _minimal_cfg()
        del cfg["handover"]["approval"]
        result = evaluate_handover(cfg, DURING)
        self.assertEqual(result["handover"]["status"], "not-approved")
        self.assertEqual(result["conflicts"][0]["code"], "approval-missing")
