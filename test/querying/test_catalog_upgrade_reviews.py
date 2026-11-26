"""
Offline regression tests for re-checking internal access-level review records
against an upgraded IAM action catalog.

The fixtures under test/files/catalog_upgrade/ provide two small catalogs (old and
new) plus three synthetic review records:

* acme:DeployWidget - the new catalog now matches the manually approved value, but
  the catalog classification the approval referenced at the time has changed.
* acme:DescribeWidget - only display material (the description) changed; nothing
  relevant to the approval changed.
* acme:RetireWidget - the new catalog no longer contains a confirmable action.

Everything goes through the real catalog loading entry point
(policy_sentry.shared.iam_data.load_iam_definition) and the real query entry
points (policy_sentry.querying.actions), so the tests observe the classification
the application actually serves.
"""

from __future__ import annotations

import json
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from policy_sentry.querying import actions as action_queries
from policy_sentry.querying import all as all_queries
from policy_sentry.querying.actions import get_action_data, get_actions_with_access_level
from policy_sentry.shared import iam_data

FIXTURE_DIR = Path(__file__).parent.parent / "files" / "catalog_upgrade"
OLD_CATALOG_PATH = FIXTURE_DIR / "iam-definition-old.json"
NEW_CATALOG_PATH = FIXTURE_DIR / "iam-definition-new.json"
REVIEW_RECORDS_PATH = FIXTURE_DIR / "review-records.json"

STATUS_OK = "ok"
STATUS_RECHECK = "recheck"


def load_catalog(catalog_path: Path) -> dict[str, Any]:
    """Load a catalog fixture through the real IAM definition loading entry point."""
    original_path = iam_data.iam_definition_path
    iam_data.iam_definition_path = catalog_path
    try:
        return iam_data.load_iam_definition()
    finally:
        iam_data.iam_definition_path = original_path


def clear_query_caches() -> None:
    iam_data.get_service_prefix_data.cache_clear()
    iam_data.get_iam_definition_schema_version.cache_clear()
    action_queries.get_action_data.cache_clear()
    action_queries.get_actions_for_service.cache_clear()


@contextmanager
def activated_catalog(catalog: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Point the real query entry points at the given catalog, then restore."""
    originals = {
        iam_data: iam_data.iam_definition,
        action_queries: action_queries.iam_definition,
        all_queries: all_queries.iam_definition,
    }
    for module in originals:
        module.iam_definition = catalog
    clear_query_caches()
    try:
        yield catalog
    finally:
        for module, original in originals.items():
            module.iam_definition = original
        clear_query_caches()


def query_access_level(action: str) -> str | None:
    """Return the access level the application actually serves for an action.

    Returns None when the action is not confirmable in the active catalog.
    """
    service, _, action_name = action.partition(":")
    entries = get_action_data(service, action_name).get(service, [])
    if not entries:
        return None
    return entries[0]["access_level"]


def evaluate_review_records(
    records: list[dict[str, Any]],
    old_catalog: dict[str, Any],
    new_catalog: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Re-check each review record against a catalog upgrade.

    An approval needs re-checking when the action is no longer confirmable in the
    new catalog, or when the catalog classification the approval was based on has
    changed - even if the new catalog happens to match the manually approved value.
    """
    with activated_catalog(old_catalog):
        old_levels = {record["action"]: query_access_level(record["action"]) for record in records}
    with activated_catalog(new_catalog):
        new_levels = {record["action"]: query_access_level(record["action"]) for record in records}

    results = {}
    for record in records:
        action = record["action"]
        old_level = old_levels[action]
        new_level = new_levels[action]
        if new_level is None:
            results[action] = {
                "status": STATUS_RECHECK,
                "reason": "action-missing",
                "old_catalog_access_level": old_level,
                "new_catalog_access_level": None,
            }
        elif old_level != new_level:
            results[action] = {
                "status": STATUS_RECHECK,
                "reason": "classification-changed",
                "old_catalog_access_level": old_level,
                "new_catalog_access_level": new_level,
            }
        else:
            results[action] = {
                "status": STATUS_OK,
                "reason": "unchanged",
                "old_catalog_access_level": old_level,
                "new_catalog_access_level": new_level,
            }
    return results


def string_only_double(
    records: list[dict[str, Any]],
    new_catalog: dict[str, Any],
) -> dict[str, str]:
    """Test double: only compares the final approved classification string against
    the classification the new catalog serves, ignoring what the approval was
    originally based on."""
    results = {}
    with activated_catalog(new_catalog):
        for record in records:
            new_level = query_access_level(record["action"])
            if new_level is not None and new_level == record["approved_access_level"]:
                results[record["action"]] = STATUS_OK
            else:
                results[record["action"]] = STATUS_RECHECK
    return results


class CatalogUpgradeReviewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.old_catalog = load_catalog(OLD_CATALOG_PATH)
        cls.new_catalog = load_catalog(NEW_CATALOG_PATH)
        cls.records: list[dict[str, Any]] = json.loads(REVIEW_RECORDS_PATH.read_bytes())
        cls.real_results = evaluate_review_records(cls.records, cls.old_catalog, cls.new_catalog)

    def test_control_old_catalog_confirms_all_records(self):
        """Control: re-validating against the old catalog flags nothing, and every
        recorded at-approval classification matches what the old catalog serves."""
        control_results = evaluate_review_records(self.records, self.old_catalog, self.old_catalog)
        for action, result in control_results.items():
            self.assertEqual(result["status"], STATUS_OK, f"{action} unexpectedly flagged on the old catalog")
            self.assertEqual(result["reason"], "unchanged")
        with activated_catalog(self.old_catalog):
            self.assertEqual(iam_data.get_iam_definition_schema_version(), "v2")
            for record in self.records:
                self.assertEqual(
                    query_access_level(record["action"]),
                    record["catalog_access_level_at_approval"],
                    f"{record['action']} record does not match the old catalog",
                )

    def test_upgrade_rechecks_each_record_individually(self):
        """The upgrade flags exactly the records whose approval basis is gone."""
        deploy = self.real_results["acme:DeployWidget"]
        self.assertEqual(deploy["status"], STATUS_RECHECK)
        self.assertEqual(deploy["reason"], "classification-changed")
        self.assertEqual(deploy["old_catalog_access_level"], "Write")
        self.assertEqual(deploy["new_catalog_access_level"], "Permissions management")

        describe = self.real_results["acme:DescribeWidget"]
        self.assertEqual(describe["status"], STATUS_OK)
        self.assertEqual(describe["reason"], "unchanged")

        retire = self.real_results["acme:RetireWidget"]
        self.assertEqual(retire["status"], STATUS_RECHECK)
        self.assertEqual(retire["reason"], "action-missing")
        self.assertIsNone(retire["new_catalog_access_level"])

    def test_upgrade_uses_app_facing_classification(self):
        """The comparison observes the classification the application actually
        serves through its query entry points, not raw fixture values."""
        with activated_catalog(self.new_catalog):
            self.assertIn(
                "acme:DeployWidget",
                get_actions_with_access_level("acme", "Permissions management"),
            )
            self.assertNotIn("acme:DeployWidget", get_actions_with_access_level("acme", "Write"))
            self.assertIn("acme:DescribeWidget", get_actions_with_access_level("acme", "Read"))
            new_description = get_action_data("acme", "DescribeWidget")["acme"][0]["description"]
        with activated_catalog(self.old_catalog):
            old_description = get_action_data("acme", "DescribeWidget")["acme"][0]["description"]
        # The description changed, but that display material is irrelevant to the approval.
        self.assertNotEqual(old_description, new_description)
        self.assertEqual(self.real_results["acme:DescribeWidget"]["status"], STATUS_OK)

    def test_string_only_double_misses_basis_change(self):
        """The string-only double under-reports: it misses the record whose approval
        basis changed, while correctly leaving the unrelated record alone."""
        double_results = string_only_double(self.records, self.new_catalog)

        # Missed by the double: final strings match, but the approval basis changed.
        self.assertEqual(double_results["acme:DeployWidget"], STATUS_OK)
        self.assertEqual(self.real_results["acme:DeployWidget"]["status"], STATUS_RECHECK)

        # Still caught by both: no confirmable action in the new catalog.
        self.assertEqual(double_results["acme:RetireWidget"], STATUS_RECHECK)
        self.assertEqual(self.real_results["acme:RetireWidget"]["status"], STATUS_RECHECK)

        # Neither implementation forces the unrelated record back into review.
        self.assertEqual(double_results["acme:DescribeWidget"], STATUS_OK)
        self.assertEqual(self.real_results["acme:DescribeWidget"]["status"], STATUS_OK)


if __name__ == "__main__":
    unittest.main()
