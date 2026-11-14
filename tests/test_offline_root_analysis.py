# Copyright 2026, the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Structural tests for the offline root authorization analysis example."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import TYPE_CHECKING

from tuf.api.metadata import Metadata, Role, Root

if TYPE_CHECKING:
    from types import ModuleType

    from securesystemslib.signer import SSlibKey

EXAMPLE_DIR = (
    Path(__file__).resolve().parents[1] / "examples" / ("offline_root_analysis")
)


def _load_module(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        name, EXAMPLE_DIR / f"{name}.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ra = _load_module("root_analysis")
gen = _load_module("generate_configs")


def _write_fixtures(out: Path) -> None:
    for name, (roots, _meta) in gen.build_scenarios().items():
        scenario_dir = out / name
        scenario_dir.mkdir()
        for root in roots:
            version = root["signed"]["version"]
            (scenario_dir / f"root_v{version}.json").write_text(
                json.dumps(root), encoding="utf-8"
            )


class FixtureAnalysisTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.fixture_root = Path(self._tmp.name)
        _write_fixtures(self.fixture_root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _report(self, scenario: str) -> ra.AnalysisReport:
        base = self.fixture_root / scenario
        return ra.analyze(base / "root_v1.json", [base / "root_v2.json"])

    def test_alias_merge_uses_material_not_keyid(self) -> None:
        view = ra.load_root_view(self.fixture_root / "shared" / "root_v1.json")
        # Seven keyid entries but only six distinct physical keys.
        self.assertEqual(len(view.root.keys), 7)
        self.assertEqual(len(view.materials), 6)

        targets = set(view.role_materials["targets"])
        snapshot = set(view.role_materials["snapshot"])
        self.assertTrue(targets & snapshot)

    def test_shared_key_shrinks_delivery_coalition(self) -> None:
        shared = self._report("shared")
        separated = self._report("separated")
        self.assertEqual(shared.arbitrary_delivery.size, 4)
        self.assertEqual(separated.arbitrary_delivery.size, 5)

        latest = ra.load_root_view(
            self.fixture_root / "shared" / "root_v2.json"
        )
        for coalition in shared.arbitrary_delivery.coalitions:
            for role in ra.DELIVERY_ROLES:
                self.assertTrue(latest.role_satisfiable(role, coalition))

    def test_freeze_is_strictly_weaker_than_delivery(self) -> None:
        for scenario in ("shared", "separated"):
            report = self._report(scenario)
            self.assertLessEqual(
                report.freeze_authority.size,
                report.arbitrary_delivery.size,
            )
            latest = ra.load_root_view(
                self.fixture_root / scenario / "root_v2.json"
            )
            freeze = report.freeze_authority.coalitions[0]
            self.assertFalse(latest.role_satisfiable("targets", freeze))

    def test_dual_threshold_root_migration(self) -> None:
        for scenario in ("shared", "separated"):
            report = self._report(scenario)
            # Disjoint v1 (2 of 2) and v2 (2 of 2) root keys => 4 materials.
            self.assertEqual(report.migration.size, 4)

    def test_per_role_authority_matches_thresholds(self) -> None:
        report = self._report("shared")
        by_role = {cr.roles[0]: cr.size for cr in report.per_role_authority}
        self.assertEqual(by_role["root"], 2)
        self.assertEqual(by_role["targets"], 2)
        self.assertEqual(by_role["snapshot"], 2)
        self.assertEqual(by_role["timestamp"], 1)


class StructuralEdgeCaseTest(unittest.TestCase):
    def _view(self, root: Root) -> ra.RootView:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "root.json"
            Metadata(root).to_file(str(path))
            return ra.load_root_view(path)

    def _base_roles(self, root_role: Role) -> dict[str, Role]:
        return {
            "root": root_role,
            "targets": Role(["other"], 1),
            "snapshot": Role(["other"], 1),
            "timestamp": Role(["other"], 1),
        }

    def test_dangling_keyid_is_flagged_and_ignored(self) -> None:
        good = gen.make_public_key("EDGE1")
        other = gen.make_public_key("EDGE1-OTHER")
        root = Root(
            version=1,
            keys={good.keyid: good, other.keyid: other},
            roles=self._base_roles(Role([good.keyid, "missing"], 1)),
        )
        view = self._view(root)
        fingerprint = ra._fingerprint(good.keytype, good.scheme, good.keyval)
        self.assertEqual(view.role_materials["root"], [fingerprint])
        codes = {f.code for f in ra._structural_findings([view])}
        self.assertIn("dangling-keyid", codes)

    def test_unsatisfiable_threshold_is_critical(self) -> None:
        key = gen.make_public_key("EDGE2")
        other = gen.make_public_key("EDGE2-OTHER")
        root = Root(
            version=1,
            keys={key.keyid: key, other.keyid: other},
            roles=self._base_roles(Role([key.keyid], 2)),
        )
        view = self._view(root)
        codes = {f.code for f in ra._structural_findings([view])}
        self.assertIn("unsatisfiable-threshold", codes)

    def test_duplicate_material_in_one_role_counts_once(self) -> None:
        key = gen.make_public_key("EDGE3")
        alias = gen.aliased_key(key, "edge3-alias")
        other = gen.make_public_key("EDGE3-OTHER")
        root = Root(
            version=1,
            keys={key.keyid: key, alias.keyid: alias, other.keyid: other},
            roles={
                "root": Role([other.keyid], 1),
                "targets": Role([key.keyid, alias.keyid], 2),
                "snapshot": Role([other.keyid], 1),
                "timestamp": Role([other.keyid], 1),
            },
        )
        view = self._view(root)
        self.assertEqual(len(view.role_materials["targets"]), 1)
        codes = {f.code for f in ra._structural_findings([view])}
        self.assertIn("unsatisfiable-threshold", codes)

    def test_shared_old_new_root_key_reduces_migration(self) -> None:
        key_a = gen.make_public_key("MIG-A")
        key_b = gen.make_public_key("MIG-B")
        other = gen.make_public_key("MIG-OTHER")

        def make_root(version: int, root_keys: list[SSlibKey]) -> Root:
            keys = {key.keyid: key for key in [*root_keys, other]}
            return Root(
                version=version,
                keys=keys,
                roles=self._base_roles(
                    Role([key.keyid for key in root_keys], 2)
                ),
            )

        with tempfile.TemporaryDirectory() as tmp:
            p1 = Path(tmp) / "v1.json"
            p2 = Path(tmp) / "v2.json"
            Metadata(make_root(1, [key_a, key_b])).to_file(str(p1))
            Metadata(make_root(2, [key_a, key_b])).to_file(str(p2))
            report = ra.analyze(p1, [p2])
            self.assertEqual(report.migration.size, 2)


class CliTest(unittest.TestCase):
    def test_json_output_is_valid(self) -> None:
        base = EXAMPLE_DIR / "configs" / "shared"
        if not (base / "root_v1.json").exists():
            self.skipTest("fixtures not generated")
        proc = subprocess.run(
            [
                sys.executable,
                str(EXAMPLE_DIR / "root_analysis.py"),
                "--trusted",
                str(base / "root_v1.json"),
                "--candidate",
                str(base / "root_v2.json"),
                "--json",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(proc.stdout)
        self.assertEqual(
            payload["arbitrary_target_delivery"]["minimum_size"], 4
        )


if __name__ == "__main__":
    unittest.main()
