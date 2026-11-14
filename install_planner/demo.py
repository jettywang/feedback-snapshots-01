# Copyright 2026, python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Runnable demonstration of the dependency admission planner.

Run from the repository root with::

    python -m install_planner.demo

The script never downloads target files and never installs anything: it only
reads signed metadata through a single bootstrapped TUF client snapshot.
"""

from __future__ import annotations

import json
import tempfile
from typing import TYPE_CHECKING

from install_planner.demo_repo import (
    APP_PATH,
    PLUGIN_PATH,
    break_role_signature,
    build_demo_repository,
    tamper_required_digest,
)
from install_planner.planner import DependencyPlanner, create_planner

if TYPE_CHECKING:
    from tests.repository_simulator import RepositorySimulator

METADATA_URL = "https://example.com/metadata/"
TARGETS_URL = "https://example.com/targets/"


def _make_planner(sim: RepositorySimulator) -> DependencyPlanner:
    cache_dir = tempfile.mkdtemp()
    return create_planner(
        cache_dir,
        METADATA_URL,
        TARGETS_URL,
        bootstrap=sim.signed_roots[0],
        fetcher=sim,
    )


def main() -> None:
    print("=" * 72)
    print("SCENARIO 1: full closure admitted against one client snapshot")
    print("=" * 72)
    sim = build_demo_repository()
    planner = _make_planner(sim)
    plan = planner.plan(APP_PATH)

    rendered = plan.to_dict()
    print(json.dumps(rendered, indent=2, sort_keys=False))
    print()
    print("Stable install order (dependencies before dependents):")
    for index, path in enumerate(plan.install_order, start=1):
        package = plan.packages[path]
        if package.authorization is None:
            print(f"  {index}. {path}  [optional, not published: skipped]")
            continue
        print(
            f"  {index}. {path}  <- signed by role "
            f"{package.authorization.role!r} (delegated by "
            f"{package.authorization.parent_role!r}), "
            f"targets metadata v{package.authorization.targetfile_version}"
        )
    assert not sim.fetch_tracker.targets, "planner must not fetch target files"
    print("\nTarget-file downloads performed: 0 (metadata-only planning)")
    print(f"Snapshot shared by all lookups: v{plan.snapshot_version}")

    print()
    print("=" * 72)
    print("SCENARIO 2: last-node digest failure rejects the whole plan")
    print("=" * 72)
    sim = build_demo_repository()
    bogus = tamper_required_digest(sim, PLUGIN_PATH)
    print(f"The root package's declaration now pins sha256 {bogus}")
    print(f"for {PLUGIN_PATH}, but the app-team role attests the real,")
    print("signed digest. Every other node of the closure is still valid.")
    planner = _make_planner(sim)
    try:
        planner.plan(APP_PATH)
    except Exception as error:  # noqa: BLE001 - demo prints every failure type
        print(f"\nPlan rejected with {type(error).__name__}: {error}")
    else:
        raise AssertionError("digest mismatch must fail the plan")

    print()
    print("=" * 72)
    print("SCENARIO 3: signature damage is not treated as 'not published'")
    print("=" * 72)
    sim = build_demo_repository()
    break_role_signature(sim, "basic-libs")
    planner = _make_planner(sim)
    try:
        planner.plan(APP_PATH)
    except Exception as error:  # noqa: BLE001
        print(f"\nPlan rejected with {type(error).__name__}: {error}")
    else:
        raise AssertionError("unsigned delegated role must fail the plan")

    print()
    print("No InstallationPlan was produced for either failing scenario:")
    print("the caller never receives a half-resolved, seemingly complete plan.")


if __name__ == "__main__":
    main()
