# Copyright 2026, python-tuf contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""A tiny in-memory TUF repository for the admission planner demos and tests.

The repository deliberately combines the two graph features the planner has
to reason about:

* a **shared dependency** (``lib/core`` is required by both ``app`` and the
  shared ``lib/util``), and
* a **terminating delegation** (``basic-libs`` terminates lookups for
  ``packages/lib/*`` so that no later role can answer those paths).

Only metadata is ever served to the planner; target content exists in the
simulator solely so that digests and lengths are well defined.
"""

from __future__ import annotations

from typing import Any

from tests.repository_simulator import RepositorySimulator, RepositoryTarget
from tuf.api.metadata import DelegatedRole, TargetFile, Targets

APP_PATH = "packages/app/app-1.0.tar"
CORE_PATH = "packages/lib/core-2.1.tar"
UTIL_PATH = "packages/lib/util-1.4.tar"
PLUGIN_PATH = "packages/plugin/plugin-0.9.tar"
OPTIONAL_PATH = "packages/optional/extras-0.3.tar"


def _dependency(
    path: str, digest: str, optional: bool = False
) -> dict[str, Any]:
    return {"path": path, "sha256": digest, "optional": optional}


def build_demo_repository() -> RepositorySimulator:
    """Build the healthy demo repository with one consistent snapshot."""
    sim = RepositorySimulator()
    sim.root.consistent_snapshot = True

    # Delegation graph:
    #   targets
    #   |- basic-libs  (terminating, packages/lib/*)
    #   `- app-team    (non-terminating, packages/app/* and packages/plugin/*)
    sim.add_delegation(
        "targets",
        DelegatedRole(
            "basic-libs", [], 1, terminating=True, paths=["packages/lib/*"]
        ),
        Targets(expires=sim.safe_expiry),
    )
    sim.add_delegation(
        "targets",
        DelegatedRole(
            "app-team",
            [],
            1,
            terminating=False,
            paths=["packages/app/*", "packages/plugin/*"],
        ),
        Targets(expires=sim.safe_expiry),
    )
    sim.add_delegation(
        "targets",
        DelegatedRole(
            "extras-team",
            [],
            1,
            terminating=False,
            paths=["packages/optional/*"],
        ),
        Targets(expires=sim.safe_expiry),
    )

    contents = {
        APP_PATH: b"application payload",
        CORE_PATH: b"core library payload",
        UTIL_PATH: b"util library payload",
        PLUGIN_PATH: b"plugin payload",
        OPTIONAL_PATH: b"optional extras payload",
    }
    for path, data in contents.items():
        # Register content first so digests can be embedded in custom sections.
        sim.target_files[path] = _repository_target(path, data)

    digests = {
        path: sim.target_files[path].target_file.hashes["sha256"]
        for path in contents
    }

    # Root package, signed by the top-level "targets" role.
    _publish_with_dependencies(
        sim,
        "targets",
        APP_PATH,
        contents[APP_PATH],
        [
            _dependency(CORE_PATH, digests[CORE_PATH]),
            _dependency(PLUGIN_PATH, digests[PLUGIN_PATH]),
            _dependency(OPTIONAL_PATH, digests[OPTIONAL_PATH], optional=True),
        ],
    )

    # Shared library subtree, all answered by the terminating basic-libs role.
    _publish_with_dependencies(
        sim,
        "basic-libs",
        CORE_PATH,
        contents[CORE_PATH],
        [],
    )
    _publish_with_dependencies(
        sim,
        "basic-libs",
        UTIL_PATH,
        contents[UTIL_PATH],
        [_dependency(CORE_PATH, digests[CORE_PATH])],
    )

    # app-team owns application-space packages; plugin shares lib/core too.
    _publish_with_dependencies(
        sim,
        "app-team",
        PLUGIN_PATH,
        contents[PLUGIN_PATH],
        [
            _dependency(UTIL_PATH, digests[UTIL_PATH]),
            _dependency(CORE_PATH, digests[CORE_PATH]),
        ],
    )

    # Optional package exists and is healthy; tests may remove it to exercise
    # optional skipping. It is published by the extras-team role.
    _publish_with_dependencies(
        sim,
        "extras-team",
        OPTIONAL_PATH,
        contents[OPTIONAL_PATH],
        [],
    )

    sim.targets.version += 1
    sim.md_delegates["basic-libs"].signed.version += 1
    sim.md_delegates["app-team"].signed.version += 1
    sim.md_delegates["extras-team"].signed.version += 1
    sim.update_snapshot()
    return sim


def remove_optional_target(sim: RepositorySimulator) -> None:
    """Make the optional dependency unpublished without breaking signatures."""
    sim.md_delegates["extras-team"].signed.targets.pop(OPTIONAL_PATH, None)
    sim.md_delegates["extras-team"].signed.version += 1
    sim.update_snapshot()


def tamper_required_digest(sim: RepositorySimulator, path: str) -> str:
    """Pin a wrong sha256 for ``path`` inside its dependent's declaration.

    Returns the bogus digest. The repository metadata itself stays correctly
    signed, so the failure is purely a declaration-vs-metadata mismatch.
    """
    bogus = "0" * 64
    for targets in _all_targets_payloads(sim):
        for target in targets.targets.values():
            custom = target.custom
            if not isinstance(custom, dict):
                continue
            for entry in custom.get("dependencies", []):
                if entry.get("path") == path:
                    entry["sha256"] = bogus
    for targets in _all_targets_payloads(sim):
        targets.version += 1
    sim.update_snapshot()
    return bogus


def break_role_signature(sim: RepositorySimulator, role: str) -> None:
    """Remove the signing key of delegated ``role`` and republish metadata.

    The role still claims the target, so the client sees an unsigned
    delegation rather than a missing target: signature damage must not be
    confusable with "not published".
    """
    sim.signers[role].clear()
    sim.md_delegates[role].signed.version += 1
    sim.update_snapshot()


def add_cycle(sim: RepositorySimulator) -> None:
    """Make lib/core and lib/util require each other."""
    core_target = sim.md_delegates["basic-libs"].signed.targets[CORE_PATH]
    util_digest = sim.target_files[UTIL_PATH].target_file.hashes["sha256"]
    core_target.unrecognized_fields["custom"] = {
        "dependencies": [_dependency(UTIL_PATH, util_digest)]
    }
    sim.md_delegates["basic-libs"].signed.version += 1
    sim.update_snapshot()


def add_conflicting_pins(sim: RepositorySimulator) -> None:
    """Pin lib/core to a second, different digest from the app-team branch."""
    plugin_target = sim.md_delegates["app-team"].signed.targets[PLUGIN_PATH]
    custom = plugin_target.unrecognized_fields["custom"]
    for entry in custom["dependencies"]:
        if entry["path"] == CORE_PATH:
            entry["sha256"] = "f" * 64
    sim.md_delegates["app-team"].signed.version += 1
    sim.update_snapshot()


def remove_required_target(sim: RepositorySimulator, path: str) -> None:
    """Unpublish a required target while keeping every signature valid."""
    for targets in _all_targets_payloads(sim):
        if path in targets.targets:
            targets.targets.pop(path)
            targets.version += 1
    sim.target_files.pop(path, None)
    sim.update_snapshot()


def _all_targets_payloads(sim: RepositorySimulator) -> list[Targets]:
    payloads = [sim.targets]
    payloads.extend(md.signed for md in sim.md_delegates.values())
    return payloads


def _role_targets(sim: RepositorySimulator, role: str) -> Targets:
    if role == "targets":
        return sim.targets
    return sim.md_delegates[role].signed


def _repository_target(path: str, data: bytes) -> RepositoryTarget:
    return RepositoryTarget(
        data, TargetFile.from_data(path, data, ["sha256"])
    )


def _publish_with_dependencies(
    sim: RepositorySimulator,
    role: str,
    path: str,
    data: bytes,
    dependencies: list[dict[str, Any]],
) -> None:
    targetfile = TargetFile(
        length=len(data),
        hashes=sim.target_files[path].target_file.hashes,
        path=path,
        unrecognized_fields={"custom": {"dependencies": dependencies}},
    )
    _role_targets(sim, role).targets[path] = targetfile
    sim.target_files[path].target_file = targetfile
