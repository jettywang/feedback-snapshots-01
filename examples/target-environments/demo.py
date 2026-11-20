"""
Demonstrate per-target lockfile auditing with a fake announcement feed.

Run from the repository root:

    python examples/target-environments/demo.py

The "announcement feed" below is an in-memory `VulnerabilityService`, so the demo
never touches the network.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from packaging.version import Version

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from pip_audit._dependency_source.pylock import PyLockSource  # noqa: E402
from pip_audit._service import (  # noqa: E402
    Dependency,
    VulnerabilityResult,
    VulnerabilityService,
)
from pip_audit._target import TargetEnvironment  # noqa: E402
from pip_audit._target_audit import audit_targets  # noqa: E402

HERE = Path(__file__).resolve().parent


class FakeAdvisoryFeed(VulnerabilityService):
    """A stand-in for an advisory source, with one advisory for jinja2 3.1.4."""

    def __init__(self) -> None:
        self.queries: list[tuple[str, str]] = []

    def query(self, spec: Dependency):
        if spec.is_skipped():
            return spec, []
        self.queries.append((spec.canonical_name, str(spec.version)))
        if (spec.canonical_name, str(spec.version)) == ("jinja2", "3.1.4"):
            return spec, [
                VulnerabilityResult(
                    id="CVE-2024-9999",
                    description="demo: jinja2 sandbox escape",
                    fix_versions=[Version("3.1.5")],
                    aliases=set(),
                )
            ]
        return spec, []


def _print_evidence(item) -> None:
    payload = item.to_dict()
    print(f"  {payload['target']['name']}: fingerprint {payload['fingerprint'][:16]}")
    print(f"    selected:     {[dep['name'] for dep in payload['dependencies']]}")
    print(f"    excluded:     {[c['name'] for c in payload['excluded']]}")
    print(f"    undetermined: {[c['name'] for c in payload['undetermined']]}")
    print(f"    error:        {payload['error']}")
    print(f"    gate passed:  {payload['gate_passed']}")


def main() -> int:
    specs = json.loads((HERE / "targets.json").read_text())
    targets = [TargetEnvironment(item["name"], item["environment"]) for item in specs]
    source = PyLockSource([HERE / "pylock.toml"])

    evidence = audit_targets(source, FakeAdvisoryFeed(), targets)

    print("Forward order:")
    for item in evidence:
        _print_evidence(item)

    reversed_evidence = audit_targets(source, FakeAdvisoryFeed(), list(reversed(targets)))
    forward_by_name = {item.target.name: item.to_dict() for item in evidence}
    reverse_by_name = {item.target.name: item.to_dict() for item in reversed_evidence}
    print("\nSwapping target order produced identical evidence:",
          forward_by_name == reverse_by_name)

    out = HERE / "evidence"
    out.mkdir(exist_ok=True)

    # A third target that no lockfile environment covers: it must still produce
    # an explicit, standalone result instead of being silently skipped.
    uncovered = TargetEnvironment(
        "windows",
        {"sys_platform": "win32", "platform_system": "Windows", "python_version": "3.12"},
    )
    print("\nForward order, plus an uncovered target:")
    for item in audit_targets(source, FakeAdvisoryFeed(), [*targets, uncovered]):
        _print_evidence(item)

    for item in evidence:
        (out / f"{item.target.name}.json").write_text(
            json.dumps(item.to_dict(), indent=2, sort_keys=True)
        )
    print(f"\nWrote per-target evidence to {out}")

    return 0 if all(item.is_gate_passed() for item in evidence) else 1


if __name__ == "__main__":
    sys.exit(main())
