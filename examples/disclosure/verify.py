"""
Verify the disclosure evidence produced by `run.py`.

Usage:
    python examples/disclosure/verify.py success OUTPUT_DIR
    python examples/disclosure/verify.py failure OUTPUT_DIR

Exits non-zero on the first violated rule, so it can be used directly in CI.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import osv_fixture  # noqa: E402

FORBIDDEN_PUBLIC_KEYS = {"description", "skip_reason", "error", "traceback"}
FORBIDDEN_PUBLIC_TEXT = (
    "PRIVATE-ADVISORY-MARKER",
    "ADVISORY-DESCRIPTION-MARKER",
    "internal-payments-lib",
    "internal-broken-lib",
    "/srv/private",
)


def _fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def _check_public_keys(value, path="public.json"):
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_PUBLIC_KEYS:
                _fail(f"{path} contains forbidden key {key!r}")
            _check_public_keys(child, path)
    elif isinstance(value, list):
        for child in value:
            _check_public_keys(child, path)


def verify_success(output: Path) -> None:
    public = json.loads((output / "public.json").read_text())
    internal = json.loads((output / "internal.json").read_text())
    text = json.dumps(public)

    _check_public_keys(public)
    for marker in FORBIDDEN_PUBLIC_TEXT:
        if marker in text:
            _fail(f"public.json contains {marker!r}")

    assert [dep["name"] for dep in public["public_dependencies"]] == ["public-lib"]
    vuln = public["public_dependencies"][0]["vulnerabilities"][0]
    assert set(vuln) == {"id", "aliases", "fix_versions"}, vuln

    names = [dep["name"] for dep in internal["dependencies"]]
    assert names == ["internal-broken-lib", "internal-payments-lib", "public-lib"], names
    by_name = {dep["name"]: dep for dep in internal["dependencies"]}
    assert "skip_reason" in by_name["internal-broken-lib"]
    assert (
        by_name["internal-payments-lib"]["vulnerabilities"][0]["description"]
        == osv_fixture.PRIVATE_ADVISORY_TEXT
    )
    assert (
        by_name["public-lib"]["vulnerabilities"][0]["description"]
        == osv_fixture.PUBLIC_ADVISORY_TEXT
    )
    assert internal["audit"]["status"] == "complete"
    print(f"OK: {output}")


def verify_failure(output: Path) -> None:
    if (output / "public.json").exists():
        _fail("public.json must not exist after a failed audit")
    internal = json.loads((output / "internal.json").read_text())
    assert internal["audit"]["status"] == "failed"
    assert internal["audit"]["exit_code"] == 1
    assert internal["error"]["type"] == "ConnectionError"
    assert "simulated timeout" in internal["error"]["traceback"]
    assert any(dep.get("skip_reason") for dep in internal["dependencies"])
    print(f"OK: {output}")


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in {"success", "failure"}:
        print(__doc__, file=sys.stderr)
        raise SystemExit(2)
    mode, output = sys.argv[1], Path(sys.argv[2])
    if mode == "success":
        verify_success(output)
    else:
        verify_failure(output)


if __name__ == "__main__":
    main()
