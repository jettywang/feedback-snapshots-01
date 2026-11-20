"""
Run the disclosure example against the real `pip-audit` CLI path.

Usage:
    python examples/disclosure/run.py success OUTPUT_DIR
    python examples/disclosure/run.py failure OUTPUT_DIR

The only substitution is the OSV HTTP session, which is replaced with a
deterministic fixture so the example needs no network and no live advisory
database.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Keep pip's own cache out of the evidence run.
os.environ.setdefault("PIP_NO_CACHE_DIR", "1")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import fake_environment  # noqa: E402
import osv_fixture  # noqa: E402

import pip_audit._service.osv as osv  # noqa: E402


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"success", "failure"}:
        print(__doc__, file=sys.stderr)
        return 2

    mode, output = sys.argv[1], Path(sys.argv[2]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    dists = fake_environment.create(output / "site-packages")

    allowlist = output / "public-allowlist.txt"
    allowlist.write_text(
        "# Dependency names approved for the public audit summary.\n"
        "# Everything not listed here is internal-only.\n"
        "public-lib\n",
        encoding="utf-8",
    )

    fail_after = 2 if mode == "failure" else None
    session = osv_fixture.FakeSession(fail_after=fail_after)
    osv.caching_session = lambda *args, **kwargs: session

    sys.argv = [
        "pip-audit",
        "--path",
        str(dists),
        "--vulnerability-service",
        "osv",
        "--format",
        "json",
        "--progress-spinner",
        "off",
        "--timeout",
        "1",
        "--public-report",
        str(output / "public.json"),
        "--public-allowlist",
        str(allowlist),
        "--internal-report",
        str(output / "internal.json"),
    ]

    from pip_audit._cli import audit

    audit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
