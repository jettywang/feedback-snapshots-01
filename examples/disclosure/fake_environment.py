"""
Create a throwaway set of installed distributions for the disclosure examples.

`pip list --path` recognizes these directories, so `pip-audit --path` sees them
as an audited environment without installing anything.
"""

from __future__ import annotations

from pathlib import Path

DISTRIBUTIONS = (
    ("public_lib-1.0.0.dist-info", "public-lib", "1.0.0"),
    ("internal_payments_lib-1.2.3.dist-info", "internal-payments-lib", "1.2.3"),
    # An invalid version forces the skip path, whose reason contains a path.
    ("internal_broken_lib-.dist-info", "internal-broken-lib", "NOT-A-VERSION"),
)


def create(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for directory, name, version in DISTRIBUTIONS:
        dist_info = root / directory
        dist_info.mkdir(exist_ok=True)
        (dist_info / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
            encoding="utf-8",
        )
        (dist_info / "RECORD").write_text("", encoding="utf-8")
    return root
