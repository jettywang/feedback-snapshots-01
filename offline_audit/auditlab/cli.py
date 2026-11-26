from __future__ import annotations

import argparse
import os

from .engine import run
from .report import diff_reports, render_text, to_json


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Offline effective-permission audit with per-item explanations.")
    parser.add_argument("manifest", help="path to a scenario manifest.json")
    parser.add_argument("targets", help="path to targets.json")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--diff-with", help="another manifest to compare after补件")
    args = parser.parse_args()

    report = run(args.manifest, args.targets)
    print(to_json(report) if args.json else render_text(report))

    if args.diff_with:
        other = run(args.diff_with, args.targets)
        print(os.linesep + diff_reports(report, other))


if __name__ == "__main__":
    main()
