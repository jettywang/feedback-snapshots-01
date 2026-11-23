#!/usr/bin/env python3
"""Monitoring view over an approval report.

Finds the three tracked categories:
- parse_not_analyzed: 解析没到分析（parse_failed）
- confirmed_clean:    分析已确认无发现（checked 且 finding == none）
- duplicate_results:  收到重复结果（存在 reason == duplicate 的被取代证据）
"""

import argparse
import json
import sys


def find_categories(report):
    resources = report.get("resources", [])
    return {
        "parse_not_analyzed": sorted(
            r["resource_id"] for r in resources if r.get("status") == "parse_failed"
        ),
        "confirmed_clean": sorted(
            r["resource_id"]
            for r in resources
            if r.get("status") == "checked" and r.get("finding") == "none"
        ),
        "duplicate_results": sorted(
            r["resource_id"]
            for r in resources
            if any(s.get("reason") == "duplicate" for s in r.get("superseded", []))
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", help="aggregated report JSON")
    parser.add_argument("-o", "--output", help="write result here (default: stdout)")
    args = parser.parse_args(argv)

    with open(args.report, encoding="utf-8") as handle:
        report = json.load(handle)
    text = json.dumps(find_categories(report), indent=2, ensure_ascii=False) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
