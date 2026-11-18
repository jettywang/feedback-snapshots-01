"""Entry point: build fixtures, verify them, and print a comparison table.

Usage:
    python -m strongname_lab [--out DIR] [--fixtures DIR]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import fixtures, report, verify


def _fmt(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def _table(report_data: dict) -> str:
    rows = [
        ("case", "sn", "token", "flag", "pk flag", "sn rsa", "auth digest", "auth signer", "chain", "verdict"),
    ]
    for name, case in report_data["cases"].items():
        sn = case.get("strong_name", {})
        au = case.get("authenticode", {})
        if "error" in sn:
            rows.append((name, "parse error", "-", "-", "-", "-", "-", "-", "-", sn["error"]))
            continue
        verdict = au.get("verdict", {})
        if not au.get("certificate_entries"):
            shown_verdict = "no Authenticode signature"
        elif verdict.get("published_by_trusted_publisher") is not None:
            shown_verdict = (
                f"signature={verdict.get('signature')}; trust={verdict.get('trust')}; "
                f"trusted-publisher={_fmt(verdict.get('published_by_trusted_publisher'))}"
            )
            if au.get("unauthenticated_trailing_bytes"):
                shown_verdict += f"; unauthenticated-trailing={au['unauthenticated_trailing_bytes']}B"
        else:
            shown_verdict = f"{verdict.get('signature', 'n/a')} / {verdict.get('trust', 'n/a')}"
        rows.append((
            name,
            "valid" if sn["checks"].get("rsa_signature_valid") else "invalid",
            sn["identity"]["public_key_token"] or "-",
            _fmt(sn["cli"]["strong_name_signed_flag"]),
            _fmt(sn["checks"].get("public_key_flag_matches_blob")),
            _fmt(sn["checks"].get("rsa_signature_valid")),
            _fmt(au.get("digest_matches")),
            _fmt(au.get("signer_signature_valid")),
            _fmt((au.get("certificate_chain") or {}).get("trusted")),
            shown_verdict,
        ))
    widths = [max(len(str(row[index])) for row in rows) for index in range(len(rows[0]))]
    lines = []
    for index, row in enumerate(rows):
        lines.append("  ".join(str(value).ljust(widths[col]) for col, value in enumerate(row)).rstrip())
        if index == 0:
            lines.append("  ".join("-" * width for width in widths))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline strong-name / Authenticode verification lab")
    parser.add_argument("--out", default="strongname_lab/out", help="report output directory")
    parser.add_argument("--fixtures", default="strongname_lab/fixtures/generated", help="fixture directory")
    parser.add_argument("--no-build", action="store_true", help="reuse existing fixtures instead of rebuilding")
    parser.add_argument("--json", action="store_true", help="print the full JSON report")
    args = parser.parse_args(argv)

    fixtures_dir = Path(args.fixtures)
    if not args.no_build:
        fixtures.build_all(fixtures_dir)
    data = report.build(fixtures_dir, Path(args.out))
    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    else:
        print(_table(data))
        print()
        print(f"report: {Path(args.out) / 'report.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
