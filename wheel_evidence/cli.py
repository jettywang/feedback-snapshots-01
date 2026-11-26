"""Command line interface for the offline wheel evidence inventory."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import render
from .core import InventoryError, analyze_wheel, lookup_command


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wheel-evidence",
        description=(
            "Offline evidence inventory for a single wheel: entry-point "
            "sections, normalized command names, archived script paths and "
            "RECORD digest verification."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_inv = sub.add_parser("inventory", help="full evidence inventory (default view)")
    p_inv.add_argument("wheel")
    p_inv.add_argument("--json", action="store_true", dest="as_json")

    p_ep = sub.add_parser("entry-points", help="list entry-point sections")
    p_ep.add_argument("wheel")
    p_ep.add_argument("--section", default=None, help="only show this section (e.g. console_scripts)")
    p_ep.add_argument("--json", action="store_true", dest="as_json")

    p_sc = sub.add_parser("scripts", help="list archived script paths")
    p_sc.add_argument("wheel")
    p_sc.add_argument("--json", action="store_true", dest="as_json")

    p_ver = sub.add_parser("verify", help="verify every member against RECORD")
    p_ver.add_argument("wheel")
    p_ver.add_argument("--json", action="store_true", dest="as_json")

    p_cmd = sub.add_parser("command", help="correlate one command name across all evidence kinds")
    p_cmd.add_argument("wheel")
    p_cmd.add_argument("name")
    p_cmd.add_argument("--json", action="store_true", dest="as_json")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        report = analyze_wheel(args.wheel)
    except InventoryError as exc:
        if getattr(args, "as_json", False):
            import json

            print(json.dumps({"error": exc.code, "message": exc.message}, ensure_ascii=False))
        else:
            print(f"错误 [{exc.code}]: {exc.message}", file=sys.stderr)
        return 2

    if args.cmd == "inventory":
        if args.as_json:
            print(render.dumps_json(report))
        else:
            print(render.render_inventory(report))
    elif args.cmd == "entry-points":
        if args.as_json:
            sections = report["entry_point_sections"]
            if args.section:
                sections = [s for s in sections if s["section"] == args.section]
            print(render.dumps_json({"wheel": report["wheel"]["filename"], "entry_point_sections": sections}))
        else:
            print(render.render_entry_points(report, args.section))
    elif args.cmd == "scripts":
        if args.as_json:
            print(render.dumps_json({"wheel": report["wheel"]["filename"], "scripts": report["scripts"]}))
        else:
            print(render.render_scripts(report))
    elif args.cmd == "verify":
        if args.as_json:
            print(
                render.dumps_json(
                    {
                        "wheel": report["wheel"],
                        "trust": report["trust"],
                        "record": report["record"],
                        "record_audit": report["record_audit"],
                    }
                )
            )
        else:
            print(render.render_verify(report))
    elif args.cmd == "command":
        result = lookup_command(report, args.name)
        if args.as_json:
            result = {"wheel": report["wheel"], **result}
            print(render.dumps_json(result))
        else:
            print(render.render_command(report, result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
