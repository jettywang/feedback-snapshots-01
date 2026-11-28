"""Command line entry point for the pre-deployment endpoint audit.

Usage::

    python -m endpoint_audit.cli MANIFEST [--json] [--extension MOD ...]

Exit codes:
    0 - no confirmed overlap (uncertain pairs may remain)
    1 - malformed manifest or unparseable endpoint declaration
    2 - at least one confirmed listening-range overlap
"""

from __future__ import annotations

import argparse
import json
import sys

from .audit import audit_declarations
from .extensions import DiscloserRegistry
from .manifest import load_manifest
from .report import render_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="endpoint_audit",
        description=(
            "Statically compute the network addresses covered by Twisted "
            "endpoint descriptions and flag overlapping listening ranges "
            "without binding ports or reading TLS private keys."
        ),
    )
    parser.add_argument("manifest", help="path to a text or .json service manifest")
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of a text report",
    )
    parser.add_argument(
        "--extension",
        action="append",
        default=[],
        metavar="MODULE",
        help=(
            "importable module exposing 'prefix' and "
            "'disclose(args, kwargs)' for a runtime-only scheme; repeatable"
        ),
    )
    parser.add_argument(
        "--only-conflicts",
        action="store_true",
        help="omit the confirmed-separate section from the text report",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        declarations = load_manifest(args.manifest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"manifest error: {exc}", file=sys.stderr)
        return 1

    registry = DiscloserRegistry()
    for module_name in args.extension:
        try:
            registry.load_module(module_name)
        except (ImportError, ValueError) as exc:
            print(f"extension error: {exc}", file=sys.stderr)
            return 1

    result = audit_declarations(declarations, registry)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(render_text(result, include_separate=not args.only_conflicts))

    if result.parse_issues:
        return 1
    if result.has_confirmed_overlap:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
