from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

from auditwheel.provenance import explain_member, verify_provenance

logger = logging.getLogger(__name__)


def configure_parser(sub_parsers: Any) -> None:
    help_ = "Verify a provenance document written by `auditwheel repair --provenance`."
    parser = sub_parsers.add_parser("provenance", help=help_, description=help_)
    parser.add_argument(
        "PROVENANCE_FILE",
        type=Path,
        help="Path to the provenance JSON document.",
    )
    parser.add_argument(
        "--input-wheel",
        dest="INPUT_WHEEL",
        type=Path,
        default=None,
        help="Check the input wheel from this path instead of the recorded relative path.",
    )
    parser.add_argument(
        "--output-wheel",
        dest="OUTPUT_WHEEL",
        type=Path,
        default=None,
        help="Check the output wheel from this path instead of the recorded relative path.",
    )
    parser.add_argument(
        "--json",
        dest="JSON",
        action="store_true",
        default=False,
        help="Output the verification result as JSON.",
    )
    parser.add_argument(
        "--member",
        dest="MEMBER",
        default=None,
        help=(
            "Explain one repaired wheel member: its input members, the "
            "external references that resolved to it and the rewrite steps."
        ),
    )
    parser.set_defaults(func=execute)


def execute(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    document_path: Path = args.PROVENANCE_FILE
    if not document_path.is_file():
        parser.error(f"cannot access {document_path}. No such file")

    problems = verify_provenance(
        document_path,
        input_wheel=args.INPUT_WHEEL,
        output_wheel=args.OUTPUT_WHEEL,
    )
    document = json.loads(document_path.read_text(encoding="utf-8"))
    if args.MEMBER is not None:
        explanation = explain_member(document, args.MEMBER)
        print(json.dumps(explanation, indent=None if args.JSON else 2))
        return 0 if explanation["found"] else 1
    result = {
        "document": document_path.name,
        "ok": not problems,
        "input_wheel_sha256": document.get("input_wheel", {}).get("sha256"),
        "output_wheel_sha256": document.get("output_wheel", {}).get("sha256"),
        "references": len(document.get("references", [])),
        "grafts": len(document.get("grafts", [])),
        "problems": problems,
    }
    if args.JSON:
        print(json.dumps(result))
    elif problems:
        print(f"{document_path}: FAILED")
        for problem in problems:
            print(f"  - {problem}")
    else:
        print(
            f"{document_path}: OK "
            f"({result['references']} references, {result['grafts']} grafts)",
        )
    return 0 if not problems else 1
