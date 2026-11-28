from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import argparse

logger = logging.getLogger(__name__)


def configure_parser(sub_parsers: Any) -> None:  # noqa: ANN401
    help_ = "Verify a finished wheel against its RECORD and bundled SBOM read-only."
    p = sub_parsers.add_parser("verify", help=help_, description=help_)
    p.add_argument("WHEEL_FILE", type=Path, help="Path to wheel file.")
    p.add_argument(
        "--json",
        dest="JSON",
        action="store_true",
        default=False,
        help="Output results in JSON format",
    )
    p.add_argument(
        "--fail-on-gaps",
        dest="FAIL_ON_GAPS",
        action="store_true",
        default=False,
        help="Exit non-zero when the wheel is complete but has evidence gaps",
    )
    p.set_defaults(func=execute)


def execute(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from auditwheel.verify import format_report, verify_wheel

    wheel_file: Path = args.WHEEL_FILE
    if not wheel_file.is_file():
        parser.error(f"cannot access {wheel_file}. No such file")

    report = verify_wheel(wheel_file)
    if args.JSON:
        print(json.dumps(report, indent=2))
    else:
        print(format_report(report))

    if report["status"] == "failed":
        return 1
    if report["status"] == "incomplete" and args.FAIL_ON_GAPS:
        return 1
    return 0
