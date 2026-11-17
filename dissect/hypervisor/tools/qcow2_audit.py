from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dissect.hypervisor.disk.qcow2 import QCow2
from dissect.hypervisor.disk.qcow2_audit import audit, render_text


def main() -> int:
    parser = argparse.ArgumentParser(description="QCOW2 read-only cluster occupancy audit")
    parser.add_argument("image", type=Path, help="QCOW2 image to audit (opened read-only)")
    parser.add_argument(
        "-s",
        "--snapshot",
        action="append",
        default=[],
        metavar="ID",
        help="snapshot id to explicitly include in the reference walk (repeatable)",
    )
    args = parser.parse_args()

    if not args.image.exists():
        parser.exit(f"Image {args.image} does not exist")

    with args.image.open("rb") as fh:
        qcow2 = QCow2(fh, allow_no_backing_file=True, allow_no_data_file=True)
        report = audit(qcow2, snapshots=args.snapshot)

    print(render_text(report))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        pass
