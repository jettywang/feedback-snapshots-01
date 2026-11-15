from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path
from typing import BinaryIO

from dissect.evidence.asdf import asdf
from dissect.evidence.asdf.recompose import PROVENANCE_MANIFEST, AsdfRecomposer, open_snapshot
from dissect.evidence.exception import RecomposeIncomplete, SourceBlockCorrupt, SourceGapError


def _parse_range(spec: str) -> tuple[int, int]:
    """Parse a ``offset:size`` byte range, accepting decimal or 0x-prefixed integers."""
    try:
        offset_spec, size_spec = spec.split(":", 1)
        return int(offset_spec, 0), int(size_spec, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid range {spec!r}, expected OFFSET:SIZE") from exc


def _open(path: str) -> BinaryIO:
    return Path(path).open("rb")  # noqa: SIM115 - closed by the caller's with statement


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Recompose validated ranges from existing ASDF snapshots into a new ASDF snapshot"
    )
    parser.add_argument("source", metavar="ASDF", help="source ASDF file (gzip compressed files are detected)")
    parser.add_argument("-w", "--writer", required=True, help="file to write the derived ASDF snapshot to")
    parser.add_argument(
        "-r",
        "--range",
        action="append",
        required=True,
        dest="ranges",
        metavar="OFFSET:SIZE",
        type=_parse_range,
        help="logical source range to copy, may be given multiple times",
    )
    parser.add_argument("--source-idx", type=int, default=0, help="source stream index (default: 0)")
    parser.add_argument(
        "--target-idx",
        type=int,
        default=None,
        help="destination stream index (default: same as source index)",
    )
    parser.add_argument(
        "--compress",
        action="store_true",
        help="write the derived snapshot as a whole-file gzip compressed ASDF container",
    )
    parser.add_argument("--guid", type=uuid.UUID, default=None)
    args = parser.parse_args()

    target_idx = args.source_idx if args.target_idx is None else args.target_idx
    destination = Path(args.writer)

    with _open(args.source) as source_fh, destination.open("wb") as dest_fh:
        source = open_snapshot(source_fh)
        writer = asdf.AsdfWriter(dest_fh, guid=args.guid, compress=args.compress)

        try:
            with AsdfRecomposer(writer) as recomposer:
                for offset, size in args.ranges:
                    result = recomposer.copy_range(
                        source, offset, size, source_idx=args.source_idx, target_idx=target_idx
                    )
                    print(
                        f"[*] copied {result.copied_size} bytes from idx {args.source_idx} "
                        f"offset {offset} -> idx {target_idx} sha256 {result.content_sha256}",
                        file=sys.stderr,
                    )
        except (SourceGapError, SourceBlockCorrupt, RecomposeIncomplete, OSError) as exc:
            print(f"[!] Derived snapshot rejected: {exc}", file=sys.stderr)
        else:
            print(f"[*] Wrote derived snapshot with provenance manifest {PROVENANCE_MANIFEST}", file=sys.stderr)
            return 0

    # Never leave an unpublished, header-only container behind.
    destination.unlink(missing_ok=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
