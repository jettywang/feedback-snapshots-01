"""Runnable BitLocker forensic status reporter.

Emits the :class:`~dissect.fve.bde.status.VolumeStatus` model as JSON so a backend can render the
real state of a BitLocker volume instead of collapsing suspended, paused and decrypted volumes into
a single "unencrypted" label.

Examples:
    python -m dissect.fve.tools.bde_status /path/to/volume.bin --clear-key
    python -m dissect.fve.tools.bde_status volume.bin.gz --passphrase 'secret' --pretty
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from pathlib import Path
from typing import BinaryIO

from dissect.fve.bde import BDE, assess_volume
from dissect.fve.bde.status import iter_status_records


def _open_volume(path: Path) -> BinaryIO:
    if path.suffix == ".gz":
        return gzip.open(path, "rb")
    return path.open("rb")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Report the forensic encryption status of a BitLocker volume")
    parser.add_argument("volume", type=Path, help="path to the BitLocker volume (optionally gzip compressed)")
    parser.add_argument("--clear-key", action="store_true", help="unlock with the on-volume clear/obfuscated key")
    parser.add_argument("--passphrase", type=str, help="user passphrase to unlock with")
    parser.add_argument("--recovery", type=str, help="recovery password to unlock with")
    parser.add_argument("--samples", type=int, default=8, help="number of sectors to spread across the volume")
    parser.add_argument("--sectors", type=str, help="comma-separated explicit logical sector numbers to inspect")
    parser.add_argument("--records", action="store_true", help="also emit one flat record per observed sector")
    parser.add_argument("--pretty", action="store_true", help="pretty-print the JSON output")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.volume.exists():
        print(f"Volume does not exist: {args.volume}", file=sys.stderr)
        return 1

    sectors = None
    if args.sectors:
        sectors = [int(part) for part in args.sectors.split(",") if part]

    with _open_volume(args.volume) as fh:
        bde = BDE(fh)

        # Credentials are optional. When none are supplied the model still reports metadata claims
        # and key-independent sector evidence; it never concludes that the volume is unreadable.
        if args.clear_key and bde.has_clear_key():
            bde.unlock_with_clear_key()
        elif args.passphrase and bde.has_passphrase():
            bde.unlock_with_passphrase(args.passphrase)
        elif args.recovery and bde.has_recovery_password():
            bde.unlock_with_recovery_password(args.recovery)

        status = assess_volume(bde, sectors)

    payload = status.to_dict()
    if args.records:
        payload["sector_records"] = list(iter_status_records(status))

    json.dump(payload, sys.stdout, indent=2 if args.pretty else None)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
