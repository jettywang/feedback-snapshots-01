"""Print MountedDevices identity records for one or more offline SYSTEM hives.

Each argument is a hive path, optionally prefixed with ``LABEL=`` to keep
evidence from different snapshots apart::

    python examples/mounted_devices.py SYSTEM=capture-1/SYSTEM SYSTEM=capture-2/SYSTEM

The output is JSON with per-value raw bytes, cell offsets, parse basis, and
per-identity alias records.  No host registry or live disks are accessed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from dissect.regf import regf
from dissect.regf.mounted import analyze_mounted_devices, correlate_mounted_devices


def parse_source(text: str) -> tuple[str | None, Path]:
    label, separator, path = text.partition("=")
    if separator and path:
        return label, Path(path)
    return None, Path(text)


def main() -> None:
    parser = argparse.ArgumentParser(description="Correlate MountedDevices volume identities")
    parser.add_argument("hives", nargs="+", metavar="[LABEL=]HIVE")
    args = parser.parse_args()

    analyses = []
    for source in args.hives:
        snapshot, path = parse_source(source)
        with path.open("rb") as fh:
            hive = regf.RegistryHive(fh)
            analyses.append(analyze_mounted_devices(hive, snapshot=snapshot))

    correlation = correlate_mounted_devices(*analyses)
    print(
        json.dumps(
            {
                "snapshots": [
                    {
                        "snapshot": analysis.snapshot,
                        "key_path": analysis.key_path,
                        "values": [value.to_dict() for value in analysis.values],
                        "problems": list(analysis.problems),
                    }
                    for analysis in analyses
                ],
                "records": [record.to_dict() for record in correlation.records],
                "conflicts": [conflict.to_dict() for conflict in correlation.conflicts],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
