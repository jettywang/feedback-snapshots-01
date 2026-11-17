#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''Print a reviewable region permission report for an Intel flash descriptor.

The report lists, for each master (BIOS, ME, GbE), which declared regions
(descriptor, BIOS, ME, GbE, PDR) it may read/write, with the byte ranges and
the image offsets of every register used, so each line can be recomputed by
hand. It only reflects declarations inside the image; it cannot prove the
host's runtime write protection is in effect.
'''

import argparse
import json
import sys

from uefi_firmware.descriptor_report import analyze_descriptor, format_report


def main():
    parser = argparse.ArgumentParser(
        description="Report per-master region permissions declared by an "
                    "Intel flash descriptor.")
    parser.add_argument(
        "-j", "--json", default=False, action="store_true",
        help="Output the report as JSON instead of text.")
    parser.add_argument("file", help="Firmware image containing a descriptor.")
    args = parser.parse_args()

    try:
        with open(args.file, "rb") as handle:
            data = handle.read()
    except Exception as error:
        print("Error: cannot read %s (%s)." % (args.file, error))
        return 1

    report = analyze_descriptor(data)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(format_report(report))
    if not report["valid_header"]:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
