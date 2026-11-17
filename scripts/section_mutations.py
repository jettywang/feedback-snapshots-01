#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''Generate and check the nested-section mutation corpus.

The corpus starts from a fixed, valid FFS2 volume whose sections nest inside
a compressed section and a GUID-defined section. Every variant changes one
layer; the encoder then updates the parent sizes and the padding between
siblings, so a variant stays reachable where that makes sense.

Examples:
    python scripts/section_mutations.py --list
    python scripts/section_mutations.py --write /tmp/corpus
    python scripts/section_mutations.py --check /tmp/corpus
'''

import argparse
import hashlib
import json
import os
import sys

from uefi_firmware import mutation


def read_manifest(directory):
    path = os.path.join(directory, "manifest.json")
    with open(path, "r") as handle:
        return json.load(handle)


def check(directory):
    '''Compare the files a corpus directory holds with its manifest.'''
    manifest = read_manifest(directory)
    failures = []
    entries = [("seed", manifest["seed"])]
    entries += [
        (variant["name"], variant) for variant in manifest["variants"]]
    for name, entry in entries:
        path = os.path.join(directory, entry["file"])
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except FileNotFoundError:
            failures.append("%s: %s is missing" % (name, entry["file"]))
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest != entry["sha256"]:
            failures.append(
                "%s: sha256 is %s, manifest says %s" % (
                    name, digest, entry["sha256"]))
            continue
        parsed, layers = mutation.parse_image(data)
        expect = entry.get("expect", entry)
        if parsed != expect.get("parsed"):
            failures.append(
                "%s: parsed=%s, expected %s" % (
                    name, parsed, expect.get("parsed")))
        if "layers_reached" in expect and \
                len(layers) != expect["layers_reached"]:
            failures.append(
                "%s: reached %d layers, expected %d" % (
                    name, len(layers), expect["layers_reached"]))
        if entry.get("target") and expect.get("target_reached") and \
                entry["target"] not in layers:
            failures.append(
                "%s: target %s was not reached" % (name, entry["target"]))
        print("%-32s parsed=%-5s layers=%2d sha256=%s" % (
            name, parsed, len(layers), digest[:16]))
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--write", metavar="DIR", help="Write the corpus into DIR.")
    group.add_argument(
        "--check", metavar="DIR",
        help="Check the files in DIR against their manifest.")
    group.add_argument(
        "--list", action="store_true", help="List the variants.")
    args = parser.parse_args()

    if args.list:
        corpus = mutation.build_corpus()
        print(mutation.format_report(corpus))
        return 0 if corpus["counts"]["failed_variants"] == 0 else 1

    if args.write:
        corpus = mutation.write_corpus(args.write)
        print("seed sha256=%s size=0x%x" % (
            corpus["seed"]["sha256"], corpus["seed"]["size"]))
        print("wrote %d variants to %s" % (
            len(corpus["variants"]), args.write))
        return 0 if corpus["counts"]["failed_variants"] == 0 else 1

    failures = check(args.check)
    for failure in failures:
        print("failure: %s" % failure, file=sys.stderr)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
