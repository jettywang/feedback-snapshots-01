"""Run the deterministic fuzzer and persist minimal failing artifacts.

A finding file is written only when the checker under test disagrees with
the independent oracle.  Each artifact contains the smallest reproduction
triple the task requires:

* the ROA DER (hex),
* the authenticated EE resources,
* the route triple (origin AS, AFI, prefix),

plus the expected and actual authorization and the adapter reason.
"""

import json
import os

from .fuzzer import RoaSemanticFuzzer


def run_and_persist(output_path, seed=20261114, sample_size=200):
    fuzzer = RoaSemanticFuzzer(seed=seed, sample_size=sample_size)
    _cases, findings = fuzzer.run()
    payload = {
        "seed": seed,
        "sample_size": sample_size,
        "finding_count": len(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    directory = os.path.dirname(os.path.abspath(output_path))
    if directory and not os.path.isdir(directory):
        os.makedirs(directory)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    return payload


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=os.path.join("tools", "roa_fuzz", "findings.json"))
    parser.add_argument("--seed", type=int, default=20261114)
    parser.add_argument("--sample-size", type=int, default=200)
    args = parser.parse_args(argv)
    payload = run_and_persist(args.output, args.seed, args.sample_size)
    print("seed=%d sample=%d findings=%d -> %s" % (
        payload["seed"], payload["sample_size"], payload["finding_count"], args.output))
    return 0 if payload["finding_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
