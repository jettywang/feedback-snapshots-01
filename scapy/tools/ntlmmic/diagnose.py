"""Command line interface for offline NTLM integrity diagnostics.

Subcommands:

- ``generate``: create the synthetic, credential-free validation dataset;
- ``analyze``: read a JSONL capture and report presence / verifiability /
  verdict for MIC and channel binding without any network activity.
"""

import argparse
import json
from typing import Any, Dict, List, Optional

from scapy.tools.ntlmmic.analysis import (
    analyze_context,
    detect_reused_challenge,
)
from scapy.tools.ntlmmic.evidence import (
    group_by_context,
    load_capture,
    load_keymaterial,
)
from scapy.tools.ntlmmic.synthdata import write_dataset


def _load_hex_map(path: Optional[str]) -> Dict[str, bytes]:
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        obj = json.load(handle)
    return {key: bytes.fromhex(value) for key, value in obj.items()}


def _load_ssp_audit(path: Optional[str]) -> Dict[str, Dict[str, Any]]:
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def run_analyze(args: argparse.Namespace) -> int:
    records = load_capture(args.capture)
    grouped = group_by_context(records)
    keys = load_keymaterial(args.session_keys)
    outer_bindings = _load_hex_map(args.outer_bindings)
    ssp_audit = _load_ssp_audit(args.ssp_audit)

    reuse_warnings = detect_reused_challenge(
        [
            (context_id, [evidence for _record, evidence in items])
            for context_id, items in grouped.items()
        ]
    )

    reports = []
    for context_id in sorted(grouped):
        items = grouped[context_id]
        evidences = [evidence for _record, evidence in items]
        source_records = [record for record, _evidence in items]
        report = analyze_context(
            context_id=context_id,
            evidences=evidences,
            exported_key=keys.get(context_id),
            outer_binding_hash=outer_bindings.get(context_id),
            ssp_audit=ssp_audit.get(context_id),
            records=source_records,
        )
        reports.append(report.as_dict())

    output = {
        "tool": "ntlmmic-offline-diagnose",
        "network_access": "none",
        "context_count": len(reports),
        "reused_challenge_warnings": [reason.as_dict() for reason in reuse_warnings],
        "contexts": reports,
    }
    rendered = json.dumps(output, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered + "\n")
    else:
        print(rendered)
    return 0


def run_generate(args: argparse.Namespace) -> int:
    paths = write_dataset(args.output_dir)
    print(json.dumps(paths, indent=2))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline NTLM MIC / channel-binding integrity diagnostics.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser(
        "generate",
        help="Generate the synthetic credential-free validation dataset.",
    )
    generate.add_argument("output_dir", help="Directory for generated files.")
    generate.set_defaults(func=run_generate)

    analyze = subparsers.add_parser(
        "analyze",
        help="Analyze a JSONL NTLM capture offline.",
    )
    analyze.add_argument("capture", help="Path to the JSONL capture file.")
    analyze.add_argument(
        "--session-keys",
        help="JSON map of context id to hex exported session key.",
    )
    analyze.add_argument(
        "--outer-bindings",
        help="JSON map of context id to hex outer-channel binding hash.",
    )
    analyze.add_argument(
        "--ssp-audit",
        help="JSON map of context id to SSP-side audit records.",
    )
    analyze.add_argument("--output", help="Write the JSON report to this path.")
    analyze.set_defaults(func=run_analyze)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
