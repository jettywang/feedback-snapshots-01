"""Command line entry point for the offline correlation prototype."""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from pathlib import Path
from typing import Dict, Tuple

try:  # allow both ``-m tools.ess_correlate.cli`` and direct execution
    from .analysis import CaseInputs, analyze_archive
    from .fixtures import build_corpus
    from .model import attestations_from_mapping
    from .report import render_markdown
except ImportError:  # pragma: no cover - direct script execution
    import sys as _sys
    from pathlib import Path as _Path

    _sys.path.insert(0, str(_Path(__file__).resolve().parents[2]))
    from tools.ess_correlate.analysis import CaseInputs, analyze_archive
    from tools.ess_correlate.fixtures import build_corpus
    from tools.ess_correlate.model import attestations_from_mapping
    from tools.ess_correlate.report import render_markdown

PEM_BLOCK = re.compile(
    r"-----BEGIN (?P<label>[A-Z0-9 ]+)-----\s*(?P<body>[A-Za-z0-9+/=\s]+?)\s*-----END (?P=label)-----",
    re.DOTALL,
)


def read_armoured(path: Path) -> bytes:
    text = path.read_text(encoding="utf-8")
    match = PEM_BLOCK.search(text)
    if not match:
        return base64.b64decode("".join(text.split()), validate=True)
    return base64.b64decode("".join(match.group("body").split()), validate=True)


def load_directory(directory: Path) -> Tuple[Dict[str, bytes], Dict[str, bytes]]:
    messages: Dict[str, bytes] = {}
    receipts: Dict[str, bytes] = {}
    for path in sorted(directory.glob("*.pem")):
        data = read_armoured(path)
        # ``receipt-*`` / ``receipt_*`` are the documented prefix for receipts;
        # a bare name ``receipt.pem`` is treated the same way.
        stem = path.stem
        if stem.lower().startswith(("receipt-", "receipt_")) or stem.lower() == "receipt":
            receipts[stem.split("-", 1)[-1].split("_", 1)[-1]] = data
        else:
            messages[stem] = data
    return messages, receipts


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Correlate ESS signed receipts with archived CMS signatures using "
            "field-level evidence. Signature verification outcomes are read "
            "from an explicit attestation file."
        )
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--fixtures",
        action="store_true",
        help="analyse the deterministic demonstration corpus built into the tool",
    )
    source.add_argument(
        "--archive",
        type=Path,
        help="directory of *.pem files; names starting with 'receipt' are receipts",
    )
    parser.add_argument(
        "--attestations",
        type=Path,
        help="JSON file with explicit message/receipt verification outcomes",
    )
    parser.add_argument("--json", type=Path, help="write the full JSON report here")
    parser.add_argument("--markdown", type=Path, help="write a Markdown report here")
    args = parser.parse_args(argv)

    if args.fixtures:
        corpus = build_corpus()
        messages = {message.name: message.der for message in corpus.messages}
        receipts = {receipt.name: receipt.der for receipt in corpus.receipts}
        attestation_document = corpus_attestations()
    elif args.archive:
        if args.attestations is None:
            parser.error("--archive requires --attestations")
        messages, receipts = load_directory(args.archive)
        attestation_document = json.loads(args.attestations.read_text(encoding="utf-8"))
    else:
        parser.error("choose --fixtures or --archive")

    if args.attestations is not None:
        attestation_document = json.loads(args.attestations.read_text(encoding="utf-8"))

    report = analyze_archive(
        CaseInputs(
            messages=messages,
            receipts=receipts,
            attestations=attestations_from_mapping(attestation_document),
        )
    )
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=False)
    if args.json:
        args.json.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    if args.markdown:
        args.markdown.write_text(render_markdown(report), encoding="utf-8")
    return 0


def corpus_attestations() -> Dict:
    from tools.ess_correlate.fixtures import attestations

    return attestations()


if __name__ == "__main__":
    sys.exit(main())
