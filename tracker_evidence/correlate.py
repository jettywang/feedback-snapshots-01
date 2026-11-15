"""Batch correlation of LNK TrackerDataBlock identities.

Correlation policy (stated explicitly per decision):

- CURRENT PAIR  = (volume_droid, file_droid)             -- where the object was last known
- BIRTH PAIR    = (volume_droid_birth, file_droid_birth) -- where the object was created

Rules:
  R1  Same non-zero CURRENT pair AND same non-zero BIRTH pair
      -> same tracked object (same snapshot / copies of one shortcut).
  R2  Same non-zero BIRTH pair, CURRENT pair differs
      -> migration candidates: same created object, last-known location differs.
         Records are LINKED, never merged; the differing current pairs are kept.
  R3  Equal machine_id alone, or a single equal GUID, is NEVER sufficient.
  R4  All-zero fields carry no identity and never match anything (including
      other all-zero fields).
  R5  Records with missing/truncated identity fields can only be correlated on
      the pairs that are fully present; partial overlap is reported as
      "insufficient".

Caveat: tracker fields are self-reported metadata. They do not prove the target
file currently exists, nor that machine_id belongs to a real host.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ZERO_GUID = "00000000-0000-0000-0000-000000000000"
DROID_FIELDS = ("volume_droid", "file_droid", "volume_droid_birth", "file_droid_birth")


def load_identities(evidence_paths: list[Path]) -> list[dict]:
    records = []
    for path in evidence_paths:
        views = json.loads(path.read_text())
        for view in views:
            rec = {"file": Path(view["file"]).name, "anomalies": view["tracker_block"]["anomalies"]}
            block = view["tracker_block"]
            if not block["present"]:
                rec["usable"] = False
                records.append(rec)
                continue
            fields = block["fields"]
            for name in DROID_FIELDS:
                entry = fields[name]
                rec[name] = None if entry.get("missing") else entry["guid"]
                rec[f"{name}_zero"] = bool(entry.get("all_zero"))
            machine = fields["machine_id"]
            rec["machine_id"] = machine.get("value")
            rec["usable"] = True
            records.append(rec)
    return records


def pair(rec: dict, kind: str) -> tuple | None:
    """Return the (volume, file) droid pair, or None if unusable (missing/zero)."""
    if kind == "current":
        vol, fil = rec["volume_droid"], rec["file_droid"]
        zv, zf = rec["volume_droid_zero"], rec["file_droid_zero"]
    else:
        vol, fil = rec["volume_droid_birth"], rec["file_droid_birth"]
        zv, zf = rec["volume_droid_birth_zero"], rec["file_droid_birth_zero"]
    if vol is None or fil is None or zv or zf:
        return None
    return (vol, fil)


def correlate(records: list[dict]) -> dict:
    report = {
        "groups": [],
        "migration_candidates": [],
        "partial_matches": [],
        "insufficient": [],
        "uncorrelatable": [],
    }

    by_current: dict[tuple, list[dict]] = defaultdict(list)
    by_birth: dict[tuple, list[dict]] = defaultdict(list)
    for rec in records:
        if not rec.get("usable"):
            report["uncorrelatable"].append({"file": rec["file"], "reason": "no tracker block"})
            continue
        cur, bir = pair(rec, "current"), pair(rec, "birth")
        if cur is None and bir is None:
            report["uncorrelatable"].append(
                {"file": rec["file"], "reason": "no non-zero, fully-present identity pair"}
            )
            continue
        if cur is not None:
            by_current[cur].append(rec)
        if bir is not None:
            by_birth[bir].append(rec)

    # R1: identical current AND birth pairs
    for cur, members in by_current.items():
        by_birth_pair: dict[tuple, list[dict]] = defaultdict(list)
        for rec in members:
            bir = pair(rec, "birth")
            if bir is not None:
                by_birth_pair[bir].append(rec)
        for bir, group in by_birth_pair.items():
            if len(group) > 1:
                report["groups"].append(
                    {
                        "rule": "R1",
                        "identity_used": {"current_pair": list(cur), "birth_pair": list(bir)},
                        "files": [r["file"] for r in group],
                        "conclusion": "same tracked object (identical current and birth identity pairs)",
                    }
                )

    # R2: shared birth pair, differing current pairs -> migration candidates
    for bir, members in by_birth.items():
        currents = {tuple(pair(r, "current")) for r in members}
        if len(members) > 1 and len(currents) > 1:
            report["migration_candidates"].append(
                {
                    "rule": "R2",
                    "identity_used": {"birth_pair": list(bir)},
                    "files": [
                        {"file": r["file"], "current_pair": pair(r, "current")} for r in members
                    ],
                    "conclusion": (
                        "shared birth identity, diverging current identity: candidate "
                        "move/migration chain; records kept distinct, not merged"
                    ),
                }
            )

    # R3/R5: explicit counterexamples -- machine-name-only and single-GUID overlaps
    usable = [r for r in records if r.get("usable")]
    for i, a in enumerate(usable):
        for b in usable[i + 1 :]:
            shared_machine = a["machine_id"] and a["machine_id"] == b["machine_id"]
            shared_guids = [
                name
                for name in DROID_FIELDS
                if a[name] is not None
                and a[name] == b[name]
                and a[name] != ZERO_GUID
                and not a[f"{name}_zero"]
            ]
            bir_a, bir_b = pair(a, "birth"), pair(b, "birth")
            cur_a, cur_b = pair(a, "current"), pair(b, "current")
            same_birth = bir_a is not None and bir_a == bir_b
            same_current = cur_a is not None and cur_a == cur_b
            if same_birth or same_current:
                # R5: one full pair matches but the other pair is unavailable on
                # at least one side (e.g. truncated block) -> report, do not merge.
                matched = "current_pair" if same_current else "birth_pair"
                other_a, other_b = (bir_a, bir_b) if same_current else (cur_a, cur_b)
                if other_a is None or other_b is None:
                    report["partial_matches"].append(
                        {
                            "rule": "R5",
                            "files": [a["file"], b["file"]],
                            "identity_used": {matched: cur_a if same_current else bir_a},
                            "conclusion": (
                                "one complete identity pair matches but the other pair is "
                                "missing/zero on at least one record: cannot confirm same object"
                            ),
                        }
                    )
                continue  # fully-present matches are handled by R1/R2
            reasons = []
            if shared_machine:
                reasons.append(f"same machine_id '{a['machine_id']}' only")
            if shared_guids:
                reasons.append("single shared GUID(s): " + ", ".join(shared_guids))
            if reasons:
                report["insufficient"].append(
                    {
                        "rule": "R3",
                        "files": [a["file"], b["file"]],
                        "overlap": "; ".join(reasons),
                        "conclusion": "insufficient to correlate: no complete identity pair matches",
                    }
                )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", nargs="+", type=Path, help="evidence JSON from lnk_tracker_view.py")
    args = parser.parse_args()
    records = load_identities(args.evidence)
    json.dump(correlate(records), sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
