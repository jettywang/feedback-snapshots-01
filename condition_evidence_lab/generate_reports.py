#!/usr/bin/env python3
"""Generate three local condition-evidence scenarios and verify their gates."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from policy_sentry.approval.condition_evidence import (  # noqa: E402
    generate_condition_evidence,
    render_condition_evidence_markdown,
)

FIXTURE_DIR = REPO_ROOT / "test" / "files" / "condition_evidence"
REPORT_DIR = REPO_ROOT / "condition_evidence_lab" / "reports"


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def main() -> int:
    request = json.loads((FIXTURE_DIR / "request.json").read_text(encoding="utf-8"))
    scenarios = json.loads((FIXTURE_DIR / "scenarios.json").read_text(encoding="utf-8"))
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    index: dict[str, Any] = {}
    failures: list[str] = []

    for scenario_name, spec in scenarios.items():
        overlay_path = FIXTURE_DIR / spec["overlay"]
        overlay_data = json.loads(overlay_path.read_text(encoding="utf-8"))
        report = generate_condition_evidence(
            request["template"],
            request["condition_block"],
            overlay=overlay_data,
        )
        report["catalog"]["overlay"] = f"test/files/condition_evidence/{spec['overlay']}"

        if report["release_status"] != spec["expected_release_status"]:
            failures.append(
                f"{scenario_name}: expected {spec['expected_release_status']}, got {report['release_status']}"
            )

        unresolved_types = {
            item["resource_type"] for item in report["items"] if not item["publishable"]
        }
        expected_unresolved = set(spec.get("expected_unresolved_resource_types", []))
        if unresolved_types != expected_unresolved:
            failures.append(
                f"{scenario_name}: expected unresolved {sorted(expected_unresolved)}, "
                f"got {sorted(unresolved_types)}"
            )

        if "expected_reason_code" in spec:
            reason_codes = {
                item["reason_code"]
                for item in report["items"]
                if not item["publishable"]
            }
            if spec["expected_reason_code"] not in reason_codes:
                failures.append(
                    f"{scenario_name}: expected reason {spec['expected_reason_code']}, got {sorted(reason_codes)}"
                )

        _write_json(REPORT_DIR / f"{scenario_name}.json", report)
        (REPORT_DIR / f"{scenario_name}.md").write_text(
            render_condition_evidence_markdown(report),
            encoding="utf-8",
        )
        _write_json(
            REPORT_DIR / f"{scenario_name}.base-policy.json", report["base_policy"]
        )
        _write_json(
            REPORT_DIR / f"{scenario_name}.candidate-policy.json",
            report["rendered_policy"],
        )
        legacy_policy_path = REPORT_DIR / f"{scenario_name}.policy.json"
        if legacy_policy_path.exists():
            legacy_policy_path.unlink()

        publishable_path = REPORT_DIR / f"{scenario_name}.publishable-policy.json"
        if report["publishable_policy"] is not None:
            _write_json(publishable_path, report["publishable_policy"])
        elif publishable_path.exists():
            publishable_path.unlink()

        index[scenario_name] = {
            "title_zh": spec["title_zh"],
            "release_status": report["release_status"],
            "publishable": report["publishable"],
            "summary": report["summary"],
            "required_evidence": report["required_evidence"],
            "report_json": f"{scenario_name}.json",
            "report_markdown": f"{scenario_name}.md",
            "base_policy": f"{scenario_name}.base-policy.json",
            "candidate_policy": f"{scenario_name}.candidate-policy.json",
            "publishable_policy": publishable_path.name
            if report["publishable"]
            else None,
        }

    _write_json(REPORT_DIR / "index.json", {"scenarios": index})
    print(
        json.dumps(
            {"report_dir": str(REPORT_DIR), "scenarios": index},
            indent=2,
            ensure_ascii=False,
        )
    )

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
