import io
import json
from pathlib import Path

import pytest

from pip_audit._compare import (
    CompareError,
    Status,
    compare,
    compare_reports,
    load_report,
    main,
    parse_report,
)

_EXAMPLES = Path(__file__).parent.parent / "examples" / "compare"


def _example(name):
    return _EXAMPLES / name / "before.json", _EXAMPLES / name / "after.json"


def _finding(comparison, package):
    matches = [finding for finding in comparison.findings if finding.package == package]
    assert len(matches) == 1, matches
    return matches[0]


def test_parse_legacy_array():
    payload = [
        {
            "name": "Foo_Bar",
            "version": "1.0",
            "vulns": [{"id": "CVE-1", "fix_versions": ["1.1"]}],
        }
    ]
    report = parse_report(payload, path="legacy.json")

    assert report.schema == "legacy-array"
    assert not report.has_fixes
    package = report.packages["foo-bar"]
    assert package.version_raw == "1.0"
    assert package.vulns[0].id == "CVE-1"
    assert package.vulns[0].fix_versions[0].version is not None


def test_parse_current_object():
    report = parse_report(
        {
            "dependencies": [
                {"name": "foo", "version": "1.0", "vulns": []},
                {"name": "bar", "skip_reason": "unavailable"},
            ],
            "fixes": [{"name": "foo", "old_version": "0.9", "new_version": "1.0"}],
        },
        path="current.json",
    )

    assert report.schema == "dependencies-object"
    assert report.has_fixes
    assert report.packages["bar"].is_skipped
    assert report.fixes[0].new_version == "1.0"


@pytest.mark.parametrize(
    "payload, message",
    [
        ("not json", "invalid JSON"),
        ({"dependencies": "nope"}, "expected an array"),
        ({"dependencies": [{"version": "1.0"}]}, "expected a non-empty string"),
        (
            {
                "dependencies": [
                    {"name": "foo", "version": "1.0", "vulns": []},
                    {"name": "FOO", "version": "2.0", "vulns": []},
                ]
            },
            "duplicate package",
        ),
    ],
)
def test_parse_errors(tmp_path, payload, message):
    path = tmp_path / "report.json"
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload))

    with pytest.raises(CompareError, match=message):
        load_report(path)


def test_fixed_example_requires_complete_evidence():
    comparison = compare(*_example("fixed"))
    finding = _finding(comparison, "requests")

    assert finding.status is Status.FIXED
    assert finding.fixed
    assert finding.evidence.complete
    assert finding.version_change == "upgraded"
    paths = {locator.path for locator in finding.evidence.items}
    assert "dependencies[0].vulns[0].fix_versions[0]" in paths
    assert "dependencies[0]" in paths


def test_removed_example_handles_legacy_before():
    before_path, after_path = _example("removed")
    comparison = compare(before_path, after_path)
    finding = _finding(comparison, "pyyaml")

    assert finding.status is Status.REMOVED
    assert finding.evidence.complete
    assert finding.version_after is None
    # The before input is a legacy array, so its locator is a bare index.
    before_locators = [locator for locator in finding.evidence.items if locator.report == "before"]
    assert [locator.path for locator in before_locators] == ["[0]", "[0].vulns[0]"]


def test_not_reported_example_is_not_a_fix():
    comparison = compare(*_example("not-reported"))
    finding = _finding(comparison, "jinja2")

    assert finding.status is Status.NOT_REPORTED
    assert not finding.fixed
    assert not finding.evidence.complete
    assert finding.evidence.missing


def test_downgrade_example_stays_reported():
    comparison = compare(*_example("downgrade"))
    finding = _finding(comparison, "urllib3")

    assert finding.status is Status.RETAINED
    assert finding.version_change == "downgraded"
    assert "not an upgrade" in finding.detail
    assert finding.version_before == "2.2.1"
    assert finding.version_after == "1.26.18"


def test_downgrade_with_absent_finding_is_unverifiable():
    before = parse_report(
        {
            "dependencies": [
                {
                    "name": "urllib3",
                    "version": "2.2.2",
                    "vulns": [{"id": "CVE-1", "fix_versions": ["2.3.0"]}],
                }
            ]
        }
    )
    after = parse_report({"dependencies": [{"name": "urllib3", "version": "1.26.19", "vulns": []}]})

    finding = compare_reports(before, after).findings[0]
    assert finding.status is Status.UNVERIFIABLE
    assert not finding.evidence.complete
    assert finding.version_change == "downgraded"


def test_upgrade_without_crossing_fix_version_is_unverifiable():
    before = parse_report(
        {
            "dependencies": [
                {
                    "name": "foo",
                    "version": "1.0",
                    "vulns": [{"id": "CVE-1", "fix_versions": ["2.0"]}],
                }
            ]
        }
    )
    after = parse_report({"dependencies": [{"name": "foo", "version": "1.5", "vulns": []}]})

    finding = compare_reports(before, after).findings[0]
    assert finding.status is Status.UNVERIFIABLE
    assert "upgrade range" in finding.detail
    assert any(
        locator.path == "dependencies[0].vulns[0].fix_versions[0]"
        for locator in finding.evidence.items
    )


def test_upgrade_without_fix_versions_is_unverifiable():
    before = parse_report(
        {"dependencies": [{"name": "foo", "version": "1.0", "vulns": [{"id": "CVE-1"}]}]}
    )
    after = parse_report({"dependencies": [{"name": "foo", "version": "1.5", "vulns": []}]})

    finding = compare_reports(before, after).findings[0]
    assert finding.status is Status.UNVERIFIABLE
    assert "no fix version" in finding.detail


def test_fix_action_must_match_observed_versions():
    # The `fixes` block records a different upgrade than the one in the
    # dependency list, so it must not be offered as corroboration.
    before = parse_report(
        {
            "dependencies": [
                {
                    "name": "foo",
                    "version": "1.0",
                    "vulns": [{"id": "CVE-1", "fix_versions": ["1.2"]}],
                }
            ]
        }
    )
    after = parse_report(
        {
            "dependencies": [{"name": "foo", "version": "1.3", "vulns": []}],
            "fixes": [{"name": "foo", "old_version": "0.9", "new_version": "1.1"}],
        }
    )

    finding = compare_reports(before, after).findings[0]
    assert finding.status is Status.FIXED
    assert all(locator.path != "fixes[0]" for locator in finding.evidence.items)


def test_skipped_after_package_is_unverifiable():
    before = parse_report(
        {
            "dependencies": [
                {
                    "name": "foo",
                    "version": "1.0",
                    "vulns": [{"id": "CVE-1", "fix_versions": ["1.2"]}],
                }
            ]
        }
    )
    after = parse_report(
        {"dependencies": [{"name": "foo", "skip_reason": "no matching distribution"}]}
    )

    finding = compare_reports(before, after).findings[0]
    assert finding.status is Status.UNVERIFIABLE
    assert not finding.evidence.complete


def test_new_finding_is_reported_separately():
    before = parse_report({"dependencies": [{"name": "foo", "version": "1.0", "vulns": []}]})
    after = parse_report(
        {
            "dependencies": [
                {
                    "name": "foo",
                    "version": "1.1",
                    "vulns": [{"id": "CVE-2", "fix_versions": ["1.2"]}],
                }
            ]
        }
    )

    finding = compare_reports(before, after).findings[0]
    assert finding.status is Status.NEW
    assert finding.version_change == "upgraded"


def test_aliases_match_across_reports():
    before = parse_report(
        {
            "dependencies": [
                {
                    "name": "foo",
                    "version": "1.0",
                    "vulns": [{"id": "GHSA-aaaa", "aliases": ["CVE-1"], "fix_versions": ["1.2"]}],
                }
            ]
        }
    )
    after = parse_report(
        {
            "dependencies": [
                {
                    "name": "foo",
                    "version": "1.2",
                    "vulns": [{"id": "CVE-1", "aliases": ["GHSA-aaaa"], "fix_versions": ["1.2"]}],
                }
            ]
        }
    )

    finding = compare_reports(before, after).findings[0]
    assert finding.status is Status.RETAINED


@pytest.mark.parametrize(
    "example, expected",
    [
        ("fixed", Status.NEW),
        ("removed", Status.NEW),
        ("not-reported", Status.NEW),
    ],
)
def test_swapped_inputs_reverse_the_story(example, expected):
    before_path, after_path = _example(example)
    forward = compare(before_path, after_path)
    swapped = compare(before_path, after_path, swap=True)

    assert swapped.before.path == forward.after.path
    assert swapped.after.path == forward.before.path
    assert [finding.package for finding in swapped.findings] == [
        finding.package for finding in forward.findings
    ]

    original = forward.findings[0]
    mirrored = swapped.findings[0]
    # Reversing the inputs cannot still look like a fix; the finding now exists
    # only in the report that was previously the "after" report.
    assert mirrored.status is expected
    assert original.version_before == mirrored.version_after
    assert original.version_after == mirrored.version_before
    assert not mirrored.fixed


def test_swap_of_downgrade_looks_like_an_upgrade_but_stays_reported():
    before_path, after_path = _example("downgrade")
    swapped = compare(before_path, after_path, swap=True)
    finding = swapped.findings[0]

    assert finding.status is Status.RETAINED
    assert finding.version_change == "upgraded"
    assert not finding.fixed


def test_report_order_does_not_affect_findings():
    forward = compare(*_example("fixed"))
    before_path, after_path = _example("fixed")
    before_data = json.loads(before_path.read_text())
    after_data = json.loads(after_path.read_text())
    before_data["dependencies"].reverse()
    after_data["dependencies"].reverse()

    reversed_before = parse_report(before_data, path=str(before_path))
    reversed_after = parse_report(after_data, path=str(after_path))
    shuffled = compare_reports(reversed_before, reversed_after)

    assert [finding.to_dict() | {"evidence": None} for finding in shuffled.findings] == [
        finding.to_dict() | {"evidence": None} for finding in forward.findings
    ]


def test_main_text_and_json_output(capsys):
    before_path, after_path = _example("fixed")

    assert main([str(before_path), str(after_path)]) == 0
    text = capsys.readouterr().out
    assert "Summary:" in text
    assert "evidence complete: yes" in text

    assert main(["--format", "json", str(before_path), str(after_path)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["fixed"] == 1
    record = payload["findings"][0]["evidence"]["records"][0]
    assert record["file"] == str(before_path)


def test_main_output_file_and_exit_codes(tmp_path, capsys):
    before_path, after_path = _example("not-reported")
    output = tmp_path / "comparison.json"

    assert main(["-f", "json", "-o", str(output), str(before_path), str(after_path)]) == 0
    assert json.loads(output.read_text())["findings"][0]["status"] == "not-reported"

    assert main(["--fail-on", "unresolved", str(before_path), str(after_path)]) == 1
    assert main(["--fail-on", "not-fixed", str(before_path), str(after_path)]) == 1

    fixed_before, fixed_after = _example("fixed")
    assert main(["--fail-on", "unresolved", str(fixed_before), str(fixed_after)]) == 0
    assert main(["--fail-on", "not-fixed", str(fixed_before), str(fixed_after)]) == 0

    missing = tmp_path / "missing.json"
    assert main([str(missing), str(fixed_after)]) == 2
    assert "pip-audit-compare: error" in capsys.readouterr().err


def test_stdin_report(monkeypatch, capsys):
    before_path, after_path = _example("fixed")
    monkeypatch.setattr("sys.stdin", io.StringIO(before_path.read_text()))

    assert main(["-", str(after_path)]) == 0
    assert "<stdin>" in capsys.readouterr().out


def test_missing_vulns_on_audited_package_is_rejected(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"dependencies": [{"name": "foo", "version": "1.0"}]}))

    with pytest.raises(CompareError, match="no 'vulns' array"):
        load_report(path)


def test_both_stdin_inputs_are_rejected():
    with pytest.raises(CompareError, match="only one report"):
        compare("-", "-")


def test_clean_reports_have_no_findings():
    report = parse_report(
        {"dependencies": [{"name": "foo", "version": "1.0", "vulns": []}], "fixes": []}
    )
    previous = parse_report(
        {"dependencies": [{"name": "foo", "version": "0.9", "vulns": []}], "fixes": []}
    )

    comparison = compare_reports(previous, report)
    assert comparison.findings == ()
    assert "No vulnerability findings to compare." in comparison.to_text()
    assert comparison.summary()["total"] == 0


def test_legacy_reports_without_fixes_block_still_prove_a_fix():
    before_path, after_path = _example("fixed")
    before_data = json.loads(before_path.read_text())["dependencies"]
    after_data = json.loads(after_path.read_text())["dependencies"]

    before = parse_report(before_data, path="before.json")
    after = parse_report(after_data, path="after.json")
    comparison = compare_reports(before, after)

    assert before.schema == "legacy-array"
    assert not before.has_fixes
    assert not after.has_fixes
    finding = comparison.findings[0]
    assert finding.status is Status.FIXED
    assert finding.fixed
    assert all(locator.path != "fixes[0]" for locator in finding.evidence.items)
    assert any(locator.path == "[0].vulns[0].fix_versions[0]" for locator in finding.evidence.items)
