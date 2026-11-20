import datetime
import random
from typing import cast

import pytest
from packaging.version import Version

from pip_audit._service.interface import (
    Dependency,
    ResolvedDependency,
    SkippedDependency,
    VulnerabilityID,
    VulnerabilityResult,
    VulnerabilityService,
)


def test_dependency_typing():
    # there are only two subclasses of Dependency
    assert set(Dependency.__subclasses__()) == {ResolvedDependency, SkippedDependency}

    # Dependency itself cannot be initialized
    with pytest.raises(NotImplementedError):
        Dependency(name="explodes")

    r = ResolvedDependency(name="foo", version=Version("1.0.0"))
    assert r.name == "foo"
    assert r.canonical_name == "foo"
    assert not r.is_skipped()

    s = SkippedDependency(name="bar", skip_reason="unit test")
    assert s.name == "bar"
    assert s.canonical_name == "bar"
    assert s.is_skipped()


def test_vulnerability_service(vuln_service, spec):
    service = vuln_service()
    spec = spec("1.0.1")

    _, vulns = service.query(spec)
    assert len(vulns) == 1

    all_ = dict(service.query_all([spec]))
    assert len(all_) == 1
    assert len(all_[spec]) == 1


def test_vulnerability_service_no_results(vuln_service, spec):
    service = vuln_service()
    spec = spec("1.1.1")

    _, vulns = service.query(spec)
    assert len(vulns) == 0


def test_vulnerability_result_update_aliases():
    result1 = VulnerabilityResult(
        id="FOO",
        description="stub",
        fix_versions=[Version("1.0.0")],
        aliases={"BAR", "BAZ", "ZAP"},
    )
    result2 = VulnerabilityResult(
        id="BAR",
        description="stub",
        fix_versions=[Version("1.0.0")],
        aliases={"FOO", "BAZ", "QUUX"},
    )

    merged = result1.merge_aliases(result2)
    assert merged.id == "FOO"
    assert merged.aliases == {"BAR", "BAZ", "ZAP", "QUUX"}


def test_vulnerability_result_has_any_id():
    result = VulnerabilityResult(
        id="FOO",
        description="bar",
        fix_versions=[Version("1.0.0")],
        aliases={"BAR", "BAZ", "QUUX"},
    )

    assert result.has_any_id({"FOO"})
    assert result.has_any_id({"ham", "eggs", "BAZ"})
    assert not result.has_any_id({"zilch"})
    assert not result.has_any_id(set())


@pytest.mark.parametrize("_n", range(10))
def test_vulnerability_result_create(_n):
    ids = cast(
        list[VulnerabilityID],
        ["testid1", "testid2", "GHSA-XXXX-XXXXX", "CVE-XXXX-XXXXX", "PYSEC-XXXX-XXXXX"],
    )
    random.shuffle(ids)

    result = VulnerabilityResult.create(ids, "foo", [], None)

    assert result.id == "PYSEC-XXXX-XXXXX"
    ids.remove(VulnerabilityID("PYSEC-XXXX-XXXXX"))
    assert result.aliases == set(ids)


class TestVulnerabilityService:
    @pytest.mark.parametrize(
        ["timestamp", "result"],
        [
            (None, None),
            ("2019-08-24T14:15:22Z", datetime.datetime(2019, 8, 24, 14, 15, 22)),
            (
                "2022-10-22T00:00:27.668938Z",
                datetime.datetime(2022, 10, 22, 0, 0, 27, 668938),
            ),
        ],
    )
    def test_parse_rfc3339(self, timestamp, result):
        assert VulnerabilityService._parse_rfc3339(timestamp) == result


def test_source_info_and_skip_status_defaults():
    from pathlib import Path

    from pip_audit._service.interface import (
        DependencySourceType,
        SkipStatus,
        SourceInfo,
        classify_skip,
    )

    resolved = ResolvedDependency(name="foo", version=Version("1.0.0"))
    assert resolved.source_info is None

    info = SourceInfo(
        source=DependencySourceType.Requirements,
        filename=Path("r.txt"),
        line_number=4,
        raw="foo==1.0.0",
    )
    located = ResolvedDependency(name="foo", version=Version("1.0.0"), source_info=info)
    assert located.source_info.location == "r.txt:4"

    # Provenance and status do not change identity/equality.
    assert resolved == located
    assert len({resolved, located}) == 1

    # A file-only source has no `:line` suffix.
    file_only = SourceInfo(
        source=DependencySourceType.PyLock,
        filename=Path("pylock.toml"),
        line_number=None,
        raw="",
    )
    assert file_only.location == "pylock.toml"

    # Explicit status is honored; unset status is derived from the reason.
    explicit = SkippedDependency(
        "bar",
        "no version specified",
        source_info=info,
        skip_status=SkipStatus.NeedsEvidence,
    )
    assert explicit.status is SkipStatus.NeedsEvidence
    assert explicit.source_info is info

    derived = SkippedDependency("bar", "requirement marked as editable")
    assert derived.status is SkipStatus.Legitimate


def test_classify_skip_reasons():
    from pip_audit._service.interface import SkipStatus, classify_skip

    legitimate = [
        "requirement marked as editable",
        "URL requirements cannot be pinned to a specific package version",
        "requirement does not apply to this environment",
    ]
    for reason in legitimate:
        assert classify_skip(reason) is SkipStatus.Legitimate

    # Unknown or evidence-bearing reasons default to needing evidence.
    assert classify_skip("no version specified") is SkipStatus.NeedsEvidence
    assert classify_skip("could not deduce package version from URL requirement") is (
        SkipStatus.NeedsEvidence
    )
    assert classify_skip("something unexpected") is SkipStatus.NeedsEvidence
