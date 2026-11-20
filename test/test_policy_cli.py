"""
End-to-end coverage for the confidentiality routing policy.

These tests exercise the CLI wiring with stub backends: they assert exactly which
queries each backend receives and inspect the final JSON report, including the
explicit coverage gap when the internal service is unavailable.
"""

from __future__ import annotations

import json

import pretend  # type: ignore
import pytest
from packaging.version import Version

import pip_audit._cli as cli
from pip_audit._service import (
    OsvService as _RealOsvService,
    INTERNAL_SOURCE,
    PUBLIC_SOURCE,
    ConnectionError,
    ResolvedDependency,
    VulnerabilityResult,
    VulnerabilityService,
)


# `cli._parser()` reads this attribute while building argument defaults, so keep
# a handle to the real class before any test monkeypatches `cli.OsvService`.
_REAL_OSV_DEFAULT_URL = _RealOsvService.DEFAULT_OSV_URL


class RecordingService(VulnerabilityService):
    def __init__(self, vulns_for=(), fail_with=None):
        self.queries: list[str] = []
        self._vulns_for = set(vulns_for)
        self._fail_with = fail_with

    def query(self, spec):
        if spec.is_skipped():
            return spec, []
        self.queries.append(spec.name)
        if self._fail_with is not None:
            raise self._fail_with
        if spec.canonical_name in self._vulns_for:
            return spec, [
                VulnerabilityResult(
                    id="CVE-2026-0001",
                    description="fake",
                    fix_versions=[Version("9.9.9")],
                    aliases=set(),
                )
            ]
        return spec, []


class FakeSource:
    """A dependency source that returns a fixed set of dependencies."""

    def __init__(self, deps):
        self._deps = deps

    def collect(self):
        yield from self._deps

    def fix(self, _):  # pragma: no cover
        raise NotImplementedError


def _run_cli(monkeypatch, capsys, args, deps, public, internal, osv_factory):
    monkeypatch.setenv("PIP_AUDIT_PROGRESS_SPINNER", "off")
    parser = cli._parser()
    parsed = parser.parse_args(args)

    monkeypatch.setattr(cli, "_parse_args", lambda *a: parsed)
    monkeypatch.setattr(cli, "PipSource", lambda *a, **kw: FakeSource(deps))
    monkeypatch.setattr(cli, "PyPIService", lambda *a, **kw: public)
    # `_parser()` is re-built inside `audit()`; give it a stub that still exposes
    # the real default URL so parsing succeeds before the factory is used.
    osv_stub = pretend.stub(
        DEFAULT_OSV_URL=_REAL_OSV_DEFAULT_URL, __call__=osv_factory
    )
    monkeypatch.setattr(cli, "OsvService", osv_stub)

    code = 0
    try:
        cli.audit()
    except SystemExit as exc:
        code = exc.code or 0

    captured = capsys.readouterr()
    return code, captured


DEPS = [
    ResolvedDependency(name="secret-plugin", version=Version("1.0.0"), source=INTERNAL_SOURCE),
    ResolvedDependency(name="requests", version=Version("2.0.0"), source=PUBLIC_SOURCE),
]


def test_cli_routes_internal_and_public_backends(monkeypatch, capsys):
    public = RecordingService(vulns_for={"requests"})
    internal = RecordingService(vulns_for={"secret-plugin"})

    # The internal service is constructed from the internal OSV URL.
    def fake_osv(*a, **kw):
        if kw.get("osv_url") == "https://osv.internal/v1/query":
            return internal
        return public

    code, captured = _run_cli(
        monkeypatch,
        capsys,
        [
            "-f",
            "json",
            "--internal-index-url",
            "https://internal.example/simple",
            "--internal-vulnerability-service-url",
            "https://osv.internal/v1/query",
        ],
        DEPS,
        public,
        internal,
        fake_osv,
    )

    # Each backend only saw its own package name.
    assert public.queries == ["requests"]
    assert internal.queries == ["secret-plugin"]
    assert code == 1  # vulnerabilities found

    payload = json.loads(captured.out)
    deps = {d["name"]: d for d in payload["dependencies"]}
    assert deps["secret-plugin"]["source"] == "internal"
    assert deps["requests"]["source"] == "public"
    assert deps["secret-plugin"]["vulns"][0]["id"] == "CVE-2026-0001"
    assert "coverage" not in payload
    assert "Found 2 known vulnerabilities" in captured.err


def test_cli_internal_outage_reports_coverage_gap(monkeypatch, capsys, caplog):
    public = RecordingService(vulns_for={"requests"})
    internal = RecordingService(fail_with=ConnectionError("internal feed down"))

    code, captured = _run_cli(
        monkeypatch,
        capsys,
        [
            "-f",
            "json",
            "--internal-index-url",
            "https://internal.example/simple",
            "--internal-vulnerability-service-url",
            "https://osv.internal/v1/query",
        ],
        DEPS,
        public,
        internal,
        lambda *a, **kw: internal,
    )

    # The public service still only saw the public package, even though the
    # internal one failed.
    assert public.queries == ["requests"]
    assert code == 1  # public vulnerability still reported

    payload = json.loads(captured.out)
    deps = {d["name"]: d for d in payload["dependencies"]}
    assert deps["secret-plugin"]["policy_skipped"] is True
    assert "unavailable" in deps["secret-plugin"]["skip_reason"]
    assert payload["coverage"]["complete"] is False
    assert payload["coverage"]["unaudited"][0]["name"] == "secret-plugin"
    assert "Coverage incomplete" in caplog.text


def test_cli_without_internal_service_never_queries_public_for_internal(
    monkeypatch, capsys
):
    public = RecordingService()

    code, captured = _run_cli(
        monkeypatch,
        capsys,
        [
            "-f",
            "json",
            "--internal-index-url",
            "https://internal.example/simple",
        ],
        DEPS,
        public,
        None,
        lambda *a, **kw: pytest.fail("internal service should not be constructed"),
    )

    assert public.queries == ["requests"]
    payload = json.loads(captured.out)
    deps = {d["name"]: d for d in payload["dependencies"]}
    assert deps["secret-plugin"]["policy_skipped"] is True
    assert payload["coverage"]["complete"] is False
    # The environment is clean apart from the deliberate coverage gap.
    assert code == 0
