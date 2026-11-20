from __future__ import annotations

import pytest
from packaging.version import Version

import pip_audit._service as service
from pip_audit._service import (
    INTERNAL_SERVICE_UNAVAILABLE_REASON,
    INTERNAL_SOURCE,
    NO_INTERNAL_SERVICE_REASON,
    PUBLIC_SOURCE,
)


def _dep(name, version="1.0.0", source=None):
    return service.ResolvedDependency(name=name, version=Version(version), source=source)


class RecordingPublicService(service.VulnerabilityService):
    def __init__(self):
        self.queries = []

    def query(self, spec):
        self.queries.append(spec)
        return spec, []


class RecordingInternalService(service.VulnerabilityService):
    def __init__(self, fail_with=None, vulns=None):
        self.queries = []
        self._fail_with = fail_with
        self._vulns = vulns or []

    def query(self, spec):
        self.queries.append(spec)
        if self._fail_with is not None:
            raise self._fail_with
        return spec, list(self._vulns)


def test_internal_never_reaches_public_service():
    public = RecordingPublicService()
    internal = RecordingInternalService()
    router = service.RoutingService(public, internal)

    internal_dep = _dep("secret-plugin", source=INTERNAL_SOURCE)
    public_dep = _dep("requests", source=PUBLIC_SOURCE)

    results = dict(router.query_all(iter([internal_dep, public_dep])))

    assert internal.queries == [internal_dep]
    assert public.queries == [public_dep]
    assert internal_dep in results
    assert public_dep in results


def test_same_name_different_sources_routed_separately():
    public = RecordingPublicService()
    internal = RecordingInternalService()
    router = service.RoutingService(public, internal)

    public_dep = _dep("shared-name", source=PUBLIC_SOURCE)
    internal_dep = _dep("shared-name", source=INTERNAL_SOURCE)

    list(router.query_all(iter([public_dep, internal_dep])))

    assert public.queries == [public_dep]
    assert internal.queries == [internal_dep]
    # The public backend must never see the internal object (and thus its source).
    assert public.queries[0].source == PUBLIC_SOURCE


def test_unsourced_dependencies_are_treated_as_public():
    public = RecordingPublicService()
    internal = RecordingInternalService()
    router = service.RoutingService(public, internal)

    dep = _dep("requests")
    list(router.query_all(iter([dep])))

    assert public.queries == [dep]
    assert internal.queries == []


def test_no_internal_service_marks_policy_gap():
    public = RecordingPublicService()
    router = service.RoutingService(public, None)

    dep = _dep("secret-plugin", source=INTERNAL_SOURCE)
    dep_out, vulns = router.query(dep)

    assert dep_out.is_skipped()
    assert dep_out.policy_skipped is True
    assert dep_out.skip_reason == NO_INTERNAL_SERVICE_REASON
    assert dep_out.source == INTERNAL_SOURCE
    assert vulns == []
    assert public.queries == []


@pytest.mark.parametrize(
    "error",
    [
        service.ConnectionError("connection refused"),
        service.ServiceError("boom"),
    ],
)
def test_internal_service_failure_marks_policy_gap(error):
    public = RecordingPublicService()
    internal = RecordingInternalService(fail_with=error)
    router = service.RoutingService(public, internal)

    dep = _dep("secret-plugin", source=INTERNAL_SOURCE)
    dep_out, vulns = router.query(dep)

    assert dep_out.is_skipped()
    assert dep_out.policy_skipped is True
    assert INTERNAL_SERVICE_UNAVAILABLE_REASON in dep_out.skip_reason
    assert str(error) in dep_out.skip_reason
    assert vulns == []
    assert public.queries == []


def test_internal_result_preserves_source():
    public = RecordingPublicService()

    class FreshDependencyService(service.VulnerabilityService):
        def query(self, spec):
            # Deliberately drop provenance, as a naive backend might.
            return service.ResolvedDependency(spec.name, spec.version), []

    router = service.RoutingService(public, FreshDependencyService())
    dep = _dep("secret-plugin", source=INTERNAL_SOURCE)

    dep_out, _ = router.query(dep)
    assert dep_out.source == INTERNAL_SOURCE


def test_routing_service_declares_internal_support():
    router = service.RoutingService(RecordingPublicService())
    assert router.supports_internal_queries
    assert not RecordingPublicService().supports_internal_queries


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://internal.example/simple/pkg", INTERNAL_SOURCE),
        ("https://INTERNAL.example/simple/pkg", INTERNAL_SOURCE),
        ("https://pypi.org/simple/pkg", PUBLIC_SOURCE),
        (None, PUBLIC_SOURCE),
    ],
)
def test_classify_index_source(url, expected):
    assert (
        service.classify_index_source(url, ["https://internal.example/simple"])
        == expected
    )


def test_classify_index_source_disabled_without_configuration():
    assert service.classify_index_source("https://internal.example/simple", []) is None
