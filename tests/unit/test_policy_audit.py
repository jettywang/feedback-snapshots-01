from __future__ import annotations

import pytest

from auditwheel.architecture import Architecture
from auditwheel.libc import Libc
from auditwheel.policy import WheelPolicies
from auditwheel.policy.audit import (
    AUTO_POLICY,
    PolicyAudit,
    TagRegistry,
    UnregisteredTagError,
    audit_request,
    ensure_approved,
    restrict_registry,
)

WHEEL = "cffi-1.5.0-cp27-none-linux_x86_64.whl"


@pytest.fixture
def policies() -> WheelPolicies:
    return WheelPolicies(libc=Libc.GLIBC, arch=Architecture.x86_64)


def _audit(policies, *, requested, registry=None):
    requested_policy = None
    if requested not in (None, AUTO_POLICY):
        requested_policy = policies.get_policy_by_name(f"{requested}_x86_64")
    proven = policies.get_policy_by_name("manylinux_2_17_x86_64")
    graft = policies.get_policy_by_name("manylinux_2_5_x86_64")
    return audit_request(
        policies,
        wheel_name=WHEEL,
        requested=requested,
        requested_policy=requested_policy,
        proven_policy=proven,
        proven_is_compatible=True,
        graft_policy=graft,
        registry=registry,
    )


def test_full_registry_contains_canonical_and_legacy_aliases(policies):
    registry = TagRegistry.from_policies(policies)
    # canonical names
    assert registry.allows("manylinux_2_17_x86_64")
    assert registry.allows("linux_x86_64")
    # the three registered legacy aliases
    assert registry.allows("manylinux1_x86_64")
    assert registry.allows("manylinux2010_x86_64")
    assert registry.allows("manylinux2014_x86_64")
    # an invented tag is not registered
    assert not registry.allows("manylinux_2_99_x86_64")


def test_registered_alias_request_is_approved(policies):
    audit = _audit(policies, requested="manylinux2014")
    assert audit.strategy == "requested"
    assert audit.requested == "manylinux2014"
    # the requested alias resolves to its canonical policy
    assert audit.requested_policy == "manylinux_2_17_x86_64"
    assert audit.proven_policy == "manylinux_2_17_x86_64"
    assert audit.graft_policy == "manylinux_2_5_x86_64"
    assert audit.proven_is_compatible is True
    assert audit.approved is True
    assert audit.unapproved == ()
    tags = {decision.tag: decision for decision in audit.tags}
    assert tags["manylinux2014_x86_64"].kind == "alias"
    assert tags["manylinux2014_x86_64"].canonical == "manylinux_2_17_x86_64"
    assert tags["manylinux2014_x86_64"].approved is True
    assert tags["manylinux_2_17_x86_64"].kind == "canonical"


def test_canonical_and_alias_request_produce_equivalent_audit(policies):
    via_alias = _audit(policies, requested="manylinux2014")
    via_canonical = _audit(policies, requested="manylinux_2_17")
    assert via_alias.requested_policy == via_canonical.requested_policy
    assert via_alias.proven_policy == via_canonical.proven_policy
    assert via_alias.graft_policy == via_canonical.graft_policy
    assert via_alias.tags == via_canonical.tags
    assert via_alias.approved == via_canonical.approved


def test_auto_strategy_only_advertises_proven_policy(policies):
    audit = _audit(policies, requested=AUTO_POLICY)
    assert audit.strategy == "auto"
    assert audit.requested_policy is None
    published = {decision.tag for decision in audit.tags}
    assert published == {"manylinux_2_17_x86_64", "manylinux2014_x86_64"}
    assert audit.approved is True


def test_requested_lower_priority_policy_is_also_listed(policies):
    # Request an older (higher-priority number = more compatible) alias while
    # the wheel proves a newer, less compatible tag; both must be advertised.
    requested_policy = policies.get_policy_by_name("manylinux1_x86_64")
    proven = policies.get_policy_by_name("manylinux_2_28_x86_64")
    audit = audit_request(
        policies,
        wheel_name=WHEEL,
        requested="manylinux1",
        requested_policy=requested_policy,
        proven_policy=proven,
        proven_is_compatible=True,
        graft_policy=policies.get_policy_by_name("manylinux_2_5_x86_64"),
    )
    published = {decision.tag for decision in audit.tags}
    assert "manylinux_2_28_x86_64" in published
    assert "manylinux1_x86_64" in published
    assert "manylinux_2_5_x86_64" in published


def test_restricted_registry_blocks_unapproved_new_tags(policies):
    # Network only registered the manylinux1 / manylinux_2_5 family.
    registry = restrict_registry(policies, ["linux", "manylinux1", "manylinux_2_5"])
    assert sorted(registry.tags) == [
        "linux_x86_64",
        "manylinux1_x86_64",
        "manylinux_2_5_x86_64",
    ]
    audit = _audit(policies, requested="manylinux2014", registry=registry)
    assert audit.approved is False
    assert audit.unapproved == ("manylinux_2_17_x86_64", "manylinux2014_x86_64")
    blocked = {decision.tag: decision for decision in audit.tags if not decision.approved}
    assert set(blocked) == {"manylinux_2_17_x86_64", "manylinux2014_x86_64"}
    with pytest.raises(UnregisteredTagError, match="manylinux_2_17_x86_64"):
        ensure_approved(audit)


def test_restricted_registry_allows_registered_family(policies):
    registry = restrict_registry(policies, ["linux", "manylinux1", "manylinux_2_5"])
    requested_policy = policies.get_policy_by_name("manylinux1_x86_64")
    audit = audit_request(
        policies,
        wheel_name=WHEEL,
        requested="manylinux1",
        requested_policy=requested_policy,
        proven_policy=requested_policy,
        proven_is_compatible=True,
        graft_policy=requested_policy,
        registry=registry,
    )
    ensure_approved(audit)  # must not raise
    assert audit.approved is True
    assert {decision.tag for decision in audit.tags} == {
        "manylinux_2_5_x86_64",
        "manylinux1_x86_64",
    }


def test_ensure_approved_passes_when_clean(policies):
    audit = _audit(policies, requested="manylinux1")
    ensure_approved(audit)  # no exception
    assert isinstance(audit, PolicyAudit)


def test_audit_dict_is_json_ready(policies):
    audit = _audit(policies, requested="manylinux2014")
    payload = audit.as_dict()
    assert payload["wheel"] == WHEEL
    assert payload["approved"] is True
    assert payload["unapproved_tags"] == []
    assert payload["tags"][0]["tag"]
    # every entry is made of plain JSON-serializable types
    import json

    json.dumps(payload)


def test_restrict_registry_strips_architecture_suffix():
    arm_policies = WheelPolicies(libc=Libc.GLIBC, arch=Architecture.aarch64)
    registry = restrict_registry(arm_policies, ["manylinux2014", "manylinux_2_17"])
    assert registry.tags == frozenset(
        {"manylinux_2_17_aarch64", "manylinux2014_aarch64"},
    )


def test_restrict_registry_empty_allowlist_approves_nothing(policies):
    registry = restrict_registry(policies, [])
    assert registry.tags == frozenset()
    audit = _audit(policies, requested="manylinux1", registry=registry)
    assert audit.approved is False
    # the proven 2_17 family and the requested 2_5 family are all unapproved
    assert set(audit.unapproved) == {
        "manylinux_2_17_x86_64",
        "manylinux2014_x86_64",
        "manylinux_2_5_x86_64",
        "manylinux1_x86_64",
    }
